//! Shared HTTP transport, retries, and credential boundaries.
//!
//! Layered per the harmonized cross-SDK architecture: [`policy`] is the pure
//! decision kernel (L1), [`routing`] builds the candidate set (L2),
//! [`engine`] hosts THE single retry/failover loop (L3), and [`headers`]
//! assembles each attempt (L4). This file keeps the thin entry points:
//! `request_bytes` (execute, then drain the body under the deadline),
//! `open_stream` (execute, returning the live undrained response), and the
//! deliberately single-shot `credential_free_json`.
//!
//! # Invariants
//!
//! Each line names its enforcing test. Policy tests live in
//! `transport/policy.rs`, walk tests in `transport/engine.rs`, construction
//! tests in `tests/alias_failover.rs`, contract tests in
//! `tests/client_contract.rs`.
//!
//! 1. The failover set {502, 503, 504} is a strict subset of the retry set
//!    {429, 500, 502, 503, 504, verdict-true} —
//!    `only_gateway_statuses_move_domains`, `a_429_does_not_move_domains`.
//! 2. A 500 NEVER moves domains: a server processed the non-idempotent
//!    inference, and re-sending elsewhere risks a second generation —
//!    `a_500_does_not_move_domains`,
//!    `open_stream_keeps_a_500_on_the_same_candidate`,
//!    `request_bytes_keeps_a_500_on_the_same_candidate`.
//! 3. Aliases exist only for the default host; the control plane always has
//!    exactly one candidate (the `Plane::Control` arm of
//!    `routing::plane_urls` is a singleton by construction); a custom base is
//!    never redirected — `a_custom_base_url_is_never_redirected_to_a_public_alias`,
//!    `default_client_carries_more_than_one_candidate`.
//! 4. `x-should-retry` overrides both predicates in both directions: explicit
//!    false forbids retry AND failover, explicit true forces retry,
//!    absent/unparseable keeps the status heuristics —
//!    `the_verdict_only_speaks_when_the_server_did`,
//!    `a_labelled_spent_response_is_neither_retried_nor_moved`,
//!    `a_labelled_retryable_response_is_retried_against_the_status`.
//! 5. The idempotency key is minted once per logical call BEFORE the loop
//!    (the single generator `headers::ensure_idempotency_key`) and re-sent
//!    verbatim across every attempt and domain move, so the caller is never
//!    double-charged — `per_call_workspace_and_idempotency_are_headers_not_body`.
//! 6. Retries happen only before any body bytes are surfaced; a broken open
//!    stream propagates, never reconnects. Structural: the engine returns 2xx
//!    responses undrained and [`crate::sse`] contains no retry logic —
//!    `chat_and_responses_streams_parse_sse_and_done` pins the parse path.
//! 7. `regional_failover` governs WHERE, never WHETHER: opting out collapses
//!    the candidate list to length one, and a pinned client still retries in
//!    place — `regional_failover_false_pins_the_client_to_one_host`.
//! 8. Transport errors (no server saw the request) may always move hosts
//!    within the flag gating. Rust's mechanism: the transport arm marks
//!    failover unconditionally and the single-candidate list is the pin —
//!    `regional_failover_false_pins_the_client_to_one_host`,
//!    `retries_retryable_status_then_succeeds` (single-candidate control
//!    plane retries in place).
//! 9. Terminal asymmetries are per-SDK contract and survive verbatim. Rust's
//!    contract: both status exhaustion and transport exhaustion return the
//!    classified [`Error`]; the buffered path drains the failure body for
//!    attribution while the stream-open path surfaces the classified error
//!    without ever handing the caller an open stream —
//!    `preserves_actionable_provider_error_fields`.
//! 10. The deliberately-unreachable verdict-false guard inside `failoverable`
//!     is a documented surviving mutant in the Python and Swift SDKs. Rust
//!     has no such mutant: the guard in `policy::failoverable_status` IS
//!     reachable and pinned — `a_labelled_spent_response_is_neither_retried_nor_moved`.
//!     Do not "harmonize" the mechanism; only the invariant is shared.

pub(crate) mod engine;
pub(crate) mod headers;
pub(crate) mod policy;
pub(crate) mod routing;

use crate::client::{CallOptions, Client, Plane};
use crate::error::classify_api_error;
use crate::{Error, Result};
use http::Method;
use serde::de::DeserializeOwned;
use serde_json::Value;
use url::Url;

impl Client {
    /// Buffered entry point: drives the engine, then drains the success body
    /// under the per-call deadline. The failure path is drained inside the
    /// engine, where the payload feeds error classification.
    pub(crate) async fn request_bytes(
        &self,
        plane: Plane,
        method: Method,
        path: &str,
        body: Option<Value>,
        options: CallOptions,
    ) -> Result<Vec<u8>> {
        let response = self
            .execute(plane, method, path, body, &options, false)
            .await?;
        let bytes = self.read_response(response, &options).await?;
        Ok(bytes.to_vec())
    }

    /// Streaming entry point: drives the same engine and hands back the live
    /// [`reqwest::Response`] with its body untouched, ready for SSE parsing.
    pub(crate) async fn open_stream(
        &self,
        plane: Plane,
        method: Method,
        path: &str,
        body: Value,
        options: CallOptions,
    ) -> Result<reqwest::Response> {
        self.execute(plane, method, path, Some(body), &options, true)
            .await
    }

    /// DELIBERATELY single-shot, credential-free, HTTPS-or-loopback-only
    /// fetch for public metadata (trust releases, status documents).
    ///
    /// This stays OUTSIDE the engine by design: the target is a
    /// caller-supplied absolute URL, not a plane-routed path, so candidate
    /// failover does not apply, and adding retries would change documented
    /// observable behaviour. No Authorization, workspace, or idempotency
    /// headers are ever attached.
    pub(crate) async fn credential_free_json<T: DeserializeOwned>(
        &self,
        target: &str,
    ) -> Result<T> {
        let url = Url::parse(target)
            .map_err(|error| Error::InvalidConfiguration(format!("invalid public URL: {error}")))?;
        if url.scheme() != "https"
            && url.host_str() != Some("127.0.0.1")
            && url.host_str() != Some("localhost")
        {
            return Err(Error::InvalidConfiguration(
                "public metadata URL must use HTTPS".to_owned(),
            ));
        }
        let response = self
            .http
            .get(url)
            .header(
                "user-agent",
                format!("trusted-router-rust/{}", env!("CARGO_PKG_VERSION")),
            )
            .send()
            .await
            .map_err(policy::map_reqwest_error)?;
        let status = response.status();
        let bytes = response.bytes().await.map_err(policy::map_reqwest_error)?;
        if !status.is_success() {
            return Err(classify_api_error(
                status.as_u16(),
                serde_json::from_slice(&bytes).ok(),
                None,
            ));
        }
        serde_json::from_slice(&bytes).map_err(|error| Error::Serialization(error.to_string()))
    }
}
