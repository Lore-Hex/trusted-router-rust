//! Shared HTTP transport, retries, and credential boundaries.
//!
//! Layered per the harmonized cross-SDK architecture: [`policy`] is the pure
//! decision kernel (L1), [`routing`] builds the candidate set (L2),
//! [`engine`] hosts THE single retry/failover loop (L3), and [`headers`]
//! assembles each attempt (L4). This file keeps the thin entry points:
//! `request_bytes` (execute, then drain the body under the deadline),
//! `open_stream` (execute, returning the live undrained response), and the
//! deliberately single-shot `credential_free_json`. The telemetry beacon
//! (`telemetry::reporter`) follows the `credential_free_json` precedent —
//! one single-shot `POST` outside this engine, no retries, no failover — on
//! the reporter's own client rather than either transport below.
//!
//! # Invariants
//!
//! Each line names its enforcing test. Policy tests live in
//! `transport/policy.rs`, walk tests in `transport/engine.rs`, construction
//! tests in `tests/alias_failover.rs`, contract tests in
//! `tests/client_contract.rs`.
//!
//! 1. The failover set {502, 503, 504} is a strict subset of the retry set
//!    {429, every status >=500, verdict-true} —
//!    `only_gateway_statuses_move_domains`, `all_server_errors_are_retryable`,
//!    `a_429_does_not_move_domains`.
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
//! 8. Transport errors are ambiguous about server acceptance, so retries and
//!    host moves require a replay-safe method or idempotency key. Rust's
//!    transport arm marks a potential failover, then the replay gate and the
//!    candidate list decide whether it can occur —
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
use crate::telemetry::StreamRecorder;
use crate::{Error, Result};
use http::Method;
use serde::de::DeserializeOwned;
use serde_json::Value;
use std::time::Duration;
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
        let (response, recorder) = self
            .execute(plane, method, path, body, &options, false)
            .await?;
        // The call is finished here, not in the engine: a success body that
        // fails to drain is this attempt's outcome (§5.3), recorded with its
        // typed class before the error is flattened.
        match self.read_body(response, &options).await {
            Ok(bytes) => {
                if let Some(mut recorder) = recorder {
                    recorder.finish(false);
                }
                Ok(bytes.to_vec())
            }
            Err(failure) => {
                if let Some(mut recorder) = recorder {
                    failure.record(&mut recorder, true, false);
                    recorder.finish(false);
                }
                Err(failure.into_error("response body deadline exceeded"))
            }
        }
    }

    /// Streaming entry point: drives the same engine and hands back the live
    /// [`reqwest::Response`] with its body untouched, ready for SSE parsing,
    /// together with the call's recorder for the SSE layer to finish (first
    /// event, mid-body failure, completion, or abandonment).
    pub(crate) async fn open_stream(
        &self,
        plane: Plane,
        method: Method,
        path: &str,
        body: Value,
        options: CallOptions,
    ) -> Result<(reqwest::Response, Option<StreamRecorder>)> {
        let (response, recorder) = self
            .execute(plane, method, path, Some(body), &options, true)
            .await?;
        Ok((response, recorder.map(StreamRecorder::new)))
    }

    /// Executes a plane request on the SDK-owned credential-free transport.
    /// This is used for OAuth exchange and attestation so an injected
    /// reqwest client's default headers, cookies, and redirect policy cannot
    /// cross the credential boundary.
    pub(crate) async fn credential_free_plane_bytes(
        &self,
        plane: Plane,
        method: Method,
        path: &str,
        body: Option<Value>,
        mut options: CallOptions,
    ) -> Result<Vec<u8>> {
        options.api_key = Some(String::new());
        options.workspace_id = Some(String::new());
        options.headers.retain(|name, _| !credential_header(name));
        self.credential_free_clone()
            .request_bytes(plane, method, path, body, options)
            .await
    }

    pub(crate) async fn credential_free_control_request<T: DeserializeOwned>(
        &self,
        method: Method,
        path: &str,
        body: Option<Value>,
        options: CallOptions,
    ) -> Result<T> {
        let bytes = self
            .credential_free_plane_bytes(Plane::Control, method, path, body, options)
            .await?;
        serde_json::from_slice(&bytes).map_err(|error| Error::Serialization(error.to_string()))
    }

    fn credential_free_clone(&self) -> Self {
        let mut client = self.clone();
        client.api_key = None;
        client.workspace_id = None;
        client.telemetry = false;
        client.telemetry_sink = None;
        client.headers.retain(|name, _| !credential_header(name));
        client.http = self.credential_free_http.clone();
        client
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
        let request = self
            .credential_free_http
            .get(url)
            .header(
                "user-agent",
                format!("trusted-router-rust/{}", env!("CARGO_PKG_VERSION")),
            )
            .build()
            .map_err(policy::map_reqwest_error)?;
        let response = match self.timeout {
            Some(duration) if duration != Duration::ZERO => {
                tokio::time::timeout(duration, self.credential_free_http.execute(request))
                    .await
                    .map_err(|_| {
                        Error::Timeout(
                            "public metadata response headers deadline exceeded".to_owned(),
                        )
                    })?
                    .map_err(policy::map_reqwest_error)?
            }
            _ => self
                .credential_free_http
                .execute(request)
                .await
                .map_err(policy::map_reqwest_error)?,
        };
        let status = response.status();
        let bytes = match self.timeout {
            Some(duration) if duration != Duration::ZERO => {
                tokio::time::timeout(duration, response.bytes())
                    .await
                    .map_err(|_| {
                        Error::Timeout("public metadata response body deadline exceeded".to_owned())
                    })?
                    .map_err(policy::map_reqwest_error)?
            }
            _ => response.bytes().await.map_err(policy::map_reqwest_error)?,
        };
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

fn credential_header(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "authorization"
            | "proxy-authorization"
            | "cookie"
            | "cookie2"
            | "x-api-key"
            | "x-trustedrouter-workspace"
            | "idempotency-key"
            | "x-tr-client"
    )
}
