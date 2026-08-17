//! L4 — attempt assembly: per-attempt headers and per-call idempotency keys.
//!
//! Header maps are rebuilt for every attempt from the same [`CallOptions`],
//! so every attempt and every domain move sends identical credentials and the
//! identical idempotency key. Empty-string overrides deliberately suppress
//! the Authorization and workspace headers
//! (`explicit_empty_overrides_suppress_credentials` in
//! `tests/client_contract.rs`).

use crate::client::{CallOptions, Client};
use crate::telemetry::RequestRecorder;
use crate::{Error, Result};
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};

impl Client {
    pub(crate) fn request_headers(
        &self,
        options: &CallOptions,
        telemetry: Option<&RequestRecorder>,
    ) -> Result<HeaderMap> {
        let mut headers = HeaderMap::new();
        for (name, value) in self.headers.iter().chain(options.headers.iter()) {
            // The reserved telemetry header is SDK-owned UNCONDITIONALLY
            // (client telemetry contract v1 §3.2): a caller-supplied
            // `x-tr-client` is dropped before parsing, on every plane and
            // regardless of opt-out, so a forged value can neither ride the
            // wire as telemetry nor fail the request by being unparseable.
            // (trusted-router-py forwards a caller value when telemetry is
            // off — an accident of its header plumbing, not contract, and
            // deliberately not replicated.)
            if name.eq_ignore_ascii_case("x-tr-client") {
                continue;
            }
            headers.insert(parse_header_name(name)?, parse_header_value(value)?);
        }
        // One bounded, content-free reliability header per attempt (§3.2).
        enforce_reserved_telemetry_header(&mut headers, telemetry);
        headers.insert(
            reqwest::header::USER_AGENT,
            parse_header_value(&format!(
                "trusted-router-rust/{}",
                env!("CARGO_PKG_VERSION")
            ))?,
        );
        let api_key = options.api_key.as_ref().or(self.api_key.as_ref());
        if let Some(api_key) = api_key.filter(|value| !value.is_empty()) {
            headers.insert(
                reqwest::header::AUTHORIZATION,
                parse_header_value(&format!("Bearer {api_key}"))?,
            );
        }
        let workspace = options.workspace_id.as_ref().or(self.workspace_id.as_ref());
        if let Some(workspace) = workspace.filter(|value| !value.is_empty()) {
            headers.insert(
                HeaderName::from_static("x-trustedrouter-workspace"),
                parse_header_value(workspace)?,
            );
        }
        if let Some(key) = options
            .idempotency_key
            .as_ref()
            .filter(|value| !value.is_empty())
        {
            headers.insert(
                HeaderName::from_static("idempotency-key"),
                parse_header_value(key)?,
            );
        }
        Ok(headers)
    }
}

/// Mints the retry-stable idempotency key when the caller supplied none.
///
/// This is the SINGLE key generator in the SDK (invariant 5): buffered
/// endpoint wrappers and the SSE streaming openers both come through here, so
/// the `tr-req-{uuid}` key is minted ONCE per logical call BEFORE the retry
/// loop and replayed verbatim on every attempt and every domain move — the
/// caller is never double-charged (idempotent auth + exactly-once settlement).
/// Its header transport is pinned by
/// `per_call_workspace_and_idempotency_are_headers_not_body` in
/// `tests/client_contract.rs`.
pub(crate) fn ensure_idempotency_key(mut options: CallOptions) -> CallOptions {
    if options.idempotency_key.is_none() {
        options.idempotency_key = Some(format!("tr-req-{}", uuid::Uuid::new_v4().simple()));
    }
    options
}

/// The single owner of the `x-tr-client` slot in a header map: any existing
/// value is removed, and the recorder's value — when there is one — is
/// inserted. The recorder returns `None` for custom hosts, out-of-bounds
/// attempt indices, and out-of-grammar values, and an unparseable value is
/// silently skipped — telemetry may never fail a request (§2.2).
///
/// Called twice per attempt: on the SDK-assembled map in
/// [`Client::request_headers`], and again by the engine on the BUILT
/// [`reqwest::Request`]'s map — the last point the SDK sees the headers.
/// That second pass means an `x-tr-client` sneaking in through any
/// SDK-visible layer is replaced or dropped. One layer remains structurally
/// out of reach: reqwest merges an injected client's `default_headers`
/// inside its own `execute_request` (insert-if-vacant), after the request
/// leaves the SDK. An occupied slot — every attempt with a live recorder
/// value — blocks that merge; a deliberately vacant slot on a suppressed
/// attempt cannot, so a caller who configured `x-tr-client` as a default on
/// their injected reqwest client ships their own value on suppressed
/// attempts. That is the caller's client configuration, pinned as a
/// documented boundary in `tests/telemetry_header.rs`.
pub(crate) fn enforce_reserved_telemetry_header(
    headers: &mut HeaderMap,
    telemetry: Option<&RequestRecorder>,
) {
    headers.remove("x-tr-client");
    if let Some(value) = telemetry.and_then(RequestRecorder::header_value) {
        if let Ok(value) = HeaderValue::from_str(&value) {
            headers.insert(HeaderName::from_static("x-tr-client"), value);
        }
    }
}

fn parse_header_name(value: &str) -> Result<HeaderName> {
    HeaderName::from_bytes(value.as_bytes())
        .map_err(|error| Error::InvalidConfiguration(format!("invalid header name: {error}")))
}

fn parse_header_value(value: &str) -> Result<HeaderValue> {
    HeaderValue::from_str(value)
        .map_err(|error| Error::InvalidConfiguration(format!("invalid header value: {error}")))
}
