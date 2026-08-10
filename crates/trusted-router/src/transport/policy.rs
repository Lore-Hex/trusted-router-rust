//! L1 — policy kernel: pure retry/failover decisions. No I/O, no clock reads
//! beyond `retry-after` date math, no [`Client`](crate::client::Client) access.
//!
//! Every predicate here is a decision function over a status line and headers,
//! which is what makes the whole decision table unit-testable without a mock
//! transport (see `failover_tests` below). The invariants this kernel enforces
//! are documented at [`crate::transport`] module level; the load-bearing ones
//! locally:
//!
//! - Failover set {502, 503, 504} is a strict subset of the retry set
//!   (`only_gateway_statuses_move_domains`, `a_500_does_not_move_domains`,
//!   `a_429_does_not_move_domains`).
//! - `x-should-retry` overrides both predicates in both directions
//!   (`the_verdict_only_speaks_when_the_server_did`,
//!   `a_labelled_spent_response_is_neither_retried_nor_moved`,
//!   `a_labelled_retryable_response_is_retried_against_the_status`).
//! - `retry-after-ms` beats `retry-after`; malformed values fall through to
//!   the heuristics (`retry_after_ms_is_honored_and_beats_retry_after`).

use crate::error::classify_api_error;
use crate::Error;
use rand::Rng;
use reqwest::header::{HeaderMap, RETRY_AFTER};
use serde_json::Value;
use std::time::{Duration, SystemTime};

/// The canonical decision the transport engine acts on for one failed attempt.
///
/// The engine consumes this blindly: `retry` says WHETHER another attempt may
/// happen, `failover` says WHERE (advance the candidate cursor or stay put),
/// `retry_after` floors the backoff, and `error` is what surfaces when the
/// decision is terminal. Keeping the fields together means there is exactly
/// one place — this module — where those questions are answered.
pub(crate) struct FailureDisposition {
    /// The classified error to surface if this attempt is terminal.
    pub(crate) error: Error,
    /// Whether another attempt is allowed at all (invariant 7: WHETHER).
    pub(crate) retry: bool,
    /// Whether the attempt may move to the next candidate (invariant 7: WHERE).
    pub(crate) failover: bool,
    /// Server-requested backoff floor, when one was sent.
    pub(crate) retry_after: Option<Duration>,
}

impl FailureDisposition {
    /// Decision for a non-2xx HTTP response whose failure body was drained.
    pub(crate) fn from_http(status: u16, headers: &HeaderMap, payload: Option<Value>) -> Self {
        let retry_after = parse_retry_after(headers);
        Self {
            error: classify_api_error(status, payload, retry_after),
            retry: retryable_status(status, headers),
            failover: failoverable_status(status, headers),
            retry_after,
        }
    }

    /// Decision for a transport-level failure (no HTTP response at all).
    ///
    /// A transport failure means no server saw the request, so moving to
    /// another domain cannot double-execute anything: `failover` is
    /// unconditionally true (invariant 8). A pinned client still cannot move
    /// because its candidate list has length one — the list is the gate, not a
    /// second flag.
    pub(crate) fn from_transport(error: Error) -> Self {
        let retry = retryable_transport(&error);
        Self {
            error,
            retry,
            failover: true,
            retry_after: None,
        }
    }
}

/// The gateway's explicit verdict, which overrides every heuristic below it.
///
/// A status code cannot say whether a provider already ran. A 502 from "could
/// not reach the provider" and a 502 from "the generation succeeded and then
/// settlement failed" are indistinguishable here, and only the second is
/// dangerous to re-send. The gateway knows and says so, using the same
/// `x-should-retry` header `OpenAI`'s clients honour.
///
/// `None` means the server did not say, which leaves existing behaviour intact
/// for older gateways and for deliberately unlabelled paths.
fn should_retry_verdict(headers: &HeaderMap) -> Option<bool> {
    match headers
        .get("x-should-retry")?
        .to_str()
        .ok()?
        .trim()
        .to_ascii_lowercase()
        .as_str()
    {
        "true" => Some(true),
        "false" => Some(false),
        _ => None,
    }
}

fn retryable_status(status: u16, headers: &HeaderMap) -> bool {
    if let Some(verdict) = should_retry_verdict(headers) {
        return verdict;
    }
    status == 429 || matches!(status, 500 | 502 | 503 | 504)
}

pub(crate) fn retryable_transport(error: &Error) -> bool {
    matches!(error, Error::Transport(_) | Error::Timeout(_))
}

/// Full-jitter exponential backoff: 500ms base, 30s cap, exponent-capped,
/// floored by the server's `retry-after`/`retry-after-ms` when present.
pub(crate) fn retry_delay(attempt: usize, retry_after: Option<Duration>) -> Duration {
    let exponent = u32::try_from(attempt.min(6)).unwrap_or(6);
    let ceiling_ms = 500_u64.saturating_mul(2_u64.pow(exponent)).min(30_000);
    let jitter_ms = rand::thread_rng().gen_range(0..=ceiling_ms);
    retry_after
        .unwrap_or_default()
        .max(Duration::from_millis(jitter_ms))
}

pub(crate) fn parse_retry_after(headers: &HeaderMap) -> Option<Duration> {
    // retry-after-ms wins when both are present: it is the more precise of the
    // two, and a server that sends it means the sub-second value.
    if let Some(raw) = headers.get("retry-after-ms").and_then(|v| v.to_str().ok()) {
        if let Ok(millis) = raw.trim().parse::<u64>() {
            return Some(Duration::from_millis(millis));
        }
    }
    let value = headers.get(RETRY_AFTER)?.to_str().ok()?;
    if let Ok(seconds) = value.trim().parse::<u64>() {
        return Some(Duration::from_secs(seconds));
    }
    let timestamp = httpdate::parse_http_date(value).ok()?;
    timestamp.duration_since(SystemTime::now()).ok()
}

/// Transport-error classification: timeout stays a timeout, everything else is
/// a transport failure the retry predicates treat as "no server saw it".
pub(crate) fn map_reqwest_error(error: reqwest::Error) -> Error {
    if error.is_timeout() {
        Error::Timeout(error.to_string())
    } else {
        Error::Transport(error.to_string())
    }
}

/// Statuses that justify moving to a different domain.
///
/// Deliberately narrower than [`retryable_status`], which also covers 429 and
/// 500. A 429 should back off against the same host, and a 500 means a server
/// received and processed a non-idempotent inference request.
fn failoverable_status(status: u16, headers: &HeaderMap) -> bool {
    // An explicit x-should-retry: false forbids moving outright — that is the
    // gateway saying a provider already ran, which is exactly when re-sending
    // anywhere costs a second generation.
    if should_retry_verdict(headers) == Some(false) {
        return false;
    }
    // 502..=504 rather than 502 | 503 | 504 only because clippy's
    // manual_range_patterns is denied here. The set is the same three statuses,
    // and 500 stays outside it deliberately.
    matches!(status, 502..=504)
}

#[cfg(test)]
mod failover_tests {
    use super::{failoverable_status, parse_retry_after, retryable_status, should_retry_verdict};
    use reqwest::header::HeaderMap;
    use std::time::Duration;

    fn no_headers() -> HeaderMap {
        HeaderMap::new()
    }

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (name, value) in pairs {
            map.insert(
                reqwest::header::HeaderName::from_bytes(name.as_bytes()).unwrap(),
                value.parse().unwrap(),
            );
        }
        map
    }

    #[test]
    fn only_gateway_statuses_move_domains() {
        for status in [502u16, 503, 504] {
            assert!(
                failoverable_status(status, &no_headers()),
                "{status} should fail over"
            );
        }
    }

    #[test]
    fn a_500_does_not_move_domains() {
        // A 500 means a server received and processed the request. Inference is
        // not idempotent, so retrying it on another domain risks charging
        // twice. It stays RETRYABLE against the same host.
        assert!(
            !failoverable_status(500, &no_headers()),
            "500 must not move domains"
        );
        assert!(
            retryable_status(500, &no_headers()),
            "500 should still retry in place"
        );
    }

    #[test]
    fn a_429_does_not_move_domains() {
        // Rate limiting is not a reason to spread load onto another domain;
        // back off against the same host instead.
        assert!(!failoverable_status(429, &no_headers()));
        assert!(retryable_status(429, &no_headers()));
    }

    #[test]
    fn the_verdict_only_speaks_when_the_server_did() {
        assert_eq!(should_retry_verdict(&no_headers()), None);
        assert_eq!(
            should_retry_verdict(&headers(&[("x-should-retry", "TRUE")])),
            Some(true)
        );
        assert_eq!(
            should_retry_verdict(&headers(&[("x-should-retry", "false")])),
            Some(false)
        );
        // Anything we do not understand must not be read as a verdict.
        assert_eq!(
            should_retry_verdict(&headers(&[("x-should-retry", "perhaps")])),
            None
        );
    }

    #[test]
    fn a_labelled_spent_response_is_neither_retried_nor_moved() {
        let spent = headers(&[("x-should-retry", "false")]);
        assert!(
            !retryable_status(502, &spent),
            "the gateway said a provider already ran"
        );
        assert!(!failoverable_status(502, &spent), "and it must not move");
    }

    #[test]
    fn a_labelled_retryable_response_is_retried_against_the_status() {
        // The header overrides in both directions, as OpenAI's clients do.
        let retry = headers(&[("x-should-retry", "true")]);
        assert!(retryable_status(400, &retry));
    }

    #[test]
    fn retry_after_ms_is_honored_and_beats_retry_after() {
        assert_eq!(
            parse_retry_after(&headers(&[("retry-after-ms", "250")])),
            Some(Duration::from_millis(250))
        );
        assert_eq!(
            parse_retry_after(&headers(&[("retry-after-ms", "500"), ("retry-after", "9")])),
            Some(Duration::from_millis(500)),
            "the precise header should win"
        );
        assert_eq!(
            parse_retry_after(&headers(&[
                ("retry-after-ms", "soon"),
                ("retry-after", "3")
            ])),
            Some(Duration::from_secs(3)),
            "junk should fall through, not poison the backoff"
        );
    }
}
