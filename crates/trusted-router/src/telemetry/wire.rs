//! The closed beacon schema (§5) as serialised on the wire, and the bounded
//! SDK identity (§5.1). Mirrors `trusted_router.client_events_schema` and
//! the Python SDK's `_wire_event`/`_wire_attempt`/`_counter_row` clamps.
//!
//! Every string here is a closed enum or an anchored, length-bounded grammar
//! (§2.1). There is no free text: `model` and `request_id` are regex-gated
//! and dropped to `null` when they do not fit; the SDK identity falls back
//! to in-grammar defaults field by field.

use super::{
    valid_model, valid_request_id, AttemptRecord, CounterKey, CounterRow, ErrorClass, ErrorSource,
    LatencyBucket, RequestEvent, ShouldRetry,
};
use crate::constants::TELEMETRY_SCHEMA_VERSION;
use http::Method;
use serde::Serialize;
use std::collections::BTreeMap;

/// §5.3 durations are bounded to one hour.
const MAX_DURATION_MS: u64 = 3_600_000;
/// §5.3/§5.4 ages are bounded to one day.
const MAX_AGE_MS: u64 = 86_400_000;
/// §5.4 counts are bounded to ten million per row.
const MAX_COUNT: u64 = 10_000_000;
/// §5.3 caps the attempts carried by one event.
const MAX_WIRE_ATTEMPTS: usize = 16;

/// Why an event was kept (§5.3 `sample_reason`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SampleReason {
    Failure,
    Retried,
    Slow,
    Random,
}

impl SampleReason {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Failure => "failure",
            Self::Retried => "retried",
            Self::Slow => "slow",
            Self::Random => "random",
        }
    }
}

/// §5.1 `sdk`: the bounded, content-free identity of this process.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct SdkIdentity {
    pub(crate) name: &'static str,
    pub(crate) version: String,
    pub(crate) lang: &'static str,
    pub(crate) runtime: String,
    pub(crate) os: &'static str,
    pub(crate) arch: &'static str,
}

/// The contract's bounded `SemVer` grammar (≤ 32 bytes), matching Python's
/// `_SEMVER_RE`: three release numbers without leading zeroes, optional
/// dot-separated prerelease and build identifiers made of ASCII
/// alphanumerics and hyphens.
pub(crate) fn valid_semver(value: &str) -> bool {
    if value.is_empty() || value.len() > 32 {
        return false;
    }
    let mut build_parts = value.split('+');
    let core = build_parts.next().unwrap_or_default();
    let build = build_parts.next();
    if build_parts.next().is_some() {
        return false;
    }
    let mut pre_parts = core.splitn(2, '-');
    let release = pre_parts.next().unwrap_or_default();
    let prerelease = pre_parts.next();
    let valid_identifiers = |part: &str| {
        !part.is_empty()
            && part.split('.').all(|identifier| {
                !identifier.is_empty()
                    && identifier
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            })
    };
    let parts: Vec<&str> = release.split('.').collect();
    parts.len() == 3
        && parts.iter().all(|part| {
            !part.is_empty()
                && part.bytes().all(|byte| byte.is_ascii_digit())
                && (*part == "0" || !part.starts_with('0'))
        })
        && prerelease.is_none_or(valid_identifiers)
        && build.is_none_or(valid_identifiers)
}

/// The `Runtime` grammar, `^[a-z]{1,10}/[0-9A-Za-z.+-]{1,24}$`.
pub(crate) fn valid_runtime(value: &str) -> bool {
    let Some((name, version)) = value.split_once('/') else {
        return false;
    };
    !name.is_empty()
        && name.len() <= 10
        && name.bytes().all(|byte| byte.is_ascii_lowercase())
        && !version.is_empty()
        && version.len() <= 24
        && version
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b".+-".contains(&byte))
}

/// Builds the compiler runtime token shared by the beacon identity and every
/// SDK-owned HTTP client's `User-Agent`. Missing, empty, or out-of-grammar
/// releases fall back to the contract-valid unknown value.
fn runtime_token_from_release(release: Option<&str>) -> String {
    let release = release
        .filter(|value| !value.is_empty())
        .unwrap_or("unknown");
    let runtime = format!("rustc/{release}");
    if valid_runtime(&runtime) {
        runtime
    } else {
        "rustc/unknown".to_owned()
    }
}

pub(crate) fn runtime_token() -> String {
    runtime_token_from_release(option_env!("TRUSTED_ROUTER_RUSTC_RELEASE"))
}

/// Static request identity (§3.1), including the optional runtime suffix.
pub(crate) fn sdk_user_agent() -> String {
    format!(
        "trusted-router-rust/{} {}",
        env!("CARGO_PKG_VERSION"),
        runtime_token()
    )
}

fn os_enum(os: &str) -> &'static str {
    match os {
        "linux" => "linux",
        "macos" => "macos",
        "windows" => "windows",
        "ios" => "ios",
        "android" => "android",
        "freebsd" => "freebsd",
        _ => "other",
    }
}

fn arch_enum(arch: &str) -> &'static str {
    match arch {
        "x86_64" => "x64",
        "x86" => "x32",
        "aarch64" => "arm64",
        "arm" => "arm",
        "wasm32" | "wasm64" => "wasm",
        _ => "other",
    }
}

/// Builds the identity from compile-time facts: the crate version, the
/// compiler release captured by `build.rs`, and the target OS/arch. Every
/// field is validated against its grammar and falls back in-grammar, so a
/// batch can never be rejected for its identity.
pub(crate) fn sdk_identity() -> SdkIdentity {
    let version = env!("CARGO_PKG_VERSION");
    SdkIdentity {
        name: "tr-rust",
        version: if valid_semver(version) {
            version.to_owned()
        } else {
            "0.0.0".to_owned()
        },
        lang: "rust",
        runtime: runtime_token(),
        os: os_enum(std::env::consts::OS),
        arch: arch_enum(std::env::consts::ARCH),
    }
}

/// §5.3 `ClientAttempt` on the wire. Field order follows the Python SDK's
/// `_wire_attempt`; `should_retry` is omitted when it was not observed.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub(crate) struct WireAttempt {
    pub(crate) index: u64,
    pub(crate) host: &'static str,
    pub(crate) outcome: &'static str,
    pub(crate) http_status: Option<u16>,
    pub(crate) error_class: Option<&'static str>,
    pub(crate) error_source: Option<&'static str>,
    pub(crate) retry_after_ms: Option<u64>,
    pub(crate) elapsed_ms: u64,
    pub(crate) ttfb_ms: Option<u64>,
    pub(crate) request_id: Option<String>,
    pub(crate) moved: bool,
    /// Omitted when the server sent no valid verdict; otherwise a JSON
    /// boolean, matching Python's `_wire_attempt` and §5.3.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) should_retry: Option<bool>,
}

fn bounded(value: u64, minimum: u64, maximum: u64) -> u64 {
    value.clamp(minimum, maximum)
}

fn bounded_optional(value: Option<u64>, minimum: u64, maximum: u64) -> Option<u64> {
    value.filter(|value| (minimum..=maximum).contains(value))
}

impl WireAttempt {
    pub(crate) fn from_record(record: &AttemptRecord) -> Self {
        Self {
            index: bounded(u64::try_from(record.index).unwrap_or(u64::MAX), 0, 99),
            host: record.host.as_str(),
            outcome: record.outcome.as_str(),
            http_status: record
                .http_status
                .filter(|status| (100..=599).contains(status)),
            error_class: record.error_class.map(ErrorClass::as_str),
            error_source: record.error_source.map(ErrorSource::as_str),
            retry_after_ms: bounded_optional(record.retry_after_ms, 0, MAX_DURATION_MS),
            elapsed_ms: bounded(record.elapsed_ms, 0, MAX_DURATION_MS),
            ttfb_ms: bounded_optional(record.ttfb_ms, 0, MAX_DURATION_MS),
            request_id: record
                .request_id
                .clone()
                .filter(|value| valid_request_id(value)),
            moved: record.moved,
            should_retry: match record.should_retry {
                ShouldRetry::True => Some(true),
                ShouldRetry::False => Some(false),
                ShouldRetry::Absent => None,
            },
        }
    }
}

/// §5.3 `ClientRequestEvent` on the wire.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub(crate) struct WireEvent {
    pub(crate) age_ms: u64,
    pub(crate) plane: &'static str,
    pub(crate) endpoint: &'static str,
    pub(crate) method: &'static str,
    pub(crate) streaming: bool,
    pub(crate) provider_pinned: bool,
    pub(crate) model: Option<String>,
    pub(crate) attempts: Vec<WireAttempt>,
    pub(crate) final_outcome: &'static str,
    pub(crate) final_http_status: Option<u16>,
    pub(crate) total_ms: u64,
    pub(crate) ttft_ms: Option<u64>,
    pub(crate) failover_used: bool,
    pub(crate) timeout_phase: &'static str,
    pub(crate) configured_timeout_ms: Option<u64>,
    pub(crate) sample_rate: f64,
    pub(crate) sample_reason: &'static str,
}

impl WireEvent {
    /// Converts a finished call into its wire shape, or `None` when the
    /// schema cannot carry it (no attempts, or a sample rate outside
    /// `(0, 1]`). `age_ms` starts at zero and is recomputed at flush.
    pub(crate) fn from_event(
        event: &RequestEvent,
        sample_reason: SampleReason,
        sample_rate: f64,
    ) -> Option<Self> {
        let attempts: Vec<WireAttempt> = event
            .attempts
            .iter()
            .take(MAX_WIRE_ATTEMPTS)
            .map(WireAttempt::from_record)
            .collect();
        if attempts.is_empty()
            || !(sample_rate.is_finite() && sample_rate > 0.0 && sample_rate <= 1.0)
        {
            return None;
        }
        let method = match event.method {
            Method::GET => "GET",
            Method::POST => "POST",
            _ => return None,
        };
        Some(Self {
            age_ms: 0,
            plane: "inference",
            endpoint: event.endpoint.as_str(),
            method,
            streaming: event.streaming,
            provider_pinned: event.provider_pinned,
            model: event.model.clone().filter(|model| valid_model(model)),
            attempts,
            final_outcome: event.final_outcome.as_str(),
            final_http_status: event
                .final_http_status
                .filter(|status| (100..=599).contains(status)),
            total_ms: bounded(event.total_ms, 0, MAX_DURATION_MS),
            ttft_ms: bounded_optional(event.ttft_ms, 0, MAX_DURATION_MS),
            failover_used: event.failover_used,
            timeout_phase: event.timeout_phase.as_str(),
            configured_timeout_ms: bounded_optional(
                event.configured_timeout_ms,
                1,
                MAX_DURATION_MS,
            ),
            sample_rate,
            sample_reason: sample_reason.as_str(),
        })
    }

    /// The same event with its age recomputed for a flush.
    pub(crate) fn aged(&self, age_ms: u64) -> Self {
        Self {
            age_ms: bounded(age_ms, 0, MAX_AGE_MS),
            ..self.clone()
        }
    }
}

fn wire_histogram(histogram: &BTreeMap<LatencyBucket, u64>) -> BTreeMap<&'static str, u64> {
    histogram
        .iter()
        .map(|(bucket, count)| (bucket.as_str(), bounded(*count, 0, MAX_COUNT)))
        .collect()
}

/// §5.4 `ClientMinuteCounter` on the wire.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct WireCounter {
    pub(crate) window_start_age_ms: u64,
    pub(crate) level: &'static str,
    pub(crate) endpoint: &'static str,
    pub(crate) streaming: bool,
    pub(crate) host: &'static str,
    pub(crate) outcome: &'static str,
    pub(crate) error_class: Option<&'static str>,
    pub(crate) http_status_class: &'static str,
    pub(crate) timeout_phase: &'static str,
    pub(crate) timeout_floor_met: bool,
    pub(crate) provider_pinned: bool,
    pub(crate) requests: u64,
    pub(crate) attempts: u64,
    pub(crate) failover_used: u64,
    pub(crate) first_attempt_success: u64,
    pub(crate) total_ms_hist: BTreeMap<&'static str, u64>,
    pub(crate) first_event_ms_hist: BTreeMap<&'static str, u64>,
}

impl WireCounter {
    pub(crate) fn from_row(key: &CounterKey, row: &CounterRow, window_age_ms: u64) -> Self {
        Self {
            window_start_age_ms: bounded(window_age_ms, 0, MAX_AGE_MS),
            level: key.level.as_str(),
            endpoint: key.endpoint.as_str(),
            streaming: key.streaming,
            host: key.host.as_str(),
            outcome: key.outcome.as_str(),
            error_class: key.error_class.map(ErrorClass::as_str),
            http_status_class: key.http_status_class.as_str(),
            timeout_phase: key.timeout_phase.as_str(),
            timeout_floor_met: key.timeout_floor_met,
            provider_pinned: key.provider_pinned,
            requests: bounded(row.requests, 1, MAX_COUNT),
            attempts: bounded(row.attempts, 0, MAX_COUNT),
            failover_used: bounded(row.failover_used, 0, MAX_COUNT),
            first_attempt_success: bounded(row.first_attempt_success, 0, MAX_COUNT),
            total_ms_hist: wire_histogram(&row.total_ms_hist),
            first_event_ms_hist: wire_histogram(&row.first_event_ms_hist),
        }
    }
}

/// §5.1 `ClientEventsBatch` on the wire. Nothing else is ever added: no
/// tenant, key, session, or host names, no prompt text, no idempotency keys.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub(crate) struct WireBatch {
    pub(crate) schema_version: u32,
    pub(crate) batch_id: String,
    pub(crate) instance_id: String,
    pub(crate) seq: u64,
    pub(crate) sent_at_ms: u64,
    pub(crate) sdk: SdkIdentity,
    pub(crate) synthetic: bool,
    pub(crate) dropped_since_last: u64,
    pub(crate) events: Vec<WireEvent>,
    pub(crate) counters: Vec<WireCounter>,
}

impl WireBatch {
    pub(crate) fn new(batch_id: String, instance_id: String, seq: u64, sdk: SdkIdentity) -> Self {
        Self {
            schema_version: TELEMETRY_SCHEMA_VERSION,
            batch_id,
            instance_id,
            seq,
            sent_at_ms: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .ok()
                .and_then(|since| u64::try_from(since.as_millis()).ok())
                .unwrap_or(0),
            sdk,
            synthetic: false,
            dropped_since_last: 0,
            events: Vec::new(),
            counters: Vec::new(),
        }
    }
}

/// Merges a latency histogram increment into a row, clamping every count.
pub(crate) fn merge_histogram(
    target: &mut BTreeMap<LatencyBucket, u64>,
    source: &BTreeMap<LatencyBucket, u64>,
) {
    for (bucket, count) in source {
        let entry = target.entry(*bucket).or_insert(0);
        *entry = entry.saturating_add(bounded(*count, 0, MAX_COUNT));
    }
}

/// Merges one increment into a counter row, mirroring the Python SDK's
/// `_merge_counter_increment` clamps.
pub(crate) fn merge_counter_increment(target: &mut CounterRow, increment: &CounterRow) {
    target.requests = target
        .requests
        .saturating_add(bounded(increment.requests, 0, MAX_COUNT));
    target.attempts = target
        .attempts
        .saturating_add(bounded(increment.attempts, 0, MAX_COUNT));
    target.failover_used =
        target
            .failover_used
            .saturating_add(bounded(increment.failover_used, 0, MAX_COUNT));
    target.first_attempt_success = target.first_attempt_success.saturating_add(bounded(
        increment.first_attempt_success,
        0,
        MAX_COUNT,
    ));
    merge_histogram(&mut target.total_ms_hist, &increment.total_ms_hist);
    merge_histogram(
        &mut target.first_event_ms_hist,
        &increment.first_event_ms_hist,
    );
}

#[cfg(test)]
mod tests {
    use super::{
        runtime_token_from_release, sdk_identity, sdk_user_agent, valid_runtime, valid_semver,
    };

    #[test]
    fn the_identity_only_uses_the_contract_vocabulary() {
        let identity = sdk_identity();
        assert_eq!(identity.name, "tr-rust");
        assert_eq!(identity.lang, "rust");
        assert!(valid_semver(&identity.version), "{}", identity.version);
        assert!(valid_runtime(&identity.runtime), "{}", identity.runtime);
        assert!(identity.runtime.starts_with("rustc/"));
        assert!(
            ["linux", "macos", "windows", "ios", "android", "freebsd", "other"]
                .contains(&identity.os)
        );
        assert!(["x64", "x32", "arm", "arm64", "wasm", "other"].contains(&identity.arch));
    }

    #[test]
    fn the_user_agent_carries_the_same_valid_runtime_as_the_beacon_identity() {
        let user_agent = sdk_user_agent();
        let prefix = format!("trusted-router-rust/{}", env!("CARGO_PKG_VERSION"));
        assert!(user_agent.starts_with(&prefix), "{user_agent}");
        assert_eq!(user_agent.bytes().filter(|byte| *byte == b' ').count(), 1);
        let (actual_prefix, runtime) = user_agent.split_once(' ').unwrap();
        assert_eq!(actual_prefix, prefix);
        assert!(valid_runtime(runtime), "{runtime}");
        assert_eq!(runtime, sdk_identity().runtime);
        assert!(
            user_agent.len() <= 256,
            "{} bytes: {user_agent}",
            user_agent.len()
        );
    }

    #[test]
    fn a_missing_or_empty_compiler_release_has_a_valid_runtime_fallback() {
        for release in [None, Some("")] {
            let runtime = runtime_token_from_release(release);
            assert_eq!(runtime, "rustc/unknown");
            assert!(valid_runtime(&runtime), "{runtime}");
        }
    }

    #[test]
    fn the_version_grammar_matches_the_bounded_python_semver() {
        for ok in ["0.1.0", "1.2.3", "10.20.30-rc.1", "1.0.0+build.5"] {
            assert!(valid_semver(ok), "{ok}");
        }
        for bad in [
            "1.0",
            "01.0.0",
            "1.0.0-rc.1+",
            "1.0.0-",
            "",
            "v1.0.0",
            "1.0.0+build+again",
            "1.0.0-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ] {
            assert!(!valid_semver(bad), "{bad}");
        }
        assert!(valid_semver("1.0.0-rc.1+build.5"));
        assert!(valid_runtime("rustc/1.88.0"));
        assert!(valid_runtime("rustc/1.99.0-nightly"));
        assert!(!valid_runtime("Rustc/1.88.0"));
        assert!(!valid_runtime("rustc/"));
        assert!(!valid_runtime("rustc"));
        assert!(!valid_runtime("rustc/1.88.0 (abcdef 2026-01-01)"));
    }
}
