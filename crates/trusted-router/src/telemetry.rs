//! Client-observed reliability telemetry: the `x-tr-client` header channel
//! and the `/client-events` beacon channel.
//!
//! Implements contract v1 of `docs/client-telemetry.md` (Lore-Hex/quill-router):
//! the per-attempt header (§3.2) and the content-free beacon (§4, §5). This
//! file holds the closed vocabularies, the transport-error classifier, and
//! the per-call [`RequestRecorder`] that observes every attempt at the SDK's
//! single emit point (`transport::engine`, §6.1) and derives the sampled
//! event plus the exact per-minute counter increments in
//! [`RequestRecorder::finish`] (§5.3, §5.4 — a port of
//! `trusted_router._telemetry.RequestRecorder._finish`). [`reporter`]
//! buffers, bounds, and delivers those on the reporter's OWN HTTP client;
//! [`wire`] is the closed batch schema and the SDK identity.
//!
//! Non-negotiable (§2.2): telemetry never fails a request. Every path in this
//! module is total — no panics, no `unwrap`/`expect`, saturating integer
//! arithmetic, and an out-of-grammar header value sends nothing rather than
//! erroring. The beacon never rides the retry engine and is never itself
//! recorded.
//!
//! Host mapping (§5.2) matches by hostname, case-insensitively and ignoring
//! the port, mirroring `trusted_router._telemetry.host_enum` in the Python
//! SDK with one deliberate divergence: the Python SDK also compares the URL
//! scheme for the API hosts, classifying `http://api.trustedrouter.com` as
//! `custom`. This SDK classifies by hostname alone (the spec's §5.2 table maps
//! hostnames; only the control host is scheme-gated), which keeps the mapping
//! testable against a loopback HTTP mock via a DNS override — Rust has no
//! in-process fake transport, so the wire tests must speak real HTTP.

pub(crate) mod reporter;
pub(crate) mod wire;

use crate::constants::{ALIAS_API_BASE_URLS, DEFAULT_API_BASE_URL};
use crate::transport::policy::parse_retry_after;
use crate::transport::routing::{semantic_request_route, semantic_route};
use http::Method;
use reqwest::header::HeaderMap;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};
use url::Url;

/// Durations on the wire are clamped to one hour, per the contract's
/// `0..3600000` bounds (§3.2 `pm`/`sm`).
const MAX_DURATION_MS: u64 = 3_600_000;

/// Hard byte ceiling for the assembled `x-tr-client` header (§3.2).
const MAX_HEADER_BYTES: usize = 160;

/// Regional gateway hostnames (§5.2). The Rust SDK deliberately exposes no
/// per-region base-URL constants (see PARITY.md), so the telemetry host map
/// carries the hostnames itself; `known_hosts_match_the_contract` pins them
/// against the cross-SDK vocabulary.
const REGION_HOSTS: [(&str, Host); 3] = [
    ("api-us-central1.quillrouter.com", Host::UsCentral1),
    ("api-us-east4.quillrouter.com", Host::UsEast4),
    ("api-europe-west4.quillrouter.com", Host::EuropeWest4),
];

/// Closed host vocabulary (§5.2). Only values in this enum ever reach the
/// wire; anything unrecognised is `Custom`, and `Custom` suppresses the header.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(crate) enum Host {
    /// `api.trustedrouter.com`.
    Apex,
    /// `api.allyrouter.com`.
    Ally,
    /// `api.uptimerouter.com`.
    Uptime,
    /// `api-us-central1.quillrouter.com`.
    UsCentral1,
    /// `api-us-east4.quillrouter.com`.
    UsEast4,
    /// `api-europe-west4.quillrouter.com`.
    EuropeWest4,
    /// `https://trustedrouter.com` or a subdomain.
    Control,
    /// Anything else. Never measured, never named on the wire.
    Custom,
}

impl Host {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Apex => "apex",
            Self::Ally => "ally",
            Self::Uptime => "uptime",
            Self::UsCentral1 => "us_central1",
            Self::UsEast4 => "us_east4",
            Self::EuropeWest4 => "europe_west4",
            Self::Control => "control",
            Self::Custom => "custom",
        }
    }
}

/// Per-attempt outcomes (§5.2 `Outcome`). The wire vocabulary is pinned by
/// [`crate::constants::TELEMETRY_OUTCOMES`].
///
/// `stream_broken` and `aborted` are only ever the FINAL attempt's outcome:
/// the engine never retries after the first surfaced body byte (transport
/// invariant 6), so neither can be a *previous* attempt's outcome in a
/// header, and §3.2's `po` vocabulary has no `aborted` — a retry after one
/// would degrade to `po=none`, exactly like `ok`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(crate) enum AttemptOutcome {
    /// 2xx–3xx response.
    Ok,
    /// 4xx–5xx response.
    HttpError,
    /// No usable HTTP response.
    TransportError,
    /// The SDK's own deadline, or a transport-level timeout.
    Timeout,
    /// The body failed after the first event had already been surfaced.
    StreamBroken,
    /// The caller dropped the call (or the stream) before it completed.
    Aborted,
}

impl AttemptOutcome {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::HttpError => "http_error",
            Self::TransportError => "transport_error",
            Self::Timeout => "timeout",
            Self::StreamBroken => "stream_broken",
            Self::Aborted => "aborted",
        }
    }
}

/// Final outcome of a logical call (§5.2 `FinalOutcome`): the last
/// attempt's outcome, or `exhausted` when retries ran out on a failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FinalOutcome {
    /// The final attempt's own outcome.
    Outcome(AttemptOutcome),
    /// More than one attempt, the last one retryable but the ceiling hit.
    Exhausted,
}

impl FinalOutcome {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Outcome(outcome) => outcome.as_str(),
            Self::Exhausted => "exhausted",
        }
    }

    pub(crate) fn is_ok(self) -> bool {
        self == Self::Outcome(AttemptOutcome::Ok)
    }
}

/// Transport-error classes (§5.2 `ErrorClass`). The full wire vocabulary is
/// pinned by [`crate::constants::TELEMETRY_ERROR_CLASSES`].
///
/// `write_timeout` and `pool_timeout` exist for vocabulary completeness; the
/// engine has no write or pool deadlines and never produces them.
/// `stream_stalled` is the idle deadline elapsing after the first event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[allow(dead_code)] // Closed wire vocabulary; not every class is observable in reqwest.
pub(crate) enum ErrorClass {
    /// Name resolution failed.
    Dns,
    /// TLS negotiation or certificate verification failed.
    Tls,
    /// The peer refused the connection.
    ConnectRefused,
    /// Connecting exceeded a deadline.
    ConnectTimeout,
    /// Connecting failed for another reason.
    ConnectError,
    /// Waiting for the response exceeded a deadline.
    ReadTimeout,
    /// Sending the request exceeded a deadline (never produced here).
    WriteTimeout,
    /// Waiting for a pooled connection exceeded a deadline (never produced).
    PoolTimeout,
    /// HTTP framing was violated, or the peer closed mid-message.
    ProtocolError,
    /// The connection was reset or aborted.
    Reset,
    /// Another I/O failure.
    IoError,
    /// A proxy failed the request.
    ProxyError,
    /// The open stream went silent past the idle deadline.
    StreamStalled,
    /// Anything the classifier cannot name. Conservative: counts against
    /// `TrustedRouter` in the §8 methodology.
    Unknown,
}

impl ErrorClass {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Dns => "dns",
            Self::Tls => "tls",
            Self::ConnectRefused => "connect_refused",
            Self::ConnectTimeout => "connect_timeout",
            Self::ConnectError => "connect_error",
            Self::ReadTimeout => "read_timeout",
            Self::WriteTimeout => "write_timeout",
            Self::PoolTimeout => "pool_timeout",
            Self::ProtocolError => "protocol_error",
            Self::Reset => "reset",
            Self::IoError => "io_error",
            Self::ProxyError => "proxy_error",
            Self::StreamStalled => "stream_stalled",
            Self::Unknown => "unknown",
        }
    }
}

/// Closed endpoint vocabulary (§5.2 `Endpoint`), derived from the caller's
/// logical route by [`endpoint_enum`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[allow(dead_code)] // Closed wire vocabulary; control calls are intentionally unrecorded.
pub(crate) enum Endpoint {
    /// `/chat/completions`.
    ChatCompletions,
    /// `/messages`.
    Messages,
    /// `/responses`.
    Responses,
    /// `/embeddings`.
    Embeddings,
    /// `/images` and below.
    Images,
    /// `/videos` and below.
    Videos,
    /// `/models` and below.
    Models,
    /// `/fusion` and below.
    Fusion,
    /// Any other control-plane route (never recorded: control calls get no
    /// recorder at all).
    ControlOther,
    /// Any other inference-plane route.
    InferenceOther,
}

impl Endpoint {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::ChatCompletions => "chat_completions",
            Self::Messages => "messages",
            Self::Responses => "responses",
            Self::Embeddings => "embeddings",
            Self::Images => "images",
            Self::Videos => "videos",
            Self::Models => "models",
            Self::Fusion => "fusion",
            Self::ControlOther => "control_other",
            Self::InferenceOther => "inference_other",
        }
    }
}

/// Closed timeout-phase vocabulary (§5.2 `TimeoutPhase`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[allow(dead_code)] // Closed wire vocabulary; this SDK has no whole-call deadline.
pub(crate) enum TimeoutPhase {
    /// No deadline was involved.
    None,
    /// Connecting.
    Connect,
    /// Waiting for the response headers or the first event.
    FirstByte,
    /// Waiting for the next event on an open stream.
    Idle,
    /// A whole-call deadline (never produced here).
    Total,
}

impl TimeoutPhase {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Connect => "connect",
            Self::FirstByte => "first_byte",
            Self::Idle => "idle",
            Self::Total => "total",
        }
    }
}

/// Closed HTTP status class vocabulary (§5.2 `HttpStatusClass`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(crate) enum HttpStatusClass {
    /// No response, or a status outside 2xx/4xx/5xx.
    None,
    /// 200–299.
    Success,
    /// 400–499 other than 429.
    ClientError,
    /// Exactly 429.
    RateLimited,
    /// 500–599.
    ServerError,
}

impl HttpStatusClass {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Success => "2xx",
            Self::ClientError => "4xx",
            Self::RateLimited => "429",
            Self::ServerError => "5xx",
        }
    }
}

/// Closed latency-bucket vocabulary (§5.2 `LatencyBucket`); upper bounds in
/// milliseconds, exclusive.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(crate) enum LatencyBucket {
    Lt100,
    Lt200,
    Lt400,
    Lt800,
    Lt1600,
    Lt3200,
    Lt6400,
    Lt12800,
    Lt25600,
    Lt51200,
    Lt102400,
    Ge102400,
}

impl LatencyBucket {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Lt100 => "lt100",
            Self::Lt200 => "lt200",
            Self::Lt400 => "lt400",
            Self::Lt800 => "lt800",
            Self::Lt1600 => "lt1600",
            Self::Lt3200 => "lt3200",
            Self::Lt6400 => "lt6400",
            Self::Lt12800 => "lt12800",
            Self::Lt25600 => "lt25600",
            Self::Lt51200 => "lt51200",
            Self::Lt102400 => "lt102400",
            Self::Ge102400 => "ge102400",
        }
    }
}

/// Where an error response said it came from (§5.2 `ErrorSource`), read off
/// the error body's `source` field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ErrorSource {
    Router,
    Provider,
    Unknown,
}

impl ErrorSource {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Router => "router",
            Self::Provider => "provider",
            Self::Unknown => "unknown",
        }
    }

    /// Parses the error body's `source` field; anything else is `None`.
    pub(crate) fn parse(value: Option<&str>) -> Option<Self> {
        match value? {
            "router" => Some(Self::Router),
            "provider" => Some(Self::Provider),
            "unknown" => Some(Self::Unknown),
            _ => None,
        }
    }
}

/// The `x-should-retry` verdict as observed on a response (§5.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ShouldRetry {
    True,
    False,
    Absent,
}

/// Counter level (§5.4 `level`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(crate) enum Level {
    /// One row per attempt made.
    Attempt,
    /// One row per logical call, keyed on its final facts.
    Request,
}

impl Level {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Attempt => "attempt",
            Self::Request => "request",
        }
    }
}

fn constant_host(constant: &str) -> Option<String> {
    let url = Url::parse(constant).ok()?;
    url.host_str().map(str::to_ascii_lowercase)
}

fn trustedrouter_domain(host: &str) -> bool {
    host == "trustedrouter.com" || host.ends_with(".trustedrouter.com")
}

/// Maps a resolved attempt URL to the closed §5.2 host vocabulary.
pub(crate) fn host_enum(url: &Url) -> Host {
    let Some(host) = url.host_str() else {
        return Host::Custom;
    };
    let host = host.to_ascii_lowercase();
    if Some(&host) == constant_host(DEFAULT_API_BASE_URL).as_ref() {
        return Host::Apex;
    }
    if Some(&host) == constant_host(ALIAS_API_BASE_URLS[0]).as_ref() {
        return Host::Ally;
    }
    if Some(&host) == constant_host(ALIAS_API_BASE_URLS[1]).as_ref() {
        return Host::Uptime;
    }
    for (region_host, region) in REGION_HOSTS {
        if host == region_host {
            return region;
        }
    }
    if url.scheme() == "https" && trustedrouter_domain(&host) {
        return Host::Control;
    }
    Host::Custom
}

/// String-typed [`host_enum`] for configuration-time checks; anything that
/// does not parse as a URL is `Custom`, mirroring the Python SDK.
pub(crate) fn host_enum_str(base_url: &str) -> Host {
    match Url::parse(base_url) {
        Ok(url) => host_enum(&url),
        Err(_) => Host::Custom,
    }
}

/// True when `url` is the HTTPS control plane (`trustedrouter.com` or a
/// subdomain) — the §6.3 default-on gate for the control half.
fn control_host(url: &str) -> bool {
    let Ok(parsed) = Url::parse(url) else {
        return false;
    };
    parsed.scheme() == "https"
        && parsed
            .host_str()
            .is_some_and(|host| trustedrouter_domain(&host.to_ascii_lowercase()))
}

/// Resolves the §6.3 opt-out precedence without reading process state
/// implicitly: explicit builder option, then `TRUSTEDROUTER_TELEMETRY`, then
/// `DO_NOT_TRACK`, then default on iff the inference base is a known
/// `TrustedRouter` host AND the control base is the HTTPS `trustedrouter.com`
/// plane. Mirrors `trusted_router._telemetry.resolve_telemetry_enabled`.
pub(crate) fn resolve_telemetry_enabled(
    explicit: Option<bool>,
    base_url: &str,
    control_base_url: &str,
    env: &dyn Fn(&str) -> Option<String>,
) -> bool {
    if let Some(explicit) = explicit {
        return explicit;
    }
    let configured = env("TRUSTEDROUTER_TELEMETRY")
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    match configured.as_str() {
        "0" | "false" | "off" | "no" => return false,
        "1" | "true" | "on" | "yes" => return true,
        _ => {}
    }
    if env("DO_NOT_TRACK").unwrap_or_default().trim() == "1" {
        return false;
    }
    host_enum_str(base_url) != Host::Custom && control_host(control_base_url)
}

/// True for inference-plane paths the header channel covers. `/attestation`
/// is excluded for cross-SDK parity: the Python SDK fetches attestation
/// outside its retry engine, so no SDK sends `x-tr-client` on it. The
/// authorize route is excluded as a hard §2.2 MUST — client context is never
/// sent on `/internal/gateway/authorize`, whose idempotency fingerprint
/// hashes every body key and whose header surface must stay attempt-stable.
///
/// The engine passes the RESOLVED candidate path, not the caller's raw
/// string, so dot segments (`/x/../attestation`) cannot dodge either
/// exclusion — and the comparison runs on [`semantic_route`], so no
/// alternate SPELLING of an excluded route can dodge one either. A §2.2 MUST
/// has to fail closed: matching the literal route text alone let
/// `/internal/gateway/%61uthorize` through, because `Url::path` keeps percent
/// escapes while the gateway's request parser decodes them before routing.
pub(crate) fn tracked_inference_path(path: &str) -> bool {
    let clean = path.split(['?', '#']).next().unwrap_or(path);
    let route = semantic_route(clean);
    let excluded = |name: &str| route.ends_with(name) || route.contains(&format!("{name}/"));
    !excluded("/attestation") && !excluded("/internal/gateway/authorize")
}

/// Classifies a transport failure into the §5.2 vocabulary while the typed
/// [`reqwest::Error`] still exists — one call later,
/// `transport::policy::map_reqwest_error` flattens it to a message string and
/// the class is unrecoverable.
pub(crate) fn classify_transport_error(error: &reqwest::Error) -> ErrorClass {
    let connect = error.is_connect();
    if error.is_timeout() {
        return if connect {
            ErrorClass::ConnectTimeout
        } else {
            ErrorClass::ReadTimeout
        };
    }
    classify_chain(error, connect)
}

/// Walks the `std::error::Error::source` chain in two passes.
///
/// Pass one inspects typed [`std::io::Error`] kinds across the WHOLE chain —
/// a typed cause always wins. Pass two falls back to bounded message probes,
/// but only on links BELOW the outermost error: the top-level Display is
/// where caller-controlled text (reqwest embeds the request URL) can appear,
/// and a URL that happens to contain `tls` or `proxy` must never decide a
/// classification. The probes exist because two failure shapes offer no type
/// to downcast to: hyper-util labels DNS failures with a message-only
/// wrapper, and rustls failures cross the boundary as opaque strings. Proxy
/// provenance is best-effort only — a tunnel failure that surfaces a typed
/// socket error classifies as that socket error.
pub(crate) fn classify_chain(top: &(dyn std::error::Error + 'static), connect: bool) -> ErrorClass {
    const MAX_DEPTH: usize = 8;
    let mut current: Option<&(dyn std::error::Error + 'static)> = Some(top);
    let mut saw_io = false;
    let mut depth = 0;
    while let Some(error) = current {
        if depth >= MAX_DEPTH {
            break;
        }
        if let Some(io) = error.downcast_ref::<std::io::Error>() {
            match io.kind() {
                std::io::ErrorKind::ConnectionRefused => return ErrorClass::ConnectRefused,
                std::io::ErrorKind::ConnectionReset
                | std::io::ErrorKind::ConnectionAborted
                | std::io::ErrorKind::BrokenPipe => return ErrorClass::Reset,
                std::io::ErrorKind::TimedOut => {
                    return if connect {
                        ErrorClass::ConnectTimeout
                    } else {
                        ErrorClass::ReadTimeout
                    };
                }
                std::io::ErrorKind::InvalidData if connect => return ErrorClass::Tls,
                _ => saw_io = true,
            }
        }
        current = error.source();
        depth += 1;
    }
    let mut current = top.source();
    let mut depth = 0;
    while let Some(error) = current {
        if depth >= MAX_DEPTH {
            break;
        }
        let text = error.to_string().to_ascii_lowercase();
        if text.contains("dns error") || text.contains("failed to lookup address") {
            return ErrorClass::Dns;
        }
        // "corrupt message" is rustls's wording for a non-TLS or damaged
        // record ("received corrupt message of type InvalidContentType"),
        // which reaches here as an opaque io::Error of kind Other.
        if text.contains("certificate")
            || text.contains("handshake")
            || text.contains("tls")
            || text.contains("corrupt message")
        {
            return ErrorClass::Tls;
        }
        if text.contains("proxy") {
            return ErrorClass::ProxyError;
        }
        if text.contains("connection closed before") || text.contains("parse") {
            return ErrorClass::ProtocolError;
        }
        current = error.source();
        depth += 1;
    }
    if connect {
        ErrorClass::ConnectError
    } else if saw_io {
        ErrorClass::IoError
    } else {
        ErrorClass::Unknown
    }
}

/// Maps the caller's logical route to the closed §5.2 endpoint vocabulary.
/// Mirrors `trusted_router._telemetry.endpoint_enum`: exact matches for the
/// four prompt routes, prefix matches for the grouped ones, everything else
/// `inference_other`. The route is folded through
/// [`semantic_request_route`] first, so dot segments, percent escapes,
/// case, and repeated separators cannot produce a second spelling.
pub(crate) fn endpoint_enum(path: &str) -> Endpoint {
    let clean = path.split(['?', '#']).next().unwrap_or(path);
    let route = semantic_request_route(clean);
    match route.as_str() {
        "/chat/completions" => return Endpoint::ChatCompletions,
        "/messages" => return Endpoint::Messages,
        "/responses" => return Endpoint::Responses,
        "/embeddings" => return Endpoint::Embeddings,
        _ => {}
    }
    for (prefix, endpoint) in [
        ("/images", Endpoint::Images),
        ("/videos", Endpoint::Videos),
        ("/models", Endpoint::Models),
        ("/fusion", Endpoint::Fusion),
    ] {
        if route == prefix || route.starts_with(&format!("{prefix}/")) {
            return endpoint;
        }
    }
    Endpoint::InferenceOther
}

/// Buckets a millisecond latency (§5.2 `LatencyBucket`, upper bound
/// exclusive).
pub(crate) fn latency_bucket(ms: u64) -> LatencyBucket {
    const BOUNDS: [(u64, LatencyBucket); 11] = [
        (100, LatencyBucket::Lt100),
        (200, LatencyBucket::Lt200),
        (400, LatencyBucket::Lt400),
        (800, LatencyBucket::Lt800),
        (1600, LatencyBucket::Lt1600),
        (3200, LatencyBucket::Lt3200),
        (6400, LatencyBucket::Lt6400),
        (12800, LatencyBucket::Lt12800),
        (25600, LatencyBucket::Lt25600),
        (51200, LatencyBucket::Lt51200),
        (102_400, LatencyBucket::Lt102400),
    ];
    for (upper, bucket) in BOUNDS {
        if ms < upper {
            return bucket;
        }
    }
    LatencyBucket::Ge102400
}

/// Classifies an HTTP status (§5.2 `HttpStatusClass`).
pub(crate) fn status_class(status: Option<u16>) -> HttpStatusClass {
    match status {
        Some(200..=299) => HttpStatusClass::Success,
        Some(429) => HttpStatusClass::RateLimited,
        Some(400..=499) => HttpStatusClass::ClientError,
        Some(500..=599) => HttpStatusClass::ServerError,
        _ => HttpStatusClass::None,
    }
}

/// §5.4 `timeout_floor_met`: the configured deadline for the phase that
/// fired was at or above the methodology floor (connect ≥ 10 s, first byte
/// ≥ 60 s, idle ≥ 30 s), so the timeout counts against `TrustedRouter`.
pub(crate) fn timeout_floor_met(phase: TimeoutPhase, configured_ms: Option<u64>) -> bool {
    let Some(configured_ms) = configured_ms else {
        return false;
    };
    let floor = match phase {
        TimeoutPhase::Connect => 10_000,
        TimeoutPhase::FirstByte => 60_000,
        TimeoutPhase::Idle => 30_000,
        TimeoutPhase::None | TimeoutPhase::Total => return false,
    };
    configured_ms >= floor
}

/// The phase a transport-error class implies before any body was read,
/// mirroring the phase half of `trusted_router._telemetry.classify_transport_error`.
fn phase_for_class(class: ErrorClass) -> TimeoutPhase {
    match class {
        ErrorClass::ConnectTimeout => TimeoutPhase::Connect,
        ErrorClass::ReadTimeout | ErrorClass::WriteTimeout => TimeoutPhase::FirstByte,
        _ => TimeoutPhase::None,
    }
}

/// True when `model` fits the §5.3 `ModelId` grammar
/// `^[A-Za-z0-9._:/~@-]{1,128}$`.
pub(crate) fn valid_model(model: &str) -> bool {
    !model.is_empty()
        && model.len() <= 128
        && model
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:/~@-".contains(&byte))
}

/// True when `value` is an enclave request id, `^rlog_[0-9a-f]{32}$` (§3.3).
pub(crate) fn valid_request_id(value: &str) -> bool {
    value.strip_prefix("rlog_").is_some_and(|hex| {
        hex.len() == 32
            && hex
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    })
}

/// One attempt's facts, as the retry loop observed them (§5.3
/// `ClientAttempt`, plus the timeout phase the counters need).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AttemptRecord {
    pub(crate) index: usize,
    pub(crate) host: Host,
    pub(crate) outcome: AttemptOutcome,
    pub(crate) http_status: Option<u16>,
    pub(crate) error_class: Option<ErrorClass>,
    pub(crate) error_source: Option<ErrorSource>,
    pub(crate) should_retry: ShouldRetry,
    pub(crate) retry_after_ms: Option<u64>,
    pub(crate) elapsed_ms: u64,
    pub(crate) ttfb_ms: Option<u64>,
    pub(crate) request_id: Option<String>,
    pub(crate) moved: bool,
    /// The §5.2 timeout phase this attempt's failure fell in (`none` unless
    /// a deadline fired). Not a wire field of the attempt; it feeds the
    /// event's `timeout_phase` and the attempt-level counter key.
    pub(crate) phase: TimeoutPhase,
}

/// One logical call's facts as handed to the sink by
/// [`RequestRecorder::finish`] (§5.3 `ClientRequestEvent` minus the sampling
/// and age fields, which the reporter adds).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RequestEvent {
    pub(crate) endpoint: Endpoint,
    pub(crate) method: Method,
    pub(crate) streaming: bool,
    pub(crate) provider_pinned: bool,
    pub(crate) model: Option<String>,
    pub(crate) attempts: Vec<AttemptRecord>,
    pub(crate) final_outcome: FinalOutcome,
    pub(crate) final_http_status: Option<u16>,
    pub(crate) total_ms: u64,
    pub(crate) ttft_ms: Option<u64>,
    pub(crate) failover_used: bool,
    pub(crate) timeout_phase: TimeoutPhase,
    pub(crate) configured_timeout_ms: Option<u64>,
}

/// The exact ten-field counter key (§5.4): everything but the counts and
/// histograms. `model` is deliberately not part of it.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(crate) struct CounterKey {
    pub(crate) level: Level,
    pub(crate) endpoint: Endpoint,
    pub(crate) streaming: bool,
    pub(crate) host: Host,
    pub(crate) outcome: AttemptOutcome,
    pub(crate) error_class: Option<ErrorClass>,
    pub(crate) http_status_class: HttpStatusClass,
    pub(crate) timeout_phase: TimeoutPhase,
    pub(crate) timeout_floor_met: bool,
    pub(crate) provider_pinned: bool,
}

/// The counts and histograms of one counter row, also used as the increment
/// a single call contributes.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct CounterRow {
    pub(crate) requests: u64,
    pub(crate) attempts: u64,
    pub(crate) failover_used: u64,
    pub(crate) first_attempt_success: u64,
    pub(crate) total_ms_hist: BTreeMap<LatencyBucket, u64>,
    pub(crate) first_event_ms_hist: BTreeMap<LatencyBucket, u64>,
}

/// Where finished calls go: the beacon reporter in production, an
/// in-memory recorder in tests. Must never panic — it runs on the request
/// path's tail and inside `Drop`.
pub(crate) trait TelemetrySink: std::fmt::Debug + Send + Sync {
    fn on_request(&self, event: RequestEvent, counters: Vec<(CounterKey, CounterRow)>);
}

/// A sink that discards everything: the header channel without a beacon.
#[derive(Debug)]
pub(crate) struct NullSink;

impl TelemetrySink for NullSink {
    fn on_request(&self, _event: RequestEvent, _counters: Vec<(CounterKey, CounterRow)>) {}
}

/// Everything a recorder knows before the first attempt.
pub(crate) struct RecorderSpec {
    pub(crate) sink: Arc<dyn TelemetrySink>,
    pub(crate) endpoint: Endpoint,
    pub(crate) method: Method,
    pub(crate) streaming: bool,
    pub(crate) provider_pinned: bool,
    pub(crate) model: Option<String>,
    /// The per-attempt deadline (connect + headers, and the body/idle read);
    /// `None` or zero means no SDK deadline.
    pub(crate) configured_timeout: Option<Duration>,
}

fn duration_ms(start: Instant, end: Instant) -> u64 {
    let millis = end.saturating_duration_since(start).as_millis();
    u64::try_from(millis.min(u128::from(MAX_DURATION_MS))).unwrap_or(MAX_DURATION_MS)
}

fn valid_value(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 24
        && value
            .bytes()
            .all(|byte| matches!(byte, b'a'..=b'z' | b'0'..=b'9' | b'_'))
}

/// Joins `key=value` pairs into the final header, enforcing the §3.2 bounds:
/// every value anchored to `[a-z0-9_]{1,24}` and the whole header ≤ 160
/// bytes. Bounded by construction already (closed enums, clamped millisecond
/// counts) — but telemetry may never fail a request, so an out-of-grammar
/// value returns `None` and the attempt simply carries no header.
fn finalize_header(values: &[(&'static str, String)]) -> Option<String> {
    if !values.iter().all(|(_, value)| valid_value(value)) {
        return None;
    }
    let header = values
        .iter()
        .map(|(key, value)| format!("{key}={value}"))
        .collect::<Vec<_>>()
        .join(";");
    if header.len() > MAX_HEADER_BYTES {
        return None;
    }
    Some(header)
}

fn header_str<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name).and_then(|value| value.to_str().ok())
}

/// Records one logical inference call across the retry loop: derives the
/// per-attempt `x-tr-client` value (§3.2) and, at [`Self::finish`], the
/// sampled event and exact counter increments (§5.3, §5.4). A port of
/// `trusted_router._telemetry.RequestRecorder`.
///
/// Dropping an unfinished recorder records the in-flight attempt as
/// `aborted` and finishes — the Rust spelling of the Python SDK's
/// `KeyboardInterrupt`/`GeneratorExit` arms, since a cancelled future or a
/// dropped stream is the only way a call ends without reaching a terminal
/// arm of the engine.
#[derive(Debug)]
#[allow(clippy::struct_excessive_bools)] // Independent contract facts, not one state machine.
pub(crate) struct RequestRecorder {
    sink: Arc<dyn TelemetrySink>,
    endpoint: Endpoint,
    method: Method,
    /// Only `GET`/`POST` calls are recorded (the schema module's closed
    /// method vocabulary); other methods still carry the header.
    recordable: bool,
    streaming: bool,
    provider_pinned: bool,
    model: Option<String>,
    configured_timeout: Option<Duration>,
    attempts: Vec<AttemptRecord>,
    failover_used: bool,
    ttft_ms: Option<u64>,
    first_started: Option<Instant>,
    attempt_started: Option<Instant>,
    current_host: Option<Host>,
    current_index: Option<usize>,
    finished: bool,
}

impl RequestRecorder {
    pub(crate) fn new(spec: RecorderSpec) -> Self {
        let recordable = matches!(spec.method, Method::GET | Method::POST);
        Self {
            sink: spec.sink,
            endpoint: spec.endpoint,
            method: spec.method,
            recordable,
            streaming: spec.streaming,
            provider_pinned: spec.provider_pinned,
            model: spec.model.filter(|model| valid_model(model)),
            configured_timeout: spec.configured_timeout.filter(|value| !value.is_zero()),
            attempts: Vec::new(),
            failover_used: false,
            ttft_ms: None,
            first_started: None,
            attempt_started: None,
            current_host: None,
            current_index: None,
            finished: false,
        }
    }

    /// Marks the start of the next attempt against `url`. Must precede
    /// [`Self::header_value`] for that attempt.
    pub(crate) fn begin_attempt(&mut self, url: &Url) {
        let started = Instant::now();
        if self.first_started.is_none() {
            self.first_started = Some(started);
        }
        self.attempt_started = Some(started);
        self.current_host = Some(host_enum(url));
        self.current_index = Some(self.attempts.len());
    }

    /// The `x-tr-client` value for the current attempt, in the exact §3.2 key
    /// order `v,a[,po,pc,ph,pm,sm],s[,fo]`, or `None` when the attempt targets
    /// a custom host (a self-hosted gateway is not `TrustedRouter`'s to
    /// measure) or a bound would be violated. §3.2 bounds the attempt index
    /// to `0..99`: past it the header is simply not sent — the enclave would
    /// drop an `a=100` header whole anyway.
    pub(crate) fn header_value(&self) -> Option<String> {
        let index = self.current_index?;
        if index > 99 || self.current_host? == Host::Custom {
            return None;
        }
        let mut values: Vec<(&'static str, String)> =
            vec![("v", "1".to_owned()), ("a", index.to_string())];
        if index > 0 {
            let previous = self.attempts.last()?;
            let attempt_started = self.attempt_started?;
            let first_started = self.first_started.unwrap_or(attempt_started);
            // §3.2's po vocabulary is none|http_error|transport_error|
            // timeout|stream_broken — there is no "ok" or "aborted". A forced
            // retry after a sub-400 response (x-should-retry: true on a 3xx)
            // therefore degrades to po=none;pc=none rather than emitting a
            // value the enclave would drop the whole header for.
            let (po, pc) = match previous.outcome {
                AttemptOutcome::Ok | AttemptOutcome::Aborted => ("none", "none"),
                outcome => (
                    outcome.as_str(),
                    previous.error_class.map_or("none", ErrorClass::as_str),
                ),
            };
            values.push(("po", po.to_owned()));
            values.push(("pc", pc.to_owned()));
            values.push(("ph", previous.host.as_str().to_owned()));
            values.push(("pm", previous.elapsed_ms.to_string()));
            values.push((
                "sm",
                duration_ms(first_started, attempt_started).to_string(),
            ));
        }
        values.push(("s", if self.streaming { "1" } else { "0" }.to_owned()));
        if index > 0 {
            values.push(("fo", if self.failover_used { "1" } else { "0" }.to_owned()));
        }
        finalize_header(&values)
    }

    fn store_attempt(&mut self, record: AttemptRecord) {
        if let Some(existing) = self.attempts.get_mut(record.index) {
            *existing = record;
        } else {
            self.attempts.push(record);
        }
    }

    /// The attempt in flight: its start, host, and index, or `None` before
    /// the first [`Self::begin_attempt`].
    fn in_flight(&self) -> Option<(Instant, Host, usize)> {
        Some((
            self.attempt_started?,
            self.current_host?,
            self.current_index?,
        ))
    }

    /// Records an attempt that produced an HTTP response. `error_source` is
    /// the error body's `source` field for a failure response, when the
    /// engine drained one.
    pub(crate) fn on_response(
        &mut self,
        status: u16,
        headers: &HeaderMap,
        error_source: Option<ErrorSource>,
    ) {
        let Some((started, host, index)) = self.in_flight() else {
            return;
        };
        let elapsed_ms = duration_ms(started, Instant::now());
        let should_retry = match header_str(headers, "x-should-retry")
            .map(|value| value.trim().to_ascii_lowercase())
            .as_deref()
        {
            Some("true") => ShouldRetry::True,
            Some("false") => ShouldRetry::False,
            _ => ShouldRetry::Absent,
        };
        let retry_after_ms = parse_retry_after(headers).map(|delay| {
            u64::try_from(delay.as_millis().min(u128::from(MAX_DURATION_MS)))
                .unwrap_or(MAX_DURATION_MS)
        });
        let request_id = header_str(headers, "x-request-id")
            .filter(|value| valid_request_id(value))
            .map(str::to_owned);
        self.store_attempt(AttemptRecord {
            index,
            host,
            outcome: if status < 400 {
                AttemptOutcome::Ok
            } else {
                AttemptOutcome::HttpError
            },
            http_status: Some(status),
            error_class: None,
            error_source,
            should_retry,
            retry_after_ms,
            elapsed_ms,
            ttfb_ms: Some(elapsed_ms),
            request_id,
            moved: false,
            phase: TimeoutPhase::None,
        });
    }

    /// Finishes accounting for a buffered error response after its body was
    /// drained. Header-observed facts (especially `ttfb_ms`) stay anchored at
    /// header receipt while `elapsed_ms` covers the complete attempt and the
    /// bounded error source is attached once the JSON body is available.
    pub(crate) fn on_response_body_complete(&mut self, error_source: Option<ErrorSource>) {
        let Some((started, _, index)) = self.in_flight() else {
            return;
        };
        if let Some(record) = self.attempts.get_mut(index) {
            record.elapsed_ms = duration_ms(started, Instant::now());
            record.error_source = error_source;
        }
    }

    /// Records a transport-level failure of the attempt in flight. The class
    /// must be captured while the typed transport error is still alive (see
    /// [`classify_transport_error`]). `response_opened` keeps the status and
    /// ids of an already-recorded response; `body_started` turns a failure
    /// into `stream_broken` (or an idle `stream_stalled` timeout) — the
    /// mid-body outcomes of §5.2. Mirrors the Python recorder's
    /// `on_transport_error(exc, response_opened=, body_started=)`.
    pub(crate) fn on_transport_error(
        &mut self,
        class: ErrorClass,
        timed_out: bool,
        response_opened: bool,
        body_started: bool,
    ) {
        let Some((started, host, index)) = self.in_flight() else {
            return;
        };
        let mut class = class;
        let mut phase = phase_for_class(class);
        let outcome = if timed_out {
            if body_started {
                phase = TimeoutPhase::Idle;
                if class == ErrorClass::ReadTimeout {
                    class = ErrorClass::StreamStalled;
                }
            }
            AttemptOutcome::Timeout
        } else if body_started {
            AttemptOutcome::StreamBroken
        } else {
            AttemptOutcome::TransportError
        };
        let previous = self.attempts.get(index).cloned();
        let opened = previous.as_ref().filter(|_| response_opened);
        self.store_attempt(AttemptRecord {
            index,
            host,
            outcome,
            http_status: opened.and_then(|record| record.http_status),
            error_class: Some(class),
            error_source: previous.as_ref().and_then(|record| record.error_source),
            should_retry: previous
                .as_ref()
                .map_or(ShouldRetry::Absent, |record| record.should_retry),
            retry_after_ms: previous.as_ref().and_then(|record| record.retry_after_ms),
            elapsed_ms: duration_ms(started, Instant::now()),
            ttfb_ms: opened.and_then(|record| record.ttfb_ms),
            request_id: previous.and_then(|record| record.request_id),
            moved: false,
            phase,
        });
    }

    /// Records that the candidate cursor actually advanced after the latest
    /// attempt — the §3.2 `fo` bit. Call only when the index moved; a
    /// saturated advance at the end of the list is not a failover.
    pub(crate) fn on_moved(&mut self) {
        if let Some(last) = self.attempts.last_mut() {
            last.moved = true;
            self.failover_used = true;
        }
    }

    /// Records the first decoded SSE event: `ttft_ms` is measured from the
    /// FIRST attempt's start, so retries before the stream opened count.
    pub(crate) fn on_first_event(&mut self) {
        if self.ttft_ms.is_none() {
            if let Some(first_started) = self.first_started {
                self.ttft_ms = Some(duration_ms(first_started, Instant::now()));
            }
        }
    }

    /// Records that the caller abandoned the call mid-attempt: the attempt in
    /// flight becomes `aborted`, keeping whatever facts it already had.
    pub(crate) fn on_aborted(&mut self) {
        let Some((started, host, index)) = self.in_flight() else {
            return;
        };
        let previous = self.attempts.get(index).cloned();
        let record = AttemptRecord {
            index,
            host,
            outcome: AttemptOutcome::Aborted,
            http_status: previous.as_ref().and_then(|record| record.http_status),
            error_class: previous.as_ref().and_then(|record| record.error_class),
            error_source: previous.as_ref().and_then(|record| record.error_source),
            should_retry: previous
                .as_ref()
                .map_or(ShouldRetry::Absent, |record| record.should_retry),
            retry_after_ms: previous.as_ref().and_then(|record| record.retry_after_ms),
            elapsed_ms: duration_ms(started, Instant::now()),
            ttfb_ms: previous.as_ref().and_then(|record| record.ttfb_ms),
            request_id: previous
                .as_ref()
                .and_then(|record| record.request_id.clone()),
            moved: previous.as_ref().is_some_and(|record| record.moved),
            phase: previous.map_or(TimeoutPhase::None, |record| record.phase),
        };
        self.store_attempt(record);
    }

    /// `configured_timeout_ms` for a phase (§5.3): the per-attempt deadline
    /// when a connect, first-byte, or idle deadline is what fired; `None`
    /// otherwise. The Python SDK reads the phase's deadline off its
    /// `httpx.Timeout`; this SDK has one deadline covering all three phases.
    fn configured_timeout_ms(&self, phase: TimeoutPhase) -> Option<u64> {
        match phase {
            TimeoutPhase::Connect | TimeoutPhase::FirstByte | TimeoutPhase::Idle => {
                self.configured_timeout.map(|deadline| {
                    u64::try_from(deadline.as_millis().clamp(1, u128::from(MAX_DURATION_MS)))
                        .unwrap_or(MAX_DURATION_MS)
                })
            }
            TimeoutPhase::None | TimeoutPhase::Total => None,
        }
    }

    /// Derives the event and the exact counter increments and hands them to
    /// the sink, once. `exhausted` is the engine's verdict that the final
    /// attempt was retryable but the retry ceiling stopped it. Idempotent:
    /// a second call (or the `Drop` after an explicit finish) is a no-op.
    pub(crate) fn finish(&mut self, exhausted: bool) {
        if self.finished {
            return;
        }
        self.finished = true;
        let (Some(first_started), Some(last)) = (self.first_started, self.attempts.last()) else {
            return;
        };
        if !self.recordable {
            return;
        }
        let last = last.clone();
        let final_outcome =
            if exhausted && self.attempts.len() > 1 && last.outcome != AttemptOutcome::Ok {
                FinalOutcome::Exhausted
            } else {
                FinalOutcome::Outcome(last.outcome)
            };
        let timeout_phase = last.phase;
        let configured_timeout_ms = self.configured_timeout_ms(timeout_phase);
        let total_ms = duration_ms(first_started, Instant::now());
        let event = RequestEvent {
            endpoint: self.endpoint,
            method: self.method.clone(),
            streaming: self.streaming,
            provider_pinned: self.provider_pinned,
            model: self.model.clone(),
            attempts: self.attempts.clone(),
            final_outcome,
            final_http_status: last.http_status,
            total_ms,
            ttft_ms: self.ttft_ms,
            failover_used: self.failover_used,
            timeout_phase,
            configured_timeout_ms,
        };
        let request_key = CounterKey {
            level: Level::Request,
            endpoint: self.endpoint,
            streaming: self.streaming,
            host: last.host,
            // The counter outcome is the final attempt's own outcome, never
            // `exhausted` (the schema module types counters on `Outcome`).
            outcome: last.outcome,
            error_class: self.attempts.iter().find_map(|attempt| attempt.error_class),
            http_status_class: status_class(last.http_status),
            timeout_phase,
            timeout_floor_met: timeout_floor_met(timeout_phase, configured_timeout_ms),
            provider_pinned: self.provider_pinned,
        };
        let mut request_row = CounterRow {
            requests: 1,
            attempts: self.attempts.len() as u64,
            failover_used: u64::from(self.failover_used),
            first_attempt_success: u64::from(
                self.attempts
                    .first()
                    .is_some_and(|attempt| attempt.outcome == AttemptOutcome::Ok),
            ),
            total_ms_hist: BTreeMap::from([(latency_bucket(total_ms), 1)]),
            first_event_ms_hist: BTreeMap::new(),
        };
        if let Some(first_event_ms) = self.ttft_ms.or(last.ttfb_ms) {
            request_row
                .first_event_ms_hist
                .insert(latency_bucket(first_event_ms), 1);
        }
        let mut counters = vec![(request_key, request_row)];
        for attempt in &self.attempts {
            let attempt_timeout_ms = self.configured_timeout_ms(attempt.phase);
            counters.push((
                CounterKey {
                    level: Level::Attempt,
                    endpoint: self.endpoint,
                    streaming: self.streaming,
                    host: attempt.host,
                    outcome: attempt.outcome,
                    error_class: attempt.error_class,
                    http_status_class: status_class(attempt.http_status),
                    timeout_phase: attempt.phase,
                    timeout_floor_met: timeout_floor_met(attempt.phase, attempt_timeout_ms),
                    provider_pinned: self.provider_pinned,
                },
                CounterRow {
                    requests: 1,
                    attempts: 1,
                    failover_used: u64::from(attempt.moved),
                    first_attempt_success: 0,
                    total_ms_hist: BTreeMap::new(),
                    first_event_ms_hist: BTreeMap::new(),
                },
            ));
        }
        self.sink.on_request(event, counters);
    }
}

impl Drop for RequestRecorder {
    fn drop(&mut self) {
        if !self.finished {
            self.on_aborted();
            self.finish(false);
        }
    }
}

/// The recorder of an OPEN stream, shared between the SSE wire layer (first
/// event, wire failures, end of stream) and the protocol validators that
/// recognise a terminal frame. Dropping the last handle before completion
/// records `aborted` through [`RequestRecorder`]'s own `Drop`.
#[derive(Debug, Clone)]
pub(crate) struct StreamRecorder {
    state: Arc<Mutex<StreamState>>,
}

#[derive(Debug)]
struct StreamState {
    recorder: RequestRecorder,
    body_started: bool,
}

impl StreamRecorder {
    pub(crate) fn new(recorder: RequestRecorder) -> Self {
        Self {
            state: Arc::new(Mutex::new(StreamState {
                recorder,
                body_started: false,
            })),
        }
    }

    fn with_state(&self, action: impl FnOnce(&mut StreamState)) {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        action(&mut state);
    }

    /// One decoded SSE event reached the caller's layer.
    pub(crate) fn on_event(&self) {
        self.with_state(|state| {
            if !state.body_started {
                state.body_started = true;
                state.recorder.on_first_event();
            }
        });
    }

    /// The body failed under the caller: `stream_broken` or a stalled idle
    /// timeout after the first event, a plain transport failure before it.
    pub(crate) fn on_wire_failure(&self, class: ErrorClass, timed_out: bool) {
        self.with_state(|state| {
            let body_started = state.body_started;
            state
                .recorder
                .on_transport_error(class, timed_out, true, body_started);
            state.recorder.finish(false);
        });
    }

    /// The stream ended: end of body, a terminal protocol frame, or a
    /// protocol error the SDK surfaced (which, as in the Python SDK, leaves
    /// the attempt's outcome as the response that opened it).
    pub(crate) fn on_complete(&self) {
        self.with_state(|state| state.recorder.finish(false));
    }
}

// Golden vectors and vocabulary pins for the header channel (§3.2, §5.2,
// §6.3). These construct recorder state directly — private fields, same
// module — because the contract's example timings (`pm=10012;sm=10530`)
// cannot fall out of a real clock; the wire-driven proofs live in
// `transport::engine::candidate_walk_tests` and `tests/telemetry_header.rs`.
#[cfg(test)]
mod tests {
    use super::{
        classify_chain, classify_transport_error, duration_ms, finalize_header, host_enum,
        host_enum_str, resolve_telemetry_enabled, tracked_inference_path, AttemptOutcome,
        AttemptRecord, CounterKey, Endpoint, ErrorClass, FinalOutcome, Host, HttpStatusClass,
        Level, RecorderSpec, RequestRecorder, ShouldRetry, StreamRecorder, TimeoutPhase,
    };
    use crate::telemetry::reporter::RecordingSink;
    use http::Method;
    use std::collections::HashMap;
    use std::sync::Arc;
    use std::time::{Duration, Instant};
    use url::Url;

    fn apex_url() -> Url {
        Url::parse("https://api.trustedrouter.com/v1/").unwrap()
    }

    /// A recorder for the header vectors: the sink is irrelevant to them.
    fn header_recorder(streaming: bool) -> RequestRecorder {
        RequestRecorder::new(RecorderSpec {
            sink: Arc::new(RecordingSink::default()),
            endpoint: Endpoint::ChatCompletions,
            method: Method::POST,
            streaming,
            provider_pinned: false,
            model: None,
            configured_timeout: Some(Duration::from_secs(120)),
        })
    }

    fn empty_headers() -> reqwest::header::HeaderMap {
        reqwest::header::HeaderMap::new()
    }

    #[test]
    fn finish_derives_the_exact_request_and_attempt_counter_tuples() {
        let sink = Arc::new(RecordingSink::default());
        let mut recorder = RequestRecorder::new(RecorderSpec {
            sink: sink.clone(),
            endpoint: Endpoint::Responses,
            method: Method::POST,
            streaming: false,
            provider_pinned: true,
            model: Some("model/a".to_owned()),
            configured_timeout: Some(Duration::from_secs(60)),
        });
        recorder.begin_attempt(&apex_url());
        let mut retry_headers = empty_headers();
        retry_headers.insert("x-should-retry", "true".parse().unwrap());
        recorder.on_response(503, &retry_headers, None);
        recorder.on_moved();
        recorder.begin_attempt(&Url::parse("https://api.allyrouter.com/v1/responses").unwrap());
        let mut success_headers = empty_headers();
        success_headers.insert(
            "x-request-id",
            "rlog_0123456789abcdef0123456789abcdef".parse().unwrap(),
        );
        recorder.on_response(200, &success_headers, None);
        recorder.finish(false);

        let events = sink.events();
        assert_eq!(events.len(), 1);
        let event = &events[0];
        assert_eq!(event.endpoint, Endpoint::Responses);
        assert_eq!(
            event.final_outcome,
            FinalOutcome::Outcome(AttemptOutcome::Ok)
        );
        assert!(event.failover_used);
        assert_eq!(event.attempts.len(), 2);
        assert!(event.attempts[0].moved);
        assert_eq!(event.attempts[0].should_retry, ShouldRetry::True);
        assert_eq!(event.attempts[1].host, Host::Ally);

        let counters = sink.counters();
        assert_eq!(counters.len(), 1);
        assert_eq!(counters[0].len(), 3);
        assert_eq!(
            counters[0][0].0,
            CounterKey {
                level: Level::Request,
                endpoint: Endpoint::Responses,
                streaming: false,
                host: Host::Ally,
                outcome: AttemptOutcome::Ok,
                error_class: None,
                http_status_class: HttpStatusClass::Success,
                timeout_phase: TimeoutPhase::None,
                timeout_floor_met: false,
                provider_pinned: true,
            }
        );
        assert_eq!(counters[0][0].1.requests, 1);
        assert_eq!(counters[0][0].1.attempts, 2);
        assert_eq!(counters[0][0].1.failover_used, 1);
        assert_eq!(counters[0][0].1.first_attempt_success, 0);
        assert_eq!(counters[0][1].0.level, Level::Attempt);
        assert_eq!(counters[0][1].0.host, Host::Apex);
        assert_eq!(counters[0][1].0.outcome, AttemptOutcome::HttpError);
        assert_eq!(
            counters[0][1].0.http_status_class,
            HttpStatusClass::ServerError
        );
        assert_eq!(counters[0][1].1.failover_used, 1);
        assert_eq!(counters[0][2].0.host, Host::Ally);
        assert_eq!(counters[0][2].0.outcome, AttemptOutcome::Ok);

        let exhausted_sink = Arc::new(RecordingSink::default());
        let mut exhausted = RequestRecorder::new(RecorderSpec {
            sink: exhausted_sink.clone(),
            endpoint: Endpoint::Responses,
            method: Method::POST,
            streaming: false,
            provider_pinned: false,
            model: None,
            configured_timeout: None,
        });
        exhausted.begin_attempt(&apex_url());
        exhausted.on_response(503, &empty_headers(), None);
        exhausted.begin_attempt(&apex_url());
        exhausted.on_response(503, &empty_headers(), None);
        exhausted.finish(true);
        assert_eq!(
            exhausted_sink.events()[0].final_outcome,
            FinalOutcome::Exhausted
        );
        assert_eq!(
            exhausted_sink.counters()[0][0].0.outcome,
            AttemptOutcome::HttpError,
            "counter outcome is the final attempt outcome, never exhausted"
        );
    }

    #[test]
    fn stream_hooks_record_ttft_breakage_and_caller_abort_once() {
        let broken_sink = Arc::new(RecordingSink::default());
        let mut broken = RequestRecorder::new(RecorderSpec {
            sink: broken_sink.clone(),
            endpoint: Endpoint::ChatCompletions,
            method: Method::POST,
            streaming: true,
            provider_pinned: false,
            model: None,
            configured_timeout: Some(Duration::from_secs(30)),
        });
        broken.begin_attempt(&apex_url());
        broken.on_response(200, &empty_headers(), None);
        let broken = StreamRecorder::new(broken);
        broken.on_event();
        broken.on_wire_failure(ErrorClass::Reset, false);
        broken.on_complete();
        drop(broken);
        let events = broken_sink.events();
        assert_eq!(events.len(), 1);
        assert_eq!(
            events[0].final_outcome,
            FinalOutcome::Outcome(AttemptOutcome::StreamBroken)
        );
        assert!(events[0].ttft_ms.is_some());

        let aborted_sink = Arc::new(RecordingSink::default());
        let mut aborted = RequestRecorder::new(RecorderSpec {
            sink: aborted_sink.clone(),
            endpoint: Endpoint::Responses,
            method: Method::POST,
            streaming: true,
            provider_pinned: false,
            model: None,
            configured_timeout: None,
        });
        aborted.begin_attempt(&apex_url());
        aborted.on_response(200, &empty_headers(), None);
        drop(StreamRecorder::new(aborted));
        let events = aborted_sink.events();
        assert_eq!(events.len(), 1);
        assert_eq!(
            events[0].final_outcome,
            FinalOutcome::Outcome(AttemptOutcome::Aborted)
        );
    }

    #[test]
    fn methods_outside_get_and_post_never_emit_events_or_counters() {
        let sink = Arc::new(RecordingSink::default());
        let mut recorder = RequestRecorder::new(RecorderSpec {
            sink: sink.clone(),
            endpoint: Endpoint::InferenceOther,
            method: Method::PUT,
            streaming: false,
            provider_pinned: false,
            model: None,
            configured_timeout: None,
        });
        recorder.begin_attempt(&apex_url());
        assert_eq!(recorder.header_value().as_deref(), Some("v=1;a=0;s=0"));
        recorder.on_response(200, &empty_headers(), None);
        recorder.finish(false);
        assert!(sink.events().is_empty());
        assert!(sink.counters().is_empty());
    }

    #[test]
    fn attempt_zero_headers_match_the_contract_examples_byte_for_byte() {
        let mut streaming = header_recorder(true);
        streaming.begin_attempt(&apex_url());
        assert_eq!(streaming.header_value().as_deref(), Some("v=1;a=0;s=1"));

        let mut buffered = header_recorder(false);
        buffered.begin_attempt(&apex_url());
        assert_eq!(buffered.header_value().as_deref(), Some("v=1;a=0;s=0"));
    }

    #[test]
    fn the_documented_retry_example_matches_byte_for_byte() {
        // §3.2's literal example string, pinned as a PURE SERIALIZER vector:
        // the state below is constructed by hand because the document's own
        // example contradicts the executable reference — trusted-router-py's
        // on_transport_error maps every timeout (connect timeouts included)
        // to outcome "timeout", so a real engine emits
        // po=timeout;pc=connect_timeout for this scenario, never
        // po=transport_error. The modules win over the document by the
        // contract's own header; the engine-path truth is pinned by
        // the_sdk_deadline_is_recorded_as_a_timeout and
        // a_transport_error_carries_its_class_to_the_next_attempt in
        // transport::engine. This test only proves the serializer reproduces
        // the documented bytes for the documented field values.
        let first = Instant::now();
        let mut recorder = header_recorder(true);
        recorder.attempts.push(AttemptRecord {
            index: 0,
            host: Host::Apex,
            outcome: AttemptOutcome::TransportError,
            http_status: None,
            error_class: Some(ErrorClass::ConnectTimeout),
            error_source: None,
            should_retry: ShouldRetry::Absent,
            retry_after_ms: None,
            elapsed_ms: 10012,
            ttfb_ms: None,
            request_id: None,
            moved: true,
            phase: TimeoutPhase::Connect,
        });
        recorder.failover_used = true;
        recorder.first_started = Some(first);
        recorder.attempt_started = Some(first + Duration::from_millis(10530));
        recorder.current_host = Some(Host::Ally);
        recorder.current_index = Some(1);
        assert_eq!(
            recorder.header_value().as_deref(),
            Some(
                "v=1;a=1;po=transport_error;pc=connect_timeout;ph=apex;pm=10012;sm=10530;s=1;fo=1"
            )
        );
    }

    #[test]
    fn a_custom_host_suppresses_the_header() {
        // A self-hosted gateway is not TrustedRouter's to measure (§3.2).
        let mut recorder = header_recorder(true);
        recorder.begin_attempt(&Url::parse("http://127.0.0.1:9/v1/").unwrap());
        assert_eq!(recorder.header_value(), None);
        // And before begin_attempt there is nothing to describe.
        assert_eq!(header_recorder(true).header_value(), None);
    }

    #[test]
    fn recorded_durations_past_the_bound_clamp_on_the_wire() {
        // Drive the REAL recording path for an attempt that has been running
        // for two hours: Instant cannot be faked, so the recorded start is
        // rewound instead. pm and sm must clamp to the contract's 3600000
        // ceiling — never serialise past it.
        let mut recorder = header_recorder(false);
        recorder.begin_attempt(&apex_url());
        let two_hours = Duration::from_secs(2 * 3600);
        let Some(rewound) = recorder
            .attempt_started
            .and_then(|started| started.checked_sub(two_hours))
        else {
            // A platform whose monotonic clock is younger than two hours
            // cannot represent the rewind; the clamp itself stays pinned by
            // durations_clamp_to_the_contract_bounds_with_saturating_arithmetic.
            return;
        };
        recorder.attempt_started = Some(rewound);
        recorder.first_started = Some(rewound);
        recorder.on_transport_error(ErrorClass::ConnectTimeout, true, false, false);
        recorder.begin_attempt(&apex_url());
        let header = recorder.header_value().expect("in grammar");
        assert!(header.contains(";pm=3600000;"), "pm must clamp: {header}");
        assert!(header.contains(";sm=3600000;"), "sm must clamp: {header}");
        assert!(header.len() <= 160);
        assert_header_grammar(&header);
    }

    #[test]
    fn an_attempt_index_past_the_contract_bound_sends_nothing() {
        // §3.2 bounds a to 0..99. Past it the SDK stays silent instead of
        // emitting a header the enclave would drop whole. The state here is
        // production-shaped: one hundred real begin/record cycles.
        let url = apex_url();
        let mut recorder = header_recorder(false);
        for _ in 0..99 {
            recorder.begin_attempt(&url);
            recorder.on_transport_error(ErrorClass::ConnectRefused, false, false, false);
        }
        recorder.begin_attempt(&url);
        let at_bound = recorder.header_value().expect("99 itself is in bounds");
        assert!(at_bound.starts_with("v=1;a=99;"), "{at_bound}");
        assert_header_grammar(&at_bound);
        recorder.on_transport_error(ErrorClass::ConnectRefused, false, false, false);
        recorder.begin_attempt(&url);
        assert_eq!(recorder.header_value(), None, "attempt 100 must be silent");
    }

    #[test]
    fn a_forced_retry_after_ok_serialises_po_none() {
        // Serializer vector for the cross-SDK ruling: a previous attempt
        // whose outcome was ok (a sub-400 response retried on
        // x-should-retry: true) must degrade to po=none;pc=none. The
        // engine-path proof is a_forced_retry_after_a_sub_400_response_
        // reports_po_none in tests/telemetry_header.rs.
        let url = apex_url();
        let mut recorder = header_recorder(false);
        recorder.begin_attempt(&url);
        recorder.on_response(302, &empty_headers(), None);
        recorder.begin_attempt(&url);
        let header = recorder.header_value().expect("in grammar");
        assert!(
            header.starts_with("v=1;a=1;po=none;pc=none;ph=apex;"),
            "{header}"
        );
    }

    fn assert_header_grammar(header: &str) {
        for part in header.split(';') {
            let (key, value) = part.split_once('=').expect("key=value");
            assert!(!key.is_empty());
            assert!(
                !value.is_empty()
                    && value.len() <= 24
                    && value
                        .bytes()
                        .all(|byte| matches!(byte, b'a'..=b'z' | b'0'..=b'9' | b'_')),
                "value {value:?} breaks the grammar"
            );
        }
    }

    #[test]
    fn finalize_header_sends_nothing_rather_than_an_out_of_grammar_value() {
        // Telemetry may never fail a request (§2.2): the guard's only failure
        // mode is silence.
        assert_eq!(
            finalize_header(&[("v", "1".to_owned()), ("pc", "BAD-VALUE".to_owned())]),
            None
        );
        assert_eq!(finalize_header(&[("pc", String::new())]), None);
        assert_eq!(
            finalize_header(&[("pc", "a".repeat(25))]),
            None,
            "25 chars breaks the 24-char value bound"
        );
        let long = (0..7)
            .map(|index| (LONG_KEYS[index], "a".repeat(24)))
            .collect::<Vec<_>>();
        assert_eq!(finalize_header(&long), None, "161+ bytes must send nothing");
        assert_eq!(
            finalize_header(&[("v", "1".to_owned()), ("a", "0".to_owned())]).as_deref(),
            Some("v=1;a=0")
        );
    }

    const LONG_KEYS: [&str; 7] = ["k1", "k2", "k3", "k4", "k5", "k6", "k7"];

    #[test]
    fn durations_clamp_to_the_contract_bounds_with_saturating_arithmetic() {
        let start = Instant::now();
        assert_eq!(duration_ms(start, start), 0);
        assert_eq!(
            duration_ms(start, start + Duration::from_secs(2 * 3600)),
            3_600_000,
            "two hours clamps to the 0..3600000 bound"
        );
        // Reversed instants saturate to zero, never panic or wrap.
        assert_eq!(duration_ms(start + Duration::from_secs(5), start), 0);
        assert_eq!(
            duration_ms(start, start + Duration::from_millis(10530)),
            10530
        );
    }

    #[test]
    fn known_hosts_match_the_contract() {
        // §5.2 host table, cross-checked against trusted-router-py
        // _constants.py. Hostname matching is case-insensitive and ignores
        // ports; only the control plane is scheme-gated.
        for (url, expected) in [
            ("https://api.trustedrouter.com/v1", Host::Apex),
            ("HTTPS://API.TRUSTEDROUTER.COM/other/path", Host::Apex),
            ("http://api.trustedrouter.com:8443/v1", Host::Apex),
            ("https://api.allyrouter.com/v1", Host::Ally),
            ("https://api.uptimerouter.com/v1", Host::Uptime),
            (
                "https://api-us-central1.quillrouter.com/v1",
                Host::UsCentral1,
            ),
            ("https://api-us-east4.quillrouter.com/v1", Host::UsEast4),
            (
                "https://api-europe-west4.quillrouter.com/v1",
                Host::EuropeWest4,
            ),
            ("https://trustedrouter.com/v1", Host::Control),
            ("https://trust.trustedrouter.com/anything", Host::Control),
            ("http://trustedrouter.com/v1", Host::Custom),
            ("https://my.internal/v1", Host::Custom),
            ("https://nottrustedrouter.com/v1", Host::Custom),
            (
                "https://api.trustedrouter.com.evil.example/v1",
                Host::Custom,
            ),
        ] {
            assert_eq!(
                host_enum(&Url::parse(url).unwrap()),
                expected,
                "host mapping for {url}"
            );
        }
        assert_eq!(host_enum_str("not a url"), Host::Custom);
        // Wire serialisation is pinned against the shared vocabulary.
        assert_eq!(
            [
                Host::Apex.as_str(),
                Host::Ally.as_str(),
                Host::Uptime.as_str(),
                Host::UsCentral1.as_str(),
                Host::UsEast4.as_str(),
                Host::EuropeWest4.as_str(),
                Host::Control.as_str(),
                Host::Custom.as_str(),
            ],
            crate::constants::TELEMETRY_HOSTS
        );
    }

    fn env_of(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
            .collect()
    }

    #[test]
    fn telemetry_enablement_precedence_mirrors_the_python_sdk() {
        // The exact parameter table of trusted-router-py's
        // test_telemetry_enablement_precedence, plus the custom-control case.
        type Case = (
            Option<bool>,
            &'static [(&'static str, &'static str)],
            &'static str,
            &'static str,
            bool,
        );
        let default_base = "https://api.trustedrouter.com/v1";
        let cases: [Case; 9] = [
            (
                Some(true),
                &[("TRUSTEDROUTER_TELEMETRY", "0"), ("DO_NOT_TRACK", "1")],
                "x",
                "x",
                true,
            ),
            (
                Some(false),
                &[("TRUSTEDROUTER_TELEMETRY", "1")],
                default_base,
                "x",
                false,
            ),
            (
                None,
                &[("TRUSTEDROUTER_TELEMETRY", "OFF")],
                default_base,
                "x",
                false,
            ),
            (
                None,
                &[("TRUSTEDROUTER_TELEMETRY", "yes"), ("DO_NOT_TRACK", "1")],
                "x",
                "x",
                true,
            ),
            (
                None,
                &[("TRUSTEDROUTER_TELEMETRY", "maybe"), ("DO_NOT_TRACK", "1")],
                "x",
                "x",
                false,
            ),
            (
                None,
                &[],
                default_base,
                "https://telemetry.trustedrouter.com/v1",
                true,
            ),
            (
                None,
                &[],
                "https://private.example/v1",
                "https://trustedrouter.com/v1",
                false,
            ),
            (None, &[], default_base, "https://control.example/v1", false),
            (
                None,
                &[("TRUSTEDROUTER_TELEMETRY", "0")],
                default_base,
                "https://trustedrouter.com/v1",
                false,
            ),
        ];
        for (explicit, pairs, base, control, expected) in cases {
            let env = env_of(pairs);
            let resolved =
                resolve_telemetry_enabled(explicit, base, control, &|name| env.get(name).cloned());
            assert_eq!(
                resolved, expected,
                "explicit={explicit:?} env={pairs:?} base={base} control={control}"
            );
        }
    }

    #[test]
    fn attestation_and_authorize_are_the_untracked_inference_paths() {
        assert!(!tracked_inference_path("/attestation"));
        assert!(!tracked_inference_path("/attestation?nonce=ab12"));
        assert!(!tracked_inference_path("/attestation/"));
        // The engine passes resolved candidate paths, base prefix included.
        assert!(!tracked_inference_path("/v1/attestation"));
        assert!(!tracked_inference_path("/v1/attestation/evidence"));
        // §2.2 hard MUST: client context never rides the authorize route.
        assert!(!tracked_inference_path("/internal/gateway/authorize"));
        assert!(!tracked_inference_path("/v1/internal/gateway/authorize"));
        assert!(!tracked_inference_path("/v1/internal/gateway/authorize/"));
        assert!(tracked_inference_path("/chat/completions"));
        assert!(tracked_inference_path("/v1/chat/completions"));
        assert!(tracked_inference_path("/responses"));
        assert!(tracked_inference_path("/attestations"));
        assert!(tracked_inference_path("/v1/attestations"));
    }

    #[test]
    fn no_alternate_spelling_of_an_excluded_route_is_tracked() {
        // A §2.2 MUST cannot be defeated by respelling the route. `Url::path`
        // keeps percent escapes, so matching literal route text alone let
        // `%61uthorize` through while the gateway's parser decoded it back to
        // the real authorize route. Case and repeated separators fold for the
        // same fail-closed reason.
        for path in [
            "/v1/internal/gateway/%61uthorize",
            "/v1/internal/gateway/authoriz%65",
            "/v1/internal/gateway/%61%75%74%68%6f%72%69%7a%65",
            "/v1/%69nternal/gateway/authorize",
            "/v1/INTERNAL/GATEWAY/AUTHORIZE",
            "/v1/Internal/Gateway/Authorize",
            "/v1/internal//gateway/authorize",
            "/v1//internal/gateway/authorize//",
            "/v1/internal/gateway/%61uthorize?trace=1",
            "/v1/%61ttestation",
            "/v1/attestatio%6e",
            "/v1/ATTESTATION",
            "/v1//attestation",
            "/v1/%61ttestation/evidence",
        ] {
            assert!(
                !tracked_inference_path(path),
                "must never be traced: {path}"
            );
        }
        // Folding must not swallow genuine inference routes, including the
        // lookalikes that only share a prefix.
        for path in [
            "/v1/chat/completions",
            "/v1/attestations",
            "/v1/attestation%73",
            "/v1/internal/gateway/authorized_models",
            "/v1/preattestation",
            "/v1/%63hat/completions",
        ] {
            assert!(tracked_inference_path(path), "must stay traced: {path}");
        }
    }

    #[test]
    fn route_folding_is_total_on_malformed_escapes() {
        // Telemetry may never fail a request (§2.2): every spelling has to
        // fold without panicking, malformed and non-ASCII escapes included.
        for path in [
            "",
            "/",
            "//",
            "%",
            "%%",
            "%a",
            "%zz",
            "%2",
            "/%",
            "/%f0%9f%92%a9",
            "/café",
            "%00",
            "/v1/chat%",
            "/%61ttestation%",
            "/v1/attestation%zz",
        ] {
            let _ = tracked_inference_path(path);
        }
        // A malformed escape stays literal instead of being guessed at, so it
        // cannot manufacture a route match; a well-formed one still folds.
        assert!(tracked_inference_path("/attestation%zz/evidence"));
        assert!(!tracked_inference_path("/%61ttestation/evidence"));
    }

    /// Minimal error carrier for synthetic cause chains, mirroring the
    /// Python suite's `classification_walks_causes` test.
    #[derive(Debug)]
    struct Chain {
        message: &'static str,
        source: Option<Box<dyn std::error::Error + 'static>>,
    }

    impl std::fmt::Display for Chain {
        fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(formatter, "{}", self.message)
        }
    }

    impl std::error::Error for Chain {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            self.source.as_deref()
        }
    }

    fn wrapping(message: &'static str, source: Option<Box<dyn std::error::Error>>) -> Chain {
        Chain { message, source }
    }

    fn io_chain(kind: std::io::ErrorKind) -> Chain {
        wrapping(
            "request failed",
            Some(Box::new(std::io::Error::new(kind, "io failure"))),
        )
    }

    #[test]
    fn classification_walks_source_chains_by_type_first() {
        use std::io::ErrorKind;
        for (kind, connect, expected) in [
            (
                ErrorKind::ConnectionRefused,
                true,
                ErrorClass::ConnectRefused,
            ),
            (ErrorKind::ConnectionReset, false, ErrorClass::Reset),
            (ErrorKind::ConnectionAborted, false, ErrorClass::Reset),
            (ErrorKind::BrokenPipe, false, ErrorClass::Reset),
            (ErrorKind::TimedOut, true, ErrorClass::ConnectTimeout),
            (ErrorKind::TimedOut, false, ErrorClass::ReadTimeout),
            (ErrorKind::InvalidData, true, ErrorClass::Tls),
            (ErrorKind::UnexpectedEof, false, ErrorClass::IoError),
        ] {
            assert_eq!(
                classify_chain(&io_chain(kind), connect),
                expected,
                "{kind:?} connect={connect}"
            );
        }
    }

    fn probed(message: &'static str) -> Chain {
        // Real probe-worthy text always sits BELOW the outermost error, the
        // shape hyper-util and rustls actually produce.
        wrapping("request failed", Some(Box::new(wrapping(message, None))))
    }

    #[test]
    fn classification_falls_back_to_bounded_message_probes() {
        // hyper-util wraps getaddrinfo failures in a message-only error, and
        // rustls failures cross as opaque strings: these probes are the only
        // place text decides anything, and they sit behind every typed check.
        assert_eq!(
            classify_chain(&probed("dns error: lookup failed"), true),
            ErrorClass::Dns
        );
        assert_eq!(
            classify_chain(&probed("failed to lookup address information"), true),
            ErrorClass::Dns
        );
        assert_eq!(
            classify_chain(&probed("invalid peer certificate"), true),
            ErrorClass::Tls
        );
        assert_eq!(
            classify_chain(
                &probed("received corrupt message of type InvalidContentType"),
                true
            ),
            ErrorClass::Tls
        );
        assert_eq!(
            classify_chain(&probed("proxy authentication required"), false),
            ErrorClass::ProxyError
        );
        assert_eq!(
            classify_chain(&probed("connection closed before message completed"), false),
            ErrorClass::ProtocolError
        );
        assert_eq!(
            classify_chain(&probed("something else entirely"), true),
            ErrorClass::ConnectError
        );
        assert_eq!(
            classify_chain(&probed("something else entirely"), false),
            ErrorClass::Unknown
        );
    }

    #[test]
    fn the_outermost_display_never_decides_a_classification() {
        // reqwest's top-level Display can embed the request URL — text the
        // caller controls. A URL that says "tls" or "proxy" must not beat the
        // typed refusal underneath it, and a probe-worthy word that appears
        // ONLY in the outermost display decides nothing.
        let refused = wrapping(
            "error sending request for url (https://api.trustedrouter.com/v1/tls/proxy/parse)",
            Some(Box::new(std::io::Error::new(
                std::io::ErrorKind::ConnectionRefused,
                "connection refused",
            ))),
        );
        assert_eq!(classify_chain(&refused, true), ErrorClass::ConnectRefused);
        assert_eq!(
            classify_chain(&wrapping("dns error at the top only", None), false),
            ErrorClass::Unknown
        );
        assert_eq!(
            classify_chain(&wrapping("tls at the top only", None), true),
            ErrorClass::ConnectError
        );
    }

    #[tokio::test]
    async fn real_dns_failures_classify_as_dns() {
        let error = reqwest::Client::new()
            .get("http://tr-telemetry-test.invalid/v1/models")
            .send()
            .await
            .expect_err(".invalid must never resolve");
        assert_eq!(classify_transport_error(&error), ErrorClass::Dns);
    }

    #[tokio::test]
    async fn real_refused_connections_classify_as_connect_refused() {
        let port = {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            listener.local_addr().unwrap().port()
        };
        let error = reqwest::Client::new()
            .get(format!("http://127.0.0.1:{port}/v1/models"))
            .send()
            .await
            .expect_err("nobody is listening");
        assert_eq!(classify_transport_error(&error), ErrorClass::ConnectRefused);
    }

    #[tokio::test]
    async fn real_reqwest_timeouts_classify_as_read_timeout() {
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_delay(Duration::from_secs(5)))
            .mount(&server)
            .await;
        let error = reqwest::Client::builder()
            .timeout(Duration::from_millis(50))
            .build()
            .unwrap()
            .get(format!("{}/v1/models", server.uri()))
            .send()
            .await
            .expect_err("the deadline is shorter than the delay");
        assert!(error.is_timeout());
        assert_eq!(classify_transport_error(&error), ErrorClass::ReadTimeout);
    }

    #[tokio::test]
    async fn a_proxy_connect_failure_pins_to_its_socket_class() {
        // Proxy provenance is best-effort (documented boundary): reqwest's
        // failure to reach a dead proxy surfaces the underlying socket
        // error, so the pinned class is connect_refused, not proxy_error.
        // Nothing leaves the machine — the proxy connection fails first.
        let dead_port = {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            listener.local_addr().unwrap().port()
        };
        let error = reqwest::Client::builder()
            .proxy(reqwest::Proxy::all(format!("http://127.0.0.1:{dead_port}")).unwrap())
            .build()
            .unwrap()
            .get("http://api.trustedrouter.com/v1/models")
            .send()
            .await
            .expect_err("the proxy port is dead");
        assert_eq!(classify_transport_error(&error), ErrorClass::ConnectRefused);
    }

    #[tokio::test]
    async fn real_mid_request_closes_classify_as_protocol_error() {
        // Accept, read the request, close cleanly without answering: hyper
        // reports the connection closed before the message completed, the
        // exact shape python's httpx calls RemoteProtocolError.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            if let Ok((mut socket, _)) = listener.accept().await {
                let mut buffer = [0_u8; 1024];
                let _ = tokio::io::AsyncReadExt::read(&mut socket, &mut buffer).await;
                drop(socket);
            }
        });
        let error = reqwest::Client::new()
            .get(format!("http://{addr}/v1/models"))
            .send()
            .await
            .expect_err("the server hangs up before responding");
        assert_eq!(classify_transport_error(&error), ErrorClass::ProtocolError);
        server.abort();
    }
}
