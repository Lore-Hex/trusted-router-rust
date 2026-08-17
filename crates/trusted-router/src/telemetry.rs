//! Client-observed reliability telemetry: the `x-tr-client` header channel.
//!
//! Implements contract v1 of `docs/client-telemetry.md` (Lore-Hex/quill-router),
//! header channel only (§3.2). The beacon channel (§4) is deliberately absent
//! per §9/§10: no second SDK grows a beacon until the Python contract has been
//! live and calibrated. `credential_free_json` in [`crate::transport`] is the
//! reserved out-of-engine attach point for that later PR.
//!
//! Non-negotiable (§2.2): telemetry never fails a request. Every path in this
//! module is total — no panics, no `unwrap`/`expect`, saturating integer
//! arithmetic, and an out-of-grammar header value sends nothing rather than
//! erroring.
//!
//! Host mapping (§5.2) matches by hostname, case-insensitively and ignoring
//! the port, mirroring `trusted_router._telemetry.host_enum` in the Python
//! SDK with one deliberate divergence: the Python SDK also compares the URL
//! scheme for the API hosts, classifying `http://api.trustedrouter.com` as
//! `custom`. This SDK classifies by hostname alone (the spec's §5.2 table maps
//! hostnames; only the control host is scheme-gated), which keeps the mapping
//! testable against a loopback HTTP mock via a DNS override — Rust has no
//! in-process fake transport, so the wire tests must speak real HTTP.

use crate::constants::{ALIAS_API_BASE_URLS, DEFAULT_API_BASE_URL};
use std::time::Instant;
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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

/// Per-attempt outcomes producible by the transport engine (§5.2 Outcome).
///
/// `stream_broken` and `aborted` are absent deliberately: the engine never
/// retries after the first surfaced body byte (transport invariant 6), so
/// neither can ever be a *previous* attempt's outcome in a header. The full
/// wire vocabulary is pinned by [`crate::constants::TELEMETRY_OUTCOMES`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AttemptOutcome {
    /// 2xx–3xx response.
    Ok,
    /// 4xx–5xx response.
    HttpError,
    /// No usable HTTP response.
    TransportError,
    /// The SDK's own deadline, or a transport-level timeout.
    Timeout,
}

impl AttemptOutcome {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::HttpError => "http_error",
            Self::TransportError => "transport_error",
            Self::Timeout => "timeout",
        }
    }
}

/// Transport-error classes producible by the engine (§5.2 `ErrorClass`).
///
/// `write_timeout`, `pool_timeout`, and `stream_stalled` are absent because
/// the engine cannot observe them (no write/pool deadlines; no mid-stream
/// retries). The full wire vocabulary is pinned by
/// [`crate::constants::TELEMETRY_ERROR_CLASSES`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
    /// HTTP framing was violated, or the peer closed mid-message.
    ProtocolError,
    /// The connection was reset or aborted.
    Reset,
    /// Another I/O failure.
    IoError,
    /// A proxy failed the request.
    ProxyError,
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
            Self::ProtocolError => "protocol_error",
            Self::Reset => "reset",
            Self::IoError => "io_error",
            Self::ProxyError => "proxy_error",
            Self::Unknown => "unknown",
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
/// The engine passes the RESOLVED candidate path, not the caller's raw
/// string, so dot segments (`/x/../attestation`) cannot dodge either
/// exclusion.
pub(crate) fn tracked_inference_path(path: &str) -> bool {
    let clean = path.split(['?', '#']).next().unwrap_or(path);
    let clean = clean.trim_end_matches('/');
    let excluded = |route: &str| clean.ends_with(route) || clean.contains(&format!("{route}/"));
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

/// One attempt's facts, as the retry loop observed them.
#[derive(Debug, Clone, Copy)]
pub(crate) struct AttemptRecord {
    pub(crate) index: usize,
    pub(crate) host: Host,
    pub(crate) outcome: AttemptOutcome,
    pub(crate) error_class: Option<ErrorClass>,
    pub(crate) elapsed_ms: u64,
    pub(crate) moved: bool,
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

/// Records one logical inference call across the retry loop and derives the
/// per-attempt `x-tr-client` value (§3.2). Mirrors the recording half of
/// `trusted_router._telemetry.RequestRecorder`; the sink/beacon half is
/// deliberately out of scope for the header-channel PR.
#[derive(Debug)]
pub(crate) struct RequestRecorder {
    streaming: bool,
    attempts: Vec<AttemptRecord>,
    failover_used: bool,
    first_started: Option<Instant>,
    attempt_started: Option<Instant>,
    current_host: Option<Host>,
    current_index: Option<usize>,
}

impl RequestRecorder {
    pub(crate) fn new(streaming: bool) -> Self {
        Self {
            streaming,
            attempts: Vec::new(),
            failover_used: false,
            first_started: None,
            attempt_started: None,
            current_host: None,
            current_index: None,
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
            // timeout|stream_broken — there is no "ok". A forced retry after
            // a sub-400 response (x-should-retry: true on a 3xx) therefore
            // degrades to po=none;pc=none rather than emitting a value the
            // enclave would drop the whole header for.
            let (po, pc) = match previous.outcome {
                AttemptOutcome::Ok => ("none", "none"),
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

    /// Records an attempt that produced an HTTP response.
    pub(crate) fn on_response(&mut self, status: u16) {
        let (Some(started), Some(host), Some(index)) =
            (self.attempt_started, self.current_host, self.current_index)
        else {
            return;
        };
        self.store_attempt(AttemptRecord {
            index,
            host,
            outcome: if status < 400 {
                AttemptOutcome::Ok
            } else {
                AttemptOutcome::HttpError
            },
            error_class: None,
            elapsed_ms: duration_ms(started, Instant::now()),
            moved: false,
        });
    }

    /// Records an attempt that failed before an HTTP response existed. The
    /// class must be captured while the typed transport error is still alive
    /// (see [`classify_transport_error`]).
    pub(crate) fn on_transport_error(&mut self, class: ErrorClass, timed_out: bool) {
        let (Some(started), Some(host), Some(index)) =
            (self.attempt_started, self.current_host, self.current_index)
        else {
            return;
        };
        self.store_attempt(AttemptRecord {
            index,
            host,
            outcome: if timed_out {
                AttemptOutcome::Timeout
            } else {
                AttemptOutcome::TransportError
            },
            error_class: Some(class),
            elapsed_ms: duration_ms(started, Instant::now()),
            moved: false,
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
        AttemptRecord, ErrorClass, Host, RequestRecorder,
    };
    use std::collections::HashMap;
    use std::time::{Duration, Instant};
    use url::Url;

    fn apex_url() -> Url {
        Url::parse("https://api.trustedrouter.com/v1/").unwrap()
    }

    #[test]
    fn attempt_zero_headers_match_the_contract_examples_byte_for_byte() {
        let mut streaming = RequestRecorder::new(true);
        streaming.begin_attempt(&apex_url());
        assert_eq!(streaming.header_value().as_deref(), Some("v=1;a=0;s=1"));

        let mut buffered = RequestRecorder::new(false);
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
        let mut recorder = RequestRecorder::new(true);
        recorder.attempts.push(AttemptRecord {
            index: 0,
            host: Host::Apex,
            outcome: AttemptOutcome::TransportError,
            error_class: Some(ErrorClass::ConnectTimeout),
            elapsed_ms: 10012,
            moved: true,
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
        let mut recorder = RequestRecorder::new(true);
        recorder.begin_attempt(&Url::parse("http://127.0.0.1:9/v1/").unwrap());
        assert_eq!(recorder.header_value(), None);
        // And before begin_attempt there is nothing to describe.
        assert_eq!(RequestRecorder::new(true).header_value(), None);
    }

    #[test]
    fn recorded_durations_past_the_bound_clamp_on_the_wire() {
        // Drive the REAL recording path for an attempt that has been running
        // for two hours: Instant cannot be faked, so the recorded start is
        // rewound instead. pm and sm must clamp to the contract's 3600000
        // ceiling — never serialise past it.
        let mut recorder = RequestRecorder::new(false);
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
        recorder.on_transport_error(ErrorClass::ConnectTimeout, true);
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
        let mut recorder = RequestRecorder::new(false);
        for _ in 0..99 {
            recorder.begin_attempt(&url);
            recorder.on_transport_error(ErrorClass::ConnectRefused, false);
        }
        recorder.begin_attempt(&url);
        let at_bound = recorder.header_value().expect("99 itself is in bounds");
        assert!(at_bound.starts_with("v=1;a=99;"), "{at_bound}");
        assert_header_grammar(&at_bound);
        recorder.on_transport_error(ErrorClass::ConnectRefused, false);
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
        let mut recorder = RequestRecorder::new(false);
        recorder.begin_attempt(&url);
        recorder.on_response(302);
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
