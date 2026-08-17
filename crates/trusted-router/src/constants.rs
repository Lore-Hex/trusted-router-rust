//! Stable SDK defaults and model aliases.

use std::time::Duration;

/// Crate version.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
/// Attested inference API base URL.
pub const DEFAULT_API_BASE_URL: &str = "https://api.trustedrouter.com/v1";

/// Exact aliases of [`DEFAULT_API_BASE_URL`], on separate domains served by
/// separate DNS providers (trustedrouter.com from Google Cloud DNS, these two
/// from Route 53). They resolve to the same attested enclaves.
///
/// The domain is a single point of failure sitting above the whole deployment:
/// a zone that stops answering, a registrar lock, or a resolver handing out a
/// stale record takes the API down however many clouds are behind it.
pub const ALIAS_API_BASE_URLS: [&str; 2] = [
    "https://api.allyrouter.com/v1",
    "https://api.uptimerouter.com/v1",
];
/// Dashboard and account control-plane API base URL.
pub const DEFAULT_CONTROL_BASE_URL: &str = "https://trustedrouter.com/v1";
/// Public signed trust-release document.
pub const DEFAULT_TRUST_RELEASE_URL: &str =
    "https://trust.trustedrouter.com/trust/gcp-release.json";
/// Public status JSON document.
pub const DEFAULT_STATUS_URL: &str = "https://status.trustedrouter.com/status.json";
/// Default per-attempt request timeout.
pub const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(120);
/// Default orchestration timeout.
pub const DEFAULT_ORCHESTRATION_TIMEOUT: Duration = Duration::from_secs(600);
/// Number of retries after the initial request.
pub const DEFAULT_MAX_RETRIES: usize = 2;

/// Client-telemetry contract schema version implemented by this SDK.
///
/// Pinned by the cross-SDK parity tests in `tests/telemetry_header.rs`; the
/// value lists below are the closed contract-v1 vocabularies and must not
/// change without a coordinated release across every `TrustedRouter` SDK.
pub const TELEMETRY_SCHEMA_VERSION: u32 = 1;
/// Control-plane ingest path for the telemetry beacon channel. Reserved: the
/// Rust SDK implements the header channel only; no beacon is sent.
pub const DEFAULT_TELEMETRY_PATH: &str = "/client-events";
/// Closed telemetry host vocabulary (contract v1 §5.2).
pub const TELEMETRY_HOSTS: [&str; 8] = [
    "apex",
    "ally",
    "uptime",
    "us_central1",
    "us_east4",
    "europe_west4",
    "control",
    "custom",
];
/// Closed telemetry endpoint vocabulary (contract v1 §5.2).
pub const TELEMETRY_ENDPOINTS: [&str; 10] = [
    "chat_completions",
    "messages",
    "responses",
    "embeddings",
    "images",
    "videos",
    "models",
    "fusion",
    "control_other",
    "inference_other",
];
/// Closed telemetry per-attempt outcome vocabulary (contract v1 §5.2).
pub const TELEMETRY_OUTCOMES: [&str; 6] = [
    "ok",
    "http_error",
    "transport_error",
    "timeout",
    "stream_broken",
    "aborted",
];
/// Closed telemetry transport-error class vocabulary (contract v1 §5.2).
pub const TELEMETRY_ERROR_CLASSES: [&str; 14] = [
    "dns",
    "tls",
    "connect_refused",
    "connect_timeout",
    "connect_error",
    "read_timeout",
    "write_timeout",
    "pool_timeout",
    "protocol_error",
    "reset",
    "io_error",
    "proxy_error",
    "stream_stalled",
    "unknown",
];

/// Automatic non-orchestration model routing.
pub const AUTO_MODEL: &str = "trustedrouter/auto";
/// Lowest-latency healthy routing pool.
pub const FAST_MODEL: &str = "trustedrouter/fast";
/// Zero-data-retention routing pool.
pub const ZDR_MODEL: &str = "trustedrouter/zdr";
/// Provider-side confidential-compute and end-to-end-encrypted pool.
pub const E2E_MODEL: &str = "trustedrouter/e2e";
/// Alias for [`E2E_MODEL`].
pub const CONFIDENTIAL_MODEL: &str = "trustedrouter/confidential";
/// EU-focused provider pool.
pub const EU_MODEL: &str = "trustedrouter/eu";
/// US-jurisdiction provider pool.
pub const US_MODEL: &str = "trustedrouter/us";
/// Synth orchestration primitive.
pub const SYNTH_MODEL: &str = "trustedrouter/synth";
/// Legacy alias for [`SYNTH_MODEL`].
pub const FUSION_MODEL: &str = "trustedrouter/fusion";
/// Advisor orchestration primitive.
pub const ADVISOR_MODEL: &str = "trustedrouter/advisor";
/// Selector orchestration primitive.
pub const SELECTOR_MODEL: &str = "trustedrouter/selector";
/// Map-reduce orchestration primitive.
pub const MAP_REDUCE_MODEL: &str = "trustedrouter/mapreduce";
/// Subagent orchestration primitive.
pub const SUBAGENT_MODEL: &str = "trustedrouter/subagent";
/// Stable Socrates model alias.
pub const SOCRATES_MODEL: &str = "trustedrouter/socrates-1.1";
/// Stable Prometheus model alias.
pub const PROMETHEUS_MODEL: &str = "trustedrouter/prometheus-2.0";
/// Stable Zeus model alias.
pub const ZEUS_MODEL: &str = "trustedrouter/zeus-1.0";
/// Private-configuration Athena alias.
pub const ATHENA_MODEL: &str = "trustedrouter/athena";

/// Recommended permissive open-model Synth panel.
pub const SYNTH_FREEDOM_PANEL: &[&str] = &[
    "minimax/minimax-m3",
    "~kimi/latest",
    "~zai/glm-latest",
    "google/gemma-4-31b-it",
    "deepseek/deepseek-v4-flash",
];

/// Recommended fallback judge chain.
pub const SYNTH_FREEDOM_FALLBACK_JUDGES: &[&str] = &[
    "minimax/minimax-m3",
    "~zai/glm-latest",
    "~kimi/latest",
    "deepseek/deepseek-v4-flash",
    "google/gemma-4-31b-it",
];

/// Recommended fallback synthesizer chain.
pub const SYNTH_FREEDOM_FALLBACK_FINALS: &[&str] = SYNTH_FREEDOM_FALLBACK_JUDGES;
