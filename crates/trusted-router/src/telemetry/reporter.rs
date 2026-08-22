//! The beacon reporter (§4, §6.2): a bounded, out-of-engine delivery sink
//! for client reliability telemetry. A port of
//! `trusted_router._telemetry.TelemetryReporter`.
//!
//! # Where it sits
//!
//! The reporter is the only thing in the crate that talks to
//! `/client-events`, and it does so on its OWN [`reqwest::Client`] — never
//! the engine's transport, never a caller-injected client, and never through
//! [`crate::client::Client`]'s retry loop. Like `credential_free_json` in
//! [`crate::transport`], every flush is one single-shot `POST`: no retries,
//! no candidate failover, no recorder (the beacon is never itself traced).
//!
//! # Lifecycle
//!
//! Nothing runs at construction. The first recorded call lazily spawns ONE
//! worker task on the current Tokio runtime, which flushes every
//! `flush_seconds` (30 s), sooner when 50 events or ~60 KB are waiting, and
//! backs off on 429/503/transport failures (60 s doubling to 10 min,
//! honouring `Retry-After` ≤ 600 s). The worker holds only a [`Weak`]
//! reference, so dropping the last [`TelemetryReporter`] handle is the close
//! path: it stops the worker and performs one final flush bounded to 2 s on a
//! dedicated thread with its own single-threaded runtime, so it works from
//! async and blocking contexts alike and never depends on a runtime that may
//! itself be shutting down.
//!
//! When no Tokio runtime is current at the first record — which cannot
//! happen on the SDK's own request path, since `reqwest` itself requires one
//! — no worker is started; records stay in the bounded buffers and go out on
//! the final flush.
//!
//! # Bounds (§6.2)
//!
//! ≤ 1 000 buffered events (the oldest success, then the oldest failure, is
//! dropped first and every drop is counted), ≤ 256 counter keys per minute
//! window folded through the Python SDK's exact ladder, closed windows
//! retained ≤ 24 h under ~512 KiB oldest-first, batches trimmed to ≤ 65 536
//! bytes, ≤ 100 events and ≤ 200 counters. Policy from a 202 is applied only
//! when it reduces volume. 400/401/403/404/410 and `x-tr-telemetry: off`
//! disable the reporter for the rest of the process and clear its buffers.

use super::wire::{
    merge_counter_increment, sdk_user_agent, SampleReason, SdkIdentity, WireBatch, WireCounter,
    WireEvent,
};
use super::{CounterKey, CounterRow, Endpoint, ErrorClass, RequestEvent, TelemetrySink};
use crate::constants::{
    DEFAULT_TELEMETRY_PATH, TELEMETRY_BACKOFF_MAX_SECONDS, TELEMETRY_BACKOFF_MIN_SECONDS,
    TELEMETRY_FLUSH_SECONDS, TELEMETRY_MAX_BATCH_COUNTERS, TELEMETRY_MAX_BATCH_EVENTS,
    TELEMETRY_MAX_EVENTS, TELEMETRY_MAX_WINDOW_KEYS, TELEMETRY_RETENTION_BYTES,
    TELEMETRY_RETENTION_SECONDS,
};
use rand::{Rng, RngCore};
use reqwest::header::{HeaderMap, AUTHORIZATION, CONTENT_TYPE, USER_AGENT};
use serde_json::Value;
use std::collections::{BTreeMap, HashSet, VecDeque};
use std::fmt;
use std::fmt::Write as _;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, OnceLock, PoisonError, Weak};
use std::time::{Duration, Instant};
use tokio::sync::Notify;
use url::Url;

/// Urgent-flush trigger on the buffered byte estimate (§6.2 "≥ 60 KB").
const BATCH_TRIGGER_BYTES: usize = 60 * 1024;
/// Hard ceiling on one batch body (§4).
const MAX_BATCH_BYTES: usize = 65_536;
/// Urgent-flush trigger on buffered events (§6.2 "≥ 50 events").
const URGENT_EVENT_COUNT: usize = 50;
/// Rough per-key estimate for the open window in the byte trigger.
const OPEN_COUNTER_ESTIMATE_BYTES: usize = 400;
/// Longest `Retry-After` the beacon honours (§6.2).
const MAX_RETRY_AFTER_SECONDS: f64 = 600.0;
/// Longest `pause_seconds` a 202 policy may impose (§4).
const MAX_PAUSE_SECONDS: f64 = 86_400.0;
/// Slow-success threshold for 100 % sampling (§5.3).
const SLOW_MS: u64 = 30_000;
/// Per-request deadline of the reporter's own client.
const SEND_TIMEOUT: Duration = Duration::from_secs(5);
/// Bound on the exit flush (§6.2 "process exit (≤ 2 s, single attempt)").
pub(crate) const CLOSE_TIMEOUT: Duration = Duration::from_secs(2);
/// Byte estimate for an event that fails to serialise (mirrors Python).
const FALLBACK_EVENT_BYTES: usize = 600;

/// Monotonic time source. Production reads the process clock; tests inject
/// a manual one so windows, retention, backoff, and pauses are exact.
pub(crate) trait Clock: Send + Sync + fmt::Debug {
    /// Time since an arbitrary fixed origin; never decreases.
    fn now(&self) -> Duration;
}

/// [`Instant`]-backed clock measured from the first use in the process.
#[derive(Debug)]
pub(crate) struct MonotonicClock;

static CLOCK_ORIGIN: OnceLock<Instant> = OnceLock::new();

impl Clock for MonotonicClock {
    fn now(&self) -> Duration {
        Instant::now().saturating_duration_since(*CLOCK_ORIGIN.get_or_init(Instant::now))
    }
}

/// The uniform draw behind random success sampling. Production uses the
/// thread-local CSPRNG; tests inject a deterministic sequence.
pub(crate) trait SampleDraw: Send + Sync + fmt::Debug {
    /// A value in `[0, 1)`.
    fn draw(&self) -> f64;
}

#[derive(Debug)]
struct ThreadRngDraw;

impl SampleDraw for ThreadRngDraw {
    fn draw(&self) -> f64 {
        rand::thread_rng().gen::<f64>()
    }
}

/// Receives the `TRUSTEDROUTER_TELEMETRY_DEBUG=1` lines. Production writes
/// to stderr.
pub(crate) type DebugEcho = Arc<dyn Fn(&str) + Send + Sync>;

/// What the SDK-owned beacon client is built from: the same root
/// certificates and DNS overrides as the other SDK-owned transports.
#[derive(Debug, Clone, Default)]
pub(crate) struct OwnedTransport {
    pub(crate) root_certificate_pems: Vec<Vec<u8>>,
    pub(crate) host_resolutions: BTreeMap<String, SocketAddr>,
}

impl OwnedTransport {
    fn build(&self, timeout: Duration) -> Option<reqwest::Client> {
        crate::client::owned_http_builder(&self.root_certificate_pems, &self.host_resolutions)
            .ok()?
            .timeout(timeout)
            .build()
            .ok()
    }
}

/// Construction-time facts for a reporter.
pub(crate) struct ReporterConfig {
    /// The control-plane base; the beacon goes to `{base}/client-events`.
    pub(crate) control_base_url: Url,
    /// The client's own inference key. `None` (or empty) sends nothing.
    pub(crate) api_key: Option<String>,
    pub(crate) workspace_id: Option<String>,
    pub(crate) sdk: SdkIdentity,
    pub(crate) success_sample_rate: f64,
    /// `TRUSTEDROUTER_TELEMETRY_DEBUG=1`: echo each batch before sending.
    pub(crate) debug: bool,
    pub(crate) transport: OwnedTransport,
    /// Test knobs, defaulted by [`ReporterConfig::new`].
    pub(crate) flush_interval: Duration,
    pub(crate) retention_bytes: usize,
    pub(crate) clock: Arc<dyn Clock>,
    pub(crate) sampler: Arc<dyn SampleDraw>,
    pub(crate) echo: DebugEcho,
}

impl ReporterConfig {
    pub(crate) fn new(control_base_url: Url, api_key: Option<String>, sdk: SdkIdentity) -> Self {
        Self {
            control_base_url,
            api_key,
            workspace_id: None,
            sdk,
            success_sample_rate: 0.01,
            debug: false,
            transport: OwnedTransport::default(),
            flush_interval: Duration::from_secs_f64(TELEMETRY_FLUSH_SECONDS),
            retention_bytes: TELEMETRY_RETENTION_BYTES,
            clock: Arc::new(MonotonicClock),
            sampler: Arc::new(ThreadRngDraw),
            echo: Arc::new(|line: &str| eprintln!("{line}")),
        }
    }
}

/// Normalises a sample rate into `[0, 1]`, defaulting on non-finite input.
pub(crate) fn normalise_sample_rate(value: f64) -> f64 {
    if value.is_finite() {
        value.clamp(0.0, 1.0)
    } else {
        0.01
    }
}

fn normalise_flush_interval(value: Duration) -> Duration {
    let seconds = value.as_secs_f64();
    if seconds.is_finite() && seconds > 0.0 {
        Duration::from_secs_f64(seconds.min(TELEMETRY_BACKOFF_MAX_SECONDS))
    } else {
        Duration::from_secs_f64(TELEMETRY_FLUSH_SECONDS)
    }
}

fn hex_token(bytes: usize) -> String {
    let mut buffer = vec![0_u8; bytes];
    rand::thread_rng().fill_bytes(&mut buffer);
    let mut token = String::with_capacity(bytes * 2);
    for byte in buffer {
        let _ = write!(token, "{byte:02x}");
    }
    token
}

fn millis(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

fn float_value(value: &Value) -> Option<f64> {
    let parsed = match value {
        Value::Number(number) => number.as_f64()?,
        Value::String(text) => text.trim().parse::<f64>().ok()?,
        _ => return None,
    };
    parsed.is_finite().then_some(parsed)
}

#[derive(Debug)]
struct BufferedEvent {
    id: u64,
    wire: WireEvent,
    completed_at: Duration,
    estimated_bytes: usize,
    ok: bool,
}

#[derive(Debug)]
struct CounterWindow {
    id: u64,
    window_start: Duration,
    rows: Vec<(CounterKey, CounterRow)>,
    size_bytes: usize,
}

fn window_size(rows: &[(CounterKey, CounterRow)]) -> usize {
    let wire: Vec<WireCounter> = rows
        .iter()
        .map(|(key, row)| WireCounter::from_row(key, row, 0))
        .collect();
    serde_json::to_string(&wire).map_or(0, |body| body.len())
}

/// The Python SDK's `_folded_counter_key`: `error_class → unknown`, and
/// optionally `endpoint → inference_other`.
fn folded_key(key: &CounterKey, endpoint: bool) -> CounterKey {
    CounterKey {
        endpoint: if endpoint {
            Endpoint::InferenceOther
        } else {
            key.endpoint
        },
        error_class: Some(ErrorClass::Unknown),
        ..key.clone()
    }
}

fn same_but_error_class(a: &CounterKey, b: &CounterKey) -> bool {
    a.level == b.level
        && a.endpoint == b.endpoint
        && a.streaming == b.streaming
        && a.host == b.host
        && a.outcome == b.outcome
        && a.http_status_class == b.http_status_class
        && a.timeout_phase == b.timeout_phase
        && a.timeout_floor_met == b.timeout_floor_met
        && a.provider_pinned == b.provider_pinned
}

fn same_but_error_class_and_endpoint(a: &CounterKey, b: &CounterKey) -> bool {
    a.level == b.level
        && a.streaming == b.streaming
        && a.host == b.host
        && a.outcome == b.outcome
        && a.http_status_class == b.http_status_class
        && a.timeout_phase == b.timeout_phase
        && a.timeout_floor_met == b.timeout_floor_met
        && a.provider_pinned == b.provider_pinned
}

/// The items one flush put on the wire, so a 202 can retire exactly them —
/// by identity, because records keep arriving while the `POST` is in
/// flight.
struct Selected {
    body: String,
    event_ids: Vec<u64>,
    counter_refs: Vec<(u64, CounterKey)>,
    dropped: u64,
}

#[derive(Debug)]
#[allow(clippy::struct_excessive_bools)] // Mirrors Python's orthogonal bounded reporter flags.
struct State {
    success_sample_rate: f64,
    flush_interval: Duration,
    events: VecDeque<BufferedEvent>,
    events_size_bytes: usize,
    next_event_id: u64,
    current_window_start: Option<Duration>,
    /// Insertion-ordered, like the Python `dict`: the fold ladder's last
    /// resort is the FIRST inserted key.
    current_counters: Vec<(CounterKey, CounterRow)>,
    closed_windows: VecDeque<CounterWindow>,
    next_window_id: u64,
    retained_window_bytes: usize,
    dropped_since_last: u64,
    instance_id: String,
    seq: u64,
    backoff: Duration,
    backoff_until: Duration,
    paused_until: Duration,
    next_flush_at: Duration,
    /// After any flush attempt, even an urgent backlog waits one full flush
    /// interval before the next batch (§6.2 backlog drain spacing).
    urgent_not_before: Duration,
    urgent_flush: bool,
    disabled: bool,
    closed: bool,
    worker_started: bool,
}

impl State {
    fn minute_start(now: Duration) -> Duration {
        Duration::from_secs(now.as_secs() / 60 * 60)
    }

    fn roll_window(&mut self, now: Duration, retention_bytes: usize) {
        let minute_start = Self::minute_start(now);
        match self.current_window_start {
            None => self.current_window_start = Some(minute_start),
            Some(current) if minute_start > current => {
                self.close_current_window(now, retention_bytes);
                self.current_window_start = Some(minute_start);
            }
            Some(_) => {}
        }
    }

    fn close_current_window(&mut self, now: Duration, retention_bytes: usize) {
        let Some(window_start) = self.current_window_start else {
            return;
        };
        if self.current_counters.is_empty() {
            return;
        }
        let rows = std::mem::take(&mut self.current_counters);
        let size_bytes = window_size(&rows);
        self.closed_windows.push_back(CounterWindow {
            id: self.next_window_id,
            window_start,
            rows,
            size_bytes,
        });
        self.next_window_id += 1;
        self.retained_window_bytes += size_bytes;
        self.current_window_start = Some(Self::minute_start(now));
        self.prune_windows(now, retention_bytes);
    }

    fn drop_window(&mut self, window: &CounterWindow) {
        self.retained_window_bytes = self.retained_window_bytes.saturating_sub(window.size_bytes);
        self.dropped_since_last = self
            .dropped_since_last
            .saturating_add(u64::try_from(window.rows.len()).unwrap_or(u64::MAX));
    }

    fn prune_windows(&mut self, now: Duration, retention_bytes: usize) {
        let retention = Duration::from_secs(TELEMETRY_RETENTION_SECONDS);
        while let Some(oldest) = self.closed_windows.front() {
            if now.saturating_sub(oldest.window_start) > retention {
                let window = self.closed_windows.pop_front();
                if let Some(window) = window {
                    self.drop_window(&window);
                }
            } else {
                break;
            }
        }
        while self.retained_window_bytes > retention_bytes {
            let Some(window) = self.closed_windows.pop_front() else {
                break;
            };
            self.drop_window(&window);
        }
    }

    fn has_key(&self, key: &CounterKey) -> bool {
        self.current_counters
            .iter()
            .any(|(existing, _)| existing == key)
    }

    fn refold(&mut self, position: usize, endpoint: bool) -> CounterKey {
        let (existing, previous) = self.current_counters.remove(position);
        let target = folded_key(&existing, endpoint);
        let mut merged = CounterRow::default();
        merge_counter_increment(&mut merged, &previous);
        self.current_counters.push((target.clone(), merged));
        target
    }

    /// The Python SDK's `_counter_target_locked`, step for step: the key
    /// itself while under the cap; else the error-folded key if present;
    /// else refold an error-compatible existing key; else the
    /// endpoint-folded key if present; else refold an endpoint-compatible
    /// existing key; else the first existing key. Counts stay exact, only
    /// coarser, and nothing is ever dropped by folding.
    fn counter_target(&mut self, key: &CounterKey) -> CounterKey {
        if self.has_key(key) || self.current_counters.len() < TELEMETRY_MAX_WINDOW_KEYS {
            return key.clone();
        }
        let error_folded = folded_key(key, false);
        if self.has_key(&error_folded) {
            return error_folded;
        }
        if let Some(position) = self
            .current_counters
            .iter()
            .position(|(existing, _)| same_but_error_class(existing, key))
        {
            return self.refold(position, false);
        }
        let endpoint_folded = folded_key(key, true);
        if self.has_key(&endpoint_folded) {
            return endpoint_folded;
        }
        if let Some(position) = self
            .current_counters
            .iter()
            .position(|(existing, _)| same_but_error_class_and_endpoint(existing, key))
        {
            return self.refold(position, true);
        }
        self.current_counters
            .first()
            .map_or_else(|| key.clone(), |(existing, _)| existing.clone())
    }

    fn merge_counters(&mut self, counters: Vec<(CounterKey, CounterRow)>) {
        for (key, increment) in counters {
            let target = self.counter_target(&key);
            if let Some((_, row)) = self
                .current_counters
                .iter_mut()
                .find(|(existing, _)| *existing == target)
            {
                merge_counter_increment(row, &increment);
            } else {
                let mut row = CounterRow::default();
                merge_counter_increment(&mut row, &increment);
                self.current_counters.push((target, row));
            }
        }
    }

    /// Drops the oldest buffered success, or the oldest event when every
    /// buffered event is a failure (§6.2), counting the drop.
    fn drop_buffered_event(&mut self) {
        let index = self
            .events
            .iter()
            .position(|buffered| buffered.ok)
            .unwrap_or(0);
        if let Some(dropped) = self.events.remove(index) {
            self.events_size_bytes = self
                .events_size_bytes
                .saturating_sub(dropped.estimated_bytes);
            self.dropped_since_last = self.dropped_since_last.saturating_add(1);
        }
    }

    fn append_event(&mut self, wire: WireEvent, now: Duration) {
        if self.events.len() >= TELEMETRY_MAX_EVENTS {
            self.drop_buffered_event();
        }
        let estimated_bytes =
            serde_json::to_string(&wire).map_or(FALLBACK_EVENT_BYTES, |body| body.len());
        let ok = wire.final_outcome == "ok";
        self.events.push_back(BufferedEvent {
            id: self.next_event_id,
            wire,
            completed_at: now,
            estimated_bytes,
            ok,
        });
        self.next_event_id += 1;
        self.events_size_bytes += estimated_bytes;
    }

    fn urgent(&self) -> bool {
        self.events.len() >= URGENT_EVENT_COUNT
            || self.events_size_bytes
                + self.retained_window_bytes
                + self.current_counters.len() * OPEN_COUNTER_ESTIMATE_BYTES
                >= BATCH_TRIGGER_BYTES
    }

    fn gate(&self) -> Duration {
        self.paused_until.max(self.backoff_until)
    }

    /// Builds the next batch: up to 100 events (oldest first) and up to 200
    /// counters from the closed windows (oldest first), then trims from the
    /// tail until the body fits in 65 536 bytes. `None` when nothing is
    /// waiting.
    fn select_batch(
        &mut self,
        now: Duration,
        retention_bytes: usize,
        sdk: &SdkIdentity,
    ) -> Option<Selected> {
        self.roll_window(now, retention_bytes);
        self.close_current_window(now, retention_bytes);
        self.prune_windows(now, retention_bytes);
        let mut event_ids = Vec::new();
        let mut events = Vec::new();
        for buffered in self.events.iter().take(TELEMETRY_MAX_BATCH_EVENTS) {
            events.push(
                buffered
                    .wire
                    .aged(millis(now.saturating_sub(buffered.completed_at))),
            );
            event_ids.push(buffered.id);
        }
        let mut counter_refs = Vec::new();
        let mut counters = Vec::new();
        'windows: for window in &self.closed_windows {
            let age_ms = millis(now.saturating_sub(window.window_start));
            for (key, row) in &window.rows {
                if counters.len() >= TELEMETRY_MAX_BATCH_COUNTERS {
                    break 'windows;
                }
                counters.push(WireCounter::from_row(key, row, age_ms));
                counter_refs.push((window.id, key.clone()));
            }
        }
        if events.is_empty() && counters.is_empty() {
            return None;
        }
        let dropped = self.dropped_since_last;
        let mut batch = WireBatch::new(
            hex_token(16),
            self.instance_id.clone(),
            self.seq,
            sdk.clone(),
        );
        batch.dropped_since_last = dropped;
        batch.events = events;
        batch.counters = counters;
        self.seq += 1;
        loop {
            let body = serde_json::to_string(&batch).ok()?;
            if body.len() <= MAX_BATCH_BYTES {
                return Some(Selected {
                    body,
                    event_ids,
                    counter_refs,
                    dropped,
                });
            }
            if batch.events.pop().is_some() {
                event_ids.pop();
            } else if batch.counters.pop().is_some() {
                counter_refs.pop();
            } else {
                return None;
            }
        }
    }

    fn remove_selected(&mut self, event_ids: &[u64], counter_refs: &[(u64, CounterKey)]) {
        let ids: HashSet<u64> = event_ids.iter().copied().collect();
        self.events.retain(|buffered| !ids.contains(&buffered.id));
        self.events_size_bytes = self
            .events
            .iter()
            .map(|buffered| buffered.estimated_bytes)
            .sum();
        let mut changed = HashSet::new();
        for (window_id, key) in counter_refs {
            if let Some(window) = self
                .closed_windows
                .iter_mut()
                .find(|window| window.id == *window_id)
            {
                if let Some(position) = window.rows.iter().position(|(existing, _)| existing == key)
                {
                    window.rows.remove(position);
                    changed.insert(*window_id);
                }
            }
        }
        for window in self
            .closed_windows
            .iter_mut()
            .filter(|window| changed.contains(&window.id))
        {
            self.retained_window_bytes =
                self.retained_window_bytes.saturating_sub(window.size_bytes);
            window.size_bytes = if window.rows.is_empty() {
                0
            } else {
                window_size(&window.rows)
            };
            self.retained_window_bytes += window.size_bytes;
        }
        self.closed_windows.retain(|window| !window.rows.is_empty());
    }

    fn set_backoff(&mut self, now: Duration, retry_after: Option<Duration>) {
        let mut delay = self.backoff;
        if let Some(retry_after) = retry_after {
            delay = delay.max(retry_after);
        }
        let ceiling = Duration::from_secs_f64(TELEMETRY_BACKOFF_MAX_SECONDS);
        self.backoff_until = now + delay.min(ceiling);
        self.backoff = (self.backoff * 2)
            .max(Duration::from_secs_f64(TELEMETRY_BACKOFF_MIN_SECONDS))
            .min(ceiling);
    }

    fn disable(&mut self) {
        self.disabled = true;
        self.events.clear();
        self.events_size_bytes = 0;
        self.current_counters.clear();
        self.closed_windows.clear();
        self.retained_window_bytes = 0;
        self.dropped_since_last = 0;
    }

    /// Applies a 202 `policy` only where it reduces volume (§4): a lower
    /// sample rate, a longer flush interval, a bounded pause.
    fn apply_policy(&mut self, policy: &Value, now: Duration) {
        if let Some(rate) = policy.get("success_sample_rate").and_then(float_value) {
            if rate >= 0.0 && rate < self.success_sample_rate {
                self.success_sample_rate = rate;
            }
        }
        if let Some(seconds) = policy.get("flush_seconds").and_then(float_value) {
            if seconds > self.flush_interval.as_secs_f64() {
                self.flush_interval =
                    Duration::from_secs_f64(seconds.min(TELEMETRY_BACKOFF_MAX_SECONDS));
            }
        }
        if let Some(seconds) = policy.get("pause_seconds").and_then(float_value) {
            if (0.0..=MAX_PAUSE_SECONDS).contains(&seconds) {
                self.paused_until = self
                    .paused_until
                    .max(now + Duration::from_secs_f64(seconds));
            }
        }
    }
}

struct Inner {
    endpoint: Url,
    api_key: Option<String>,
    workspace_id: Option<String>,
    sdk: SdkIdentity,
    debug: bool,
    echo: DebugEcho,
    retention_bytes: usize,
    clock: Arc<dyn Clock>,
    sampler: Arc<dyn SampleDraw>,
    transport: OwnedTransport,
    state: Mutex<State>,
    wake: Arc<Notify>,
    flush_lock: tokio::sync::Mutex<()>,
    http: OnceLock<Option<reqwest::Client>>,
}

impl fmt::Debug for Inner {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TelemetryReporter")
            .field("endpoint", &self.endpoint.as_str())
            .finish_non_exhaustive()
    }
}

impl Inner {
    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn sample_reason(&self, event: &RequestEvent, rate: f64) -> Option<(SampleReason, f64)> {
        if !event.final_outcome.is_ok() {
            return Some((SampleReason::Failure, 1.0));
        }
        if event.attempts.len() > 1 || event.failover_used {
            return Some((SampleReason::Retried, 1.0));
        }
        if event.total_ms > SLOW_MS {
            return Some((SampleReason::Slow, 1.0));
        }
        let draw = self.sampler.draw();
        if rate <= 0.0 || draw >= rate {
            return None;
        }
        Some((SampleReason::Random, rate))
    }

    /// The reporter's own client, built on first use — never the engine's
    /// transport and never a caller-injected one.
    fn http(&self) -> Option<&reqwest::Client> {
        self.http
            .get_or_init(|| self.transport.build(SEND_TIMEOUT))
            .as_ref()
    }

    fn echo(&self, line: &str) {
        if self.debug {
            (self.echo)(line);
        }
    }

    fn retry_after(headers: &HeaderMap) -> Option<Duration> {
        let seconds = headers
            .get("retry-after")?
            .to_str()
            .ok()?
            .trim()
            .parse::<f64>()
            .ok()?;
        (seconds.is_finite() && (0.0..=MAX_RETRY_AFTER_SECONDS).contains(&seconds))
            .then(|| Duration::from_secs_f64(seconds))
    }

    fn handle_response(
        &self,
        status: u16,
        headers: &HeaderMap,
        body: &[u8],
        now: Duration,
        selected: &Selected,
    ) {
        let mut state = self.lock();
        let off = headers
            .get("x-tr-telemetry")
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value.trim().eq_ignore_ascii_case("off"));
        if off {
            state.disable();
            return;
        }
        match status {
            202 => {
                state.remove_selected(&selected.event_ids, &selected.counter_refs);
                state.dropped_since_last =
                    state.dropped_since_last.saturating_sub(selected.dropped);
                state.backoff = Duration::from_secs_f64(TELEMETRY_BACKOFF_MIN_SECONDS);
                state.backoff_until = Duration::ZERO;
                if let Some(policy) = serde_json::from_slice::<Value>(body)
                    .ok()
                    .and_then(|payload| payload.get("policy").cloned())
                    .filter(Value::is_object)
                {
                    state.apply_policy(&policy, now);
                }
            }
            400 | 401 | 403 | 404 | 410 => state.disable(),
            413 => {
                state.remove_selected(&selected.event_ids, &selected.counter_refs);
                let sent = selected.event_ids.len() + selected.counter_refs.len();
                state.dropped_since_last = state
                    .dropped_since_last
                    .saturating_add(u64::try_from(sent).unwrap_or(u64::MAX));
            }
            _ => state.set_backoff(now, Self::retry_after(headers)),
        }
    }

    /// One flush: select, echo when debugging, `POST` once, apply the
    /// response. Returns whether the batch was accepted. Never retries.
    async fn flush_with(&self, http: &reqwest::Client, timeout: Option<Duration>) -> bool {
        let _serialised = self.flush_lock.lock().await;
        let now = self.clock.now();
        {
            let state = self.lock();
            if state.disabled || now < state.gate() {
                return false;
            }
        }
        let Some(api_key) = self.api_key.as_deref().filter(|key| !key.is_empty()) else {
            return false;
        };
        let selected = {
            let mut state = self.lock();
            state.select_batch(now, self.retention_bytes, &self.sdk)
        };
        let Some(selected) = selected else {
            return false;
        };
        self.echo(&format!("trustedrouter telemetry batch: {}", selected.body));
        let mut request = http
            .post(self.endpoint.clone())
            .header(AUTHORIZATION, format!("Bearer {api_key}"))
            .header(USER_AGENT, sdk_user_agent())
            .header(CONTENT_TYPE, "application/json");
        if let Some(workspace) = self
            .workspace_id
            .as_deref()
            .filter(|value| !value.is_empty())
        {
            request = request.header("x-trustedrouter-workspace", workspace);
        }
        if let Some(timeout) = timeout {
            request = request.timeout(timeout.max(Duration::from_millis(1)));
        }
        let response = match request.body(selected.body.clone()).send().await {
            Ok(response) => response,
            Err(error) => {
                self.echo(&format!("trustedrouter telemetry send failed: {error}"));
                self.lock().set_backoff(self.clock.now(), None);
                return false;
            }
        };
        let status = response.status().as_u16();
        let headers = response.headers().clone();
        let body = response
            .bytes()
            .await
            .map(|bytes| bytes.to_vec())
            .unwrap_or_default();
        self.echo(&format!("trustedrouter telemetry response: {status}"));
        self.handle_response(status, &headers, &body, self.clock.now(), &selected);
        status == 202
    }

    /// The single background worker. Holds only a [`Weak`] reference so
    /// the reporter's `Drop` is never blocked by its own worker.
    async fn worker(weak: Weak<Self>, wake: Arc<Notify>) {
        loop {
            let Some(inner) = weak.upgrade() else {
                return;
            };
            let now = inner.clock.now();
            let wait = {
                let mut state = inner.lock();
                if state.closed || state.disabled {
                    return;
                }
                let gate = state.gate();
                let deadline = state.next_flush_at.max(gate);
                if state.urgent_flush && now >= gate && now >= state.urgent_not_before {
                    state.urgent_flush = false;
                    None
                } else if now < deadline {
                    Some(deadline.saturating_sub(now))
                } else {
                    None
                }
            };
            if let Some(wait) = wait {
                drop(inner);
                tokio::select! {
                    () = wake.notified() => {}
                    () = tokio::time::sleep(wait) => {}
                }
                continue;
            }
            if let Some(http) = inner.http() {
                inner.flush_with(http, None).await;
            } else {
                inner.lock().set_backoff(inner.clock.now(), None);
            }
            let mut state = inner.lock();
            state.next_flush_at = inner.clock.now() + state.flush_interval;
            state.urgent_not_before = state.next_flush_at;
        }
    }
}

/// The beacon reporter. Cloneable handles share one bounded state; see the
/// module docs for the lifecycle.
pub(crate) struct TelemetryReporter {
    inner: Arc<Inner>,
}

impl fmt::Debug for TelemetryReporter {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.inner.fmt(formatter)
    }
}

impl TelemetryReporter {
    pub(crate) fn new(config: ReporterConfig) -> Self {
        let endpoint = config
            .control_base_url
            .join(DEFAULT_TELEMETRY_PATH.trim_start_matches('/'))
            .unwrap_or(config.control_base_url);
        let flush_interval = normalise_flush_interval(config.flush_interval);
        let state = State {
            success_sample_rate: normalise_sample_rate(config.success_sample_rate),
            flush_interval,
            events: VecDeque::new(),
            events_size_bytes: 0,
            next_event_id: 0,
            current_window_start: None,
            current_counters: Vec::new(),
            closed_windows: VecDeque::new(),
            next_window_id: 0,
            retained_window_bytes: 0,
            dropped_since_last: 0,
            instance_id: hex_token(8),
            seq: 0,
            backoff: Duration::from_secs_f64(TELEMETRY_BACKOFF_MIN_SECONDS),
            backoff_until: Duration::ZERO,
            paused_until: Duration::ZERO,
            next_flush_at: Duration::ZERO,
            urgent_not_before: Duration::ZERO,
            urgent_flush: false,
            disabled: false,
            closed: false,
            worker_started: false,
        };
        Self {
            inner: Arc::new(Inner {
                endpoint,
                api_key: config.api_key,
                workspace_id: config.workspace_id,
                sdk: config.sdk,
                debug: config.debug,
                echo: config.echo,
                retention_bytes: config.retention_bytes,
                clock: config.clock,
                sampler: config.sampler,
                transport: config.transport,
                state: Mutex::new(state),
                wake: Arc::new(Notify::new()),
                flush_lock: tokio::sync::Mutex::new(()),
                http: OnceLock::new(),
            }),
        }
    }

    /// Starts the worker on the current runtime, once. Without a current
    /// runtime nothing starts (see the module docs); the next record tries
    /// again.
    fn start_worker(&self, state: &mut State, now: Duration) {
        if state.worker_started || state.disabled || state.closed {
            return;
        }
        let Ok(handle) = tokio::runtime::Handle::try_current() else {
            return;
        };
        state.next_flush_at = now + state.flush_interval;
        state.worker_started = true;
        let weak = Arc::downgrade(&self.inner);
        let wake = Arc::clone(&self.inner.wake);
        handle.spawn(Inner::worker(weak, wake));
    }

    /// One flush on the reporter's own client, for deterministic tests and
    /// callers who want delivery before continuing.
    #[cfg(test)]
    pub(crate) async fn flush_once(&self, timeout: Option<Duration>) -> bool {
        match self.inner.http() {
            Some(http) => self.inner.flush_with(http, timeout).await,
            None => false,
        }
    }

    /// Stops the worker and performs the single final flush, bounded to
    /// `timeout`, on a dedicated thread with its own runtime.
    pub(crate) fn close(&self, timeout: Duration) {
        {
            let mut state = self.inner.lock();
            if state.closed {
                return;
            }
            state.closed = true;
        }
        self.inner.wake.notify_one();
        let inner = Arc::clone(&self.inner);
        let (done, finished) = std::sync::mpsc::channel::<()>();
        let spawned = std::thread::Builder::new()
            .name("trustedrouter-telemetry-close".to_owned())
            .spawn(move || {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build();
                if let Ok(runtime) = runtime {
                    runtime.block_on(async {
                        // A fresh single-shot client: the worker's client may
                        // be bound to a runtime that is itself shutting down.
                        if let Some(http) = inner.transport.build(timeout) {
                            inner.flush_with(&http, Some(timeout)).await;
                        }
                    });
                }
                let _ = done.send(());
            });
        if spawned.is_ok() {
            let _ = finished.recv_timeout(timeout);
        }
    }

    /// Events waiting in the buffer.
    #[cfg(test)]
    pub(crate) fn buffered_events(&self) -> usize {
        self.inner.lock().events.len()
    }

    #[cfg(test)]
    pub(crate) fn dropped_since_last(&self) -> u64 {
        self.inner.lock().dropped_since_last
    }

    #[cfg(test)]
    pub(crate) fn is_disabled(&self) -> bool {
        self.inner.lock().disabled
    }

    #[cfg(test)]
    pub(crate) fn worker_started(&self) -> bool {
        self.inner.lock().worker_started
    }

    #[cfg(test)]
    pub(crate) fn success_sample_rate(&self) -> f64 {
        self.inner.lock().success_sample_rate
    }

    #[cfg(test)]
    pub(crate) fn flush_interval(&self) -> Duration {
        self.inner.lock().flush_interval
    }

    /// The open window's rows, in insertion order.
    #[cfg(test)]
    pub(crate) fn current_counters(&self) -> Vec<(CounterKey, CounterRow)> {
        self.inner.lock().current_counters.clone()
    }

    /// `(window_start, rows)` for every closed window, oldest first.
    #[cfg(test)]
    pub(crate) fn closed_windows(&self) -> Vec<(Duration, usize)> {
        self.inner
            .lock()
            .closed_windows
            .iter()
            .map(|window| (window.window_start, window.rows.len()))
            .collect()
    }

    #[cfg(test)]
    pub(crate) fn retained_window_bytes(&self) -> usize {
        self.inner.lock().retained_window_bytes
    }

    /// The buffered events' `(model, final_outcome)` pairs, oldest first.
    #[cfg(test)]
    pub(crate) fn buffered_event_labels(&self) -> Vec<(Option<String>, &'static str)> {
        self.inner
            .lock()
            .events
            .iter()
            .map(|buffered| (buffered.wire.model.clone(), buffered.wire.final_outcome))
            .collect()
    }

    /// The buffered events' sample reasons and rates, oldest first.
    #[cfg(test)]
    pub(crate) fn buffered_samples(&self) -> Vec<(&'static str, f64)> {
        self.inner
            .lock()
            .events
            .iter()
            .map(|buffered| (buffered.wire.sample_reason, buffered.wire.sample_rate))
            .collect()
    }

    /// Prunes retained windows as of `now` (the 24 h expiry).
    #[cfg(test)]
    pub(crate) fn prune_now(&self) {
        let now = self.inner.clock.now();
        let retention_bytes = self.inner.retention_bytes;
        self.inner.lock().prune_windows(now, retention_bytes);
    }
}

impl TelemetrySink for TelemetryReporter {
    fn on_request(&self, event: RequestEvent, counters: Vec<(CounterKey, CounterRow)>) {
        let now = self.inner.clock.now();
        let rate = self.inner.lock().success_sample_rate;
        let reason = self.inner.sample_reason(&event, rate);
        let sampled = reason.and_then(|(reason, rate)| WireEvent::from_event(&event, reason, rate));
        let invalid_sample = reason.is_some() && sampled.is_none();
        let mut state = self.inner.lock();
        if state.disabled || state.closed {
            return;
        }
        state.roll_window(now, self.inner.retention_bytes);
        state.merge_counters(counters);
        if invalid_sample {
            state.dropped_since_last = state.dropped_since_last.saturating_add(1);
        }
        if let Some(wire) = sampled {
            state.append_event(wire, now);
        }
        self.start_worker(&mut state, now);
        if state.urgent() {
            state.urgent_flush = true;
            self.inner.wake.notify_one();
        }
    }
}

impl Drop for TelemetryReporter {
    fn drop(&mut self) {
        self.close(CLOSE_TIMEOUT);
    }
}

/// In-memory sink for tests: records every finished call verbatim.
#[cfg(test)]
type RecordedCall = (RequestEvent, Vec<(CounterKey, CounterRow)>);

#[cfg(test)]
#[derive(Debug, Default)]
pub(crate) struct RecordingSink {
    calls: Mutex<Vec<RecordedCall>>,
}

#[cfg(test)]
impl RecordingSink {
    pub(crate) fn events(&self) -> Vec<RequestEvent> {
        self.calls
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .map(|(event, _)| event.clone())
            .collect()
    }

    pub(crate) fn counters(&self) -> Vec<Vec<(CounterKey, CounterRow)>> {
        self.calls
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .map(|(_, counters)| counters.clone())
            .collect()
    }
}

#[cfg(test)]
impl TelemetrySink for RecordingSink {
    fn on_request(&self, event: RequestEvent, counters: Vec<(CounterKey, CounterRow)>) {
        self.calls
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push((event, counters));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::{CallOptions, Client, Plane};
    use crate::telemetry::{
        AttemptOutcome, AttemptRecord, FinalOutcome, Host, HttpStatusClass, LatencyBucket, Level,
        ShouldRetry, TimeoutPhase,
    };
    use crate::types::{ChatRequest, ResponsesRequest};
    use futures_util::StreamExt;
    use http::Method;
    use serde_json::json;
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, Request, ResponseTemplate};

    #[derive(Debug)]
    struct ManualClock(AtomicU64);

    impl ManualClock {
        fn new(seconds: u64) -> Self {
            Self(AtomicU64::new(seconds * 1_000))
        }

        fn advance(&self, seconds: u64) {
            self.0.fetch_add(seconds * 1_000, Ordering::SeqCst);
        }
    }

    impl Clock for ManualClock {
        fn now(&self) -> Duration {
            Duration::from_millis(self.0.load(Ordering::SeqCst))
        }
    }

    #[derive(Debug)]
    struct FixedDraw(f64);

    impl SampleDraw for FixedDraw {
        fn draw(&self) -> f64 {
            self.0
        }
    }

    fn config(clock: Arc<dyn Clock>, draw: f64) -> ReporterConfig {
        let mut config = ReporterConfig::new(
            Url::parse("http://127.0.0.1:1/v1/").expect("test URL"),
            None,
            crate::telemetry::wire::sdk_identity(),
        );
        config.clock = clock;
        config.sampler = Arc::new(FixedDraw(draw));
        config.flush_interval = Duration::from_secs(600);
        config
    }

    fn attempt(outcome: AttemptOutcome) -> AttemptRecord {
        AttemptRecord {
            index: 0,
            host: Host::Apex,
            outcome,
            http_status: Some(if outcome == AttemptOutcome::Ok {
                200
            } else {
                503
            }),
            error_class: None,
            error_source: None,
            should_retry: ShouldRetry::Absent,
            retry_after_ms: None,
            elapsed_ms: 25,
            ttfb_ms: Some(20),
            request_id: Some("rlog_0123456789abcdef0123456789abcdef".to_owned()),
            moved: false,
            phase: TimeoutPhase::None,
        }
    }

    fn event(outcome: AttemptOutcome, model: &str) -> RequestEvent {
        let attempt = attempt(outcome);
        RequestEvent {
            endpoint: Endpoint::Responses,
            method: Method::POST,
            streaming: false,
            provider_pinned: false,
            model: Some(model.to_owned()),
            attempts: vec![attempt.clone()],
            final_outcome: FinalOutcome::Outcome(outcome),
            final_http_status: attempt.http_status,
            total_ms: 25,
            ttft_ms: None,
            failover_used: false,
            timeout_phase: TimeoutPhase::None,
            configured_timeout_ms: None,
        }
    }

    fn key() -> CounterKey {
        CounterKey {
            level: Level::Request,
            endpoint: Endpoint::Responses,
            streaming: false,
            host: Host::Apex,
            outcome: AttemptOutcome::Ok,
            error_class: None,
            http_status_class: HttpStatusClass::Success,
            timeout_phase: TimeoutPhase::None,
            timeout_floor_met: false,
            provider_pinned: false,
        }
    }

    fn row() -> CounterRow {
        CounterRow {
            requests: 1,
            attempts: 1,
            failover_used: 0,
            first_attempt_success: 1,
            total_ms_hist: BTreeMap::from([(LatencyBucket::Lt100, 1)]),
            first_event_ms_hist: BTreeMap::from([(LatencyBucket::Lt100, 1)]),
        }
    }

    fn disable(reporter: &TelemetryReporter) {
        reporter.inner.lock().disable();
    }

    #[test]
    fn sampling_and_event_eviction_match_python() {
        let clock: Arc<dyn Clock> = Arc::new(ManualClock::new(1));
        let mut zero = config(Arc::clone(&clock), 0.5);
        zero.success_sample_rate = 0.0;
        let reporter = TelemetryReporter::new(zero);
        reporter.on_request(event(AttemptOutcome::HttpError, "failure"), Vec::new());
        reporter.on_request(event(AttemptOutcome::Ok, "unsampled"), Vec::new());
        assert_eq!(reporter.buffered_events(), 1);
        assert_eq!(reporter.buffered_samples(), vec![("failure", 1.0)]);

        let mut all = config(clock, 0.0);
        all.success_sample_rate = 1.0;
        let bounded = TelemetryReporter::new(all);
        bounded.on_request(event(AttemptOutcome::HttpError, "old-failure"), Vec::new());
        for index in 0..999 {
            bounded.on_request(
                event(AttemptOutcome::Ok, &format!("success-{index}")),
                Vec::new(),
            );
        }
        bounded.on_request(event(AttemptOutcome::HttpError, "new-failure"), Vec::new());
        let labels = bounded.buffered_event_labels();
        assert_eq!(labels.len(), TELEMETRY_MAX_EVENTS);
        assert_eq!(labels[0].0.as_deref(), Some("old-failure"));
        assert!(!labels
            .iter()
            .any(|(model, _)| model.as_deref() == Some("success-0")));
        assert_eq!(bounded.dropped_since_last(), 1);
    }

    #[test]
    #[allow(clippy::too_many_lines)] // One ordered scenario pins all three fold fallbacks.
    fn counter_cap_uses_the_complete_python_fold_ladder_without_drops() {
        let reporter = TelemetryReporter::new(config(Arc::new(ManualClock::new(1)), 1.0));
        let endpoints = [
            Endpoint::ChatCompletions,
            Endpoint::Messages,
            Endpoint::Responses,
            Endpoint::Embeddings,
            Endpoint::Images,
            Endpoint::Videos,
            Endpoint::Models,
            Endpoint::Fusion,
            Endpoint::ControlOther,
            Endpoint::InferenceOther,
        ];
        let hosts = [
            Host::Apex,
            Host::Ally,
            Host::Uptime,
            Host::UsCentral1,
            Host::UsEast4,
            Host::EuropeWest4,
            Host::Control,
            Host::Custom,
        ];
        let outcomes = [
            AttemptOutcome::Ok,
            AttemptOutcome::HttpError,
            AttemptOutcome::TransportError,
            AttemptOutcome::Timeout,
            AttemptOutcome::StreamBroken,
            AttemptOutcome::Aborted,
        ];
        let mut increments = Vec::new();
        for index in 0..TELEMETRY_MAX_WINDOW_KEYS {
            let mut item = key();
            item.endpoint = endpoints[index % endpoints.len()];
            item.host = hosts[index / endpoints.len() % hosts.len()];
            item.outcome = outcomes[index / (endpoints.len() * hosts.len()) % outcomes.len()];
            item.error_class = Some(ErrorClass::Dns);
            increments.push((item, row()));
        }
        let first = increments[0].0.clone();
        reporter.inner.lock().merge_counters(increments);
        let mut overflow = first;
        overflow.error_class = Some(ErrorClass::Tls);
        reporter
            .inner
            .lock()
            .merge_counters(vec![(overflow, row())]);
        let counters = reporter.current_counters();
        assert_eq!(counters.len(), TELEMETRY_MAX_WINDOW_KEYS);
        assert_eq!(
            counters.iter().map(|(_, row)| row.requests).sum::<u64>(),
            257
        );
        assert!(counters.iter().any(|(key, row)| {
            key.error_class == Some(ErrorClass::Unknown) && row.requests == 2
        }));
        assert_eq!(reporter.dropped_since_last(), 0);

        let endpoint_fold = TelemetryReporter::new(config(Arc::new(ManualClock::new(1)), 1.0));
        let mut compatible = key();
        compatible.endpoint = Endpoint::ChatCompletions;
        compatible.error_class = Some(ErrorClass::Dns);
        let mut seeded = vec![(compatible.clone(), row())];
        for index in 1..TELEMETRY_MAX_WINDOW_KEYS {
            let mut item = key();
            item.level = Level::Attempt;
            item.endpoint = endpoints[index % endpoints.len()];
            item.host = hosts[index / endpoints.len() % hosts.len()];
            item.outcome = outcomes[index / (endpoints.len() * hosts.len()) % outcomes.len()];
            item.error_class = Some(if index % 2 == 0 {
                ErrorClass::ConnectError
            } else {
                ErrorClass::Reset
            });
            item.streaming = index % 3 == 0;
            item.provider_pinned = index % 5 == 0;
            seeded.push((item, row()));
        }
        endpoint_fold.inner.lock().merge_counters(seeded);
        let mut novel = compatible;
        novel.endpoint = Endpoint::Responses;
        novel.error_class = Some(ErrorClass::Tls);
        endpoint_fold
            .inner
            .lock()
            .merge_counters(vec![(novel, row())]);
        assert!(endpoint_fold.current_counters().iter().any(|(key, row)| {
            key.level == Level::Request
                && key.endpoint == Endpoint::InferenceOther
                && key.error_class == Some(ErrorClass::Unknown)
                && row.requests == 2
        }));

        let fallback = TelemetryReporter::new(config(Arc::new(ManualClock::new(1)), 1.0));
        fallback.inner.lock().merge_counters(
            (0..TELEMETRY_MAX_WINDOW_KEYS)
                .map(|index| {
                    let mut item = key();
                    item.endpoint = endpoints[index % endpoints.len()];
                    item.host = hosts[index / endpoints.len() % hosts.len()];
                    item.outcome =
                        outcomes[index / (endpoints.len() * hosts.len()) % outcomes.len()];
                    item.error_class = Some(ErrorClass::Dns);
                    (item, row())
                })
                .collect(),
        );
        let first = fallback.current_counters()[0].0.clone();
        let mut unrelated = key();
        unrelated.level = Level::Attempt;
        unrelated.error_class = Some(ErrorClass::PoolTimeout);
        fallback
            .inner
            .lock()
            .merge_counters(vec![(unrelated, row())]);
        let counters = fallback.current_counters();
        assert_eq!(counters.len(), TELEMETRY_MAX_WINDOW_KEYS);
        assert_eq!(
            counters
                .iter()
                .find(|(candidate, _)| candidate == &first)
                .map(|(_, row)| row.requests),
            Some(2)
        );
        assert_eq!(fallback.dropped_since_last(), 0);
    }

    #[test]
    fn closed_counter_windows_expire_after_24_hours_oldest_first() {
        let clock = Arc::new(ManualClock::new(0));
        let reporter = TelemetryReporter::new(config(clock.clone(), 1.0));
        reporter.on_request(event(AttemptOutcome::Ok, "ignored"), vec![(key(), row())]);
        clock.advance(60);
        reporter.on_request(event(AttemptOutcome::Ok, "ignored"), Vec::new());
        assert_eq!(reporter.closed_windows(), vec![(Duration::ZERO, 1)]);
        assert!(reporter.retained_window_bytes() > 0);
        clock.advance(86_401);
        reporter.prune_now();
        assert!(reporter.closed_windows().is_empty());
        assert_eq!(reporter.retained_window_bytes(), 0);
        assert_eq!(reporter.dropped_since_last(), 1);
    }

    fn network_reporter(server: &MockServer, clock: Arc<dyn Clock>) -> TelemetryReporter {
        let mut config = config(clock, 0.0);
        config.control_base_url = Url::parse(&format!("{}/v1/", server.uri())).expect("mock URL");
        config.api_key = Some("sk-tr-test".to_owned());
        config.workspace_id = Some("ws_test".to_owned());
        TelemetryReporter::new(config)
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn failed_flush_retains_24h_counters_and_retry_after_gates_the_next_post() {
        let server = MockServer::start().await;
        let calls = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&calls);
        Mock::given(method("POST"))
            .and(path("/v1/client-events"))
            .respond_with(move |_request: &Request| {
                if observed.fetch_add(1, Ordering::SeqCst) == 0 {
                    ResponseTemplate::new(429).insert_header("retry-after", "120")
                } else {
                    ResponseTemplate::new(202).set_body_json(json!({"policy": {}}))
                }
            })
            .mount(&server)
            .await;
        let clock = Arc::new(ManualClock::new(0));
        let reporter = network_reporter(&server, clock.clone());
        reporter.on_request(
            event(AttemptOutcome::HttpError, "failure"),
            vec![(key(), row())],
        );
        assert!(!reporter.flush_once(None).await);
        assert_eq!(reporter.closed_windows().len(), 1);
        clock.advance(119);
        assert!(!reporter.flush_once(None).await);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        clock.advance(1);
        assert!(reporter.flush_once(None).await);
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        let requests = server.received_requests().await.expect("request log");
        let body: Value = serde_json::from_slice(&requests[1].body).expect("batch JSON");
        assert_eq!(body["counters"][0]["window_start_age_ms"], 120_000);
        assert!(reporter.closed_windows().is_empty());
        disable(&reporter);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn permanent_errors_off_header_and_policy_only_reduce_volume() {
        let policy = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(202).set_body_json(json!({
                "policy": {"success_sample_rate": 0.005, "flush_seconds": 60, "pause_seconds": 120}
            })))
            .mount(&policy)
            .await;
        let clock = Arc::new(ManualClock::new(0));
        let mut config = config(clock.clone(), 0.0);
        config.control_base_url = Url::parse(&format!("{}/v1/", policy.uri())).expect("mock URL");
        config.api_key = Some("sk-tr-test".to_owned());
        config.success_sample_rate = 0.01;
        config.flush_interval = Duration::from_secs(30);
        let reporter = TelemetryReporter::new(config);
        reporter.on_request(event(AttemptOutcome::HttpError, "failure"), Vec::new());
        assert!(reporter.flush_once(None).await);
        assert!((reporter.success_sample_rate() - 0.005).abs() < f64::EPSILON);
        assert_eq!(reporter.flush_interval(), Duration::from_secs(60));
        reporter.inner.lock().apply_policy(
            &json!({"success_sample_rate": 0.5, "flush_seconds": 1}),
            clock.now(),
        );
        assert!((reporter.success_sample_rate() - 0.005).abs() < f64::EPSILON);
        assert_eq!(reporter.flush_interval(), Duration::from_secs(60));
        reporter.on_request(event(AttemptOutcome::HttpError, "paused"), Vec::new());
        assert!(!reporter.flush_once(None).await);
        clock.advance(120);
        assert!(reporter.flush_once(None).await);
        disable(&reporter);

        for (status, off) in [(400, false), (202, true)] {
            let server = MockServer::start().await;
            let mut response = ResponseTemplate::new(status);
            if off {
                response = response.insert_header("x-tr-telemetry", "off");
            }
            Mock::given(method("POST"))
                .respond_with(response)
                .mount(&server)
                .await;
            let permanent = network_reporter(&server, Arc::new(ManualClock::new(0)));
            permanent.on_request(event(AttemptOutcome::HttpError, "failure"), Vec::new());
            let _ = permanent.flush_once(None).await;
            assert!(permanent.is_disabled());
            assert_eq!(permanent.buffered_events(), 0);
        }

        let too_large = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(413))
            .mount(&too_large)
            .await;
        let dropped = network_reporter(&too_large, Arc::new(ManualClock::new(0)));
        dropped.on_request(
            event(AttemptOutcome::HttpError, "failure"),
            vec![(key(), row())],
        );
        assert!(!dropped.flush_once(None).await);
        assert_eq!(dropped.buffered_events(), 0);
        assert!(dropped.closed_windows().is_empty());
        assert_eq!(dropped.dropped_since_last(), 2);
        disable(&dropped);
    }

    #[tokio::test(flavor = "multi_thread")]
    #[allow(clippy::too_many_lines)] // One wire capture audits every nested schema boundary.
    async fn wire_is_private_schema_bounded_and_uses_the_reporters_own_client() {
        let engine = MockServer::start().await;
        let beacon = MockServer::start().await;
        let secret = "private prompt text that must not leave";
        Mock::given(method("POST"))
            .and(path("/v1/chat/completions"))
            .respond_with(ResponseTemplate::new(401).set_body_json(json!({
                "error": {"message": "bad key", "source": "router"}
            })))
            .mount(&engine)
            .await;
        Mock::given(method("POST"))
            .and(path("/v1/client-events"))
            .respond_with(ResponseTemplate::new(202).set_body_json(json!({"policy": {}})))
            .mount(&beacon)
            .await;
        let mut injected_headers = HeaderMap::new();
        injected_headers.insert("x-user-transport", "injected".parse().expect("header"));
        let injected = reqwest::Client::builder()
            .default_headers(injected_headers)
            .build()
            .expect("injected client");
        let client = Client::builder()
            .api_key("sk-tr-test")
            .workspace_id("ws_test")
            .api_base_url(format!("{}/v1", engine.uri()))
            .control_base_url(format!("{}/v1", beacon.uri()))
            .http_client(injected)
            .telemetry(true)
            .telemetry_sample_rate(1.0)
            .max_retries(0)
            .build()
            .expect("client");
        let result: crate::Result<Value> = client
            .request(
                Plane::Inference,
                Method::POST,
                "/chat/completions",
                Some(json!({"model": secret, "messages": [{"role": "user", "content": secret}]})),
                CallOptions::default(),
            )
            .await;
        assert!(result.is_err());
        drop(client);

        let engine_requests = engine.received_requests().await.expect("engine requests");
        assert_eq!(engine_requests.len(), 1);
        assert!(engine_requests
            .iter()
            .all(|request| request.url.path() != "/v1/client-events"));
        assert_eq!(
            engine_requests[0]
                .headers
                .get("x-user-transport")
                .and_then(|value| value.to_str().ok()),
            Some("injected")
        );
        let beacon_requests = beacon.received_requests().await.expect("beacon requests");
        assert_eq!(beacon_requests.len(), 1);
        assert!(beacon_requests[0].headers.get("x-user-transport").is_none());
        assert_eq!(
            beacon_requests[0]
                .headers
                .get("authorization")
                .and_then(|value| value.to_str().ok()),
            Some("Bearer sk-tr-test")
        );
        assert_eq!(
            beacon_requests[0]
                .headers
                .get("x-trustedrouter-workspace")
                .and_then(|value| value.to_str().ok()),
            Some("ws_test")
        );
        assert!(beacon_requests[0].body.len() <= MAX_BATCH_BYTES);
        let encoded = String::from_utf8_lossy(&beacon_requests[0].body);
        assert!(!encoded.contains(secret));
        assert!(!encoded.contains(&engine.uri()));
        let body: Value = serde_json::from_slice(&beacon_requests[0].body).expect("batch JSON");
        let keys: HashSet<&str> = body
            .as_object()
            .expect("batch object")
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(
            keys,
            HashSet::from([
                "schema_version",
                "batch_id",
                "instance_id",
                "seq",
                "sent_at_ms",
                "sdk",
                "synthetic",
                "dropped_since_last",
                "events",
                "counters"
            ])
        );
        let sdk_keys: HashSet<&str> = body["sdk"]
            .as_object()
            .expect("sdk object")
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(
            sdk_keys,
            HashSet::from(["name", "version", "lang", "runtime", "os", "arch"])
        );
        let event_keys: HashSet<&str> = body["events"][0]
            .as_object()
            .expect("event object")
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(
            event_keys,
            HashSet::from([
                "age_ms",
                "plane",
                "endpoint",
                "method",
                "streaming",
                "provider_pinned",
                "model",
                "attempts",
                "final_outcome",
                "final_http_status",
                "total_ms",
                "ttft_ms",
                "failover_used",
                "timeout_phase",
                "configured_timeout_ms",
                "sample_rate",
                "sample_reason"
            ])
        );
        let attempt_keys: HashSet<&str> = body["events"][0]["attempts"][0]
            .as_object()
            .expect("attempt object")
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(
            attempt_keys,
            HashSet::from([
                "index",
                "host",
                "outcome",
                "http_status",
                "error_class",
                "error_source",
                "retry_after_ms",
                "elapsed_ms",
                "ttfb_ms",
                "request_id",
                "moved"
            ])
        );
        let counter_keys: HashSet<&str> = body["counters"][0]
            .as_object()
            .expect("counter object")
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(
            counter_keys,
            HashSet::from([
                "window_start_age_ms",
                "level",
                "endpoint",
                "streaming",
                "host",
                "outcome",
                "error_class",
                "http_status_class",
                "timeout_phase",
                "timeout_floor_met",
                "provider_pinned",
                "requests",
                "attempts",
                "failover_used",
                "first_attempt_success",
                "total_ms_hist",
                "first_event_ms_hist"
            ])
        );
        assert_eq!(body["events"][0]["attempts"][0]["host"], "custom");
        assert!(body["events"][0]["model"].is_null());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_candidate_over_65536_bytes_is_trimmed_before_the_post() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/client-events"))
            .respond_with(ResponseTemplate::new(202).set_body_json(json!({"policy": {}})))
            .mount(&server)
            .await;
        let mut config = config(Arc::new(ManualClock::new(0)), 0.0);
        config.control_base_url = Url::parse(&format!("{}/v1/", server.uri())).expect("mock URL");
        config.api_key = Some("sk-tr-test".to_owned());
        config.success_sample_rate = 1.0;
        let reporter = TelemetryReporter::new(config);
        // This test drives `flush_once` deterministically. Worker lifecycle is
        // covered separately; suppress it so the urgent threshold cannot
        // race the pre-trim size assertion.
        reporter.inner.lock().worker_started = true;
        for index in 0..100 {
            let mut large = event(AttemptOutcome::HttpError, &"m".repeat(128));
            large.attempts = (0..16)
                .map(|attempt_index| {
                    let mut record = attempt(AttemptOutcome::HttpError);
                    record.index = attempt_index;
                    record.error_class = Some(ErrorClass::ProtocolError);
                    record.should_retry = ShouldRetry::True;
                    record.request_id = Some(format!("rlog_{index:016x}{attempt_index:016x}"));
                    record
                })
                .collect();
            reporter.on_request(large, Vec::new());
        }
        let untrimmed_bytes = {
            let state = reporter.inner.lock();
            let mut candidate = WireBatch::new(
                "0".repeat(32),
                state.instance_id.clone(),
                state.seq,
                reporter.inner.sdk.clone(),
            );
            candidate.events = state
                .events
                .iter()
                .take(TELEMETRY_MAX_BATCH_EVENTS)
                .map(|buffered| buffered.wire.clone())
                .collect();
            serde_json::to_vec(&candidate)
                .expect("candidate JSON")
                .len()
        };
        assert_eq!(MAX_BATCH_BYTES, 65_536);
        assert!(untrimmed_bytes > 65_536, "{untrimmed_bytes}");
        assert!(reporter.flush_once(None).await);
        let requests = server.received_requests().await.expect("request log");
        assert_eq!(requests.len(), 1);
        assert!(requests[0].body.len() <= 65_536);
        let body: Value = serde_json::from_slice(&requests[0].body).expect("batch JSON");
        assert_eq!(body["events"][0]["attempts"][0]["should_retry"], true);
        assert!(
            reporter.buffered_events() > 0,
            "tail was retained for a later batch"
        );
        disable(&reporter);
    }

    fn streaming_client(engine: &str, beacon: &str) -> Client {
        Client::builder()
            .api_key("sk-tr-test")
            .api_base_url(format!("{engine}/v1"))
            .control_base_url(format!("{beacon}/v1"))
            .telemetry(true)
            .telemetry_sample_rate(1.0)
            .max_retries(0)
            .build()
            .expect("streaming client")
    }

    async fn accepted_beacon() -> MockServer {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/client-events"))
            .respond_with(ResponseTemplate::new(202).set_body_json(json!({"policy": {}})))
            .mount(&server)
            .await;
        server
    }

    async fn only_batch(server: &MockServer) -> Value {
        let requests = server.received_requests().await.expect("beacon log");
        assert_eq!(requests.len(), 1);
        serde_json::from_slice(&requests[0].body).expect("batch JSON")
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn real_engine_streams_record_first_event_mid_body_breakage_and_abort() {
        let complete_engine = MockServer::start().await;
        let complete_beacon = accepted_beacon().await;
        Mock::given(method("POST"))
            .and(path("/v1/chat/completions"))
            .respond_with(ResponseTemplate::new(200).set_body_raw(
                "data: {\"choices\":[{\"delta\":{\"content\":\"hi\"}}]}\n\ndata: [DONE]\n\n",
                "text/event-stream",
            ))
            .mount(&complete_engine)
            .await;
        let complete = streaming_client(&complete_engine.uri(), &complete_beacon.uri());
        let mut stream = complete
            .chat_completions_stream(ChatRequest::user("model/a", "secret prompt"))
            .await
            .expect("stream opens");
        assert!(stream.next().await.expect("first item").is_ok());
        while stream.next().await.is_some() {}
        drop(stream);
        drop(complete);
        let batch = only_batch(&complete_beacon).await;
        assert_eq!(batch["events"][0]["final_outcome"], "ok");
        assert!(batch["events"][0]["ttft_ms"].is_number());

        let abort_engine = MockServer::start().await;
        let abort_beacon = accepted_beacon().await;
        Mock::given(method("POST"))
            .and(path("/v1/responses"))
            .respond_with(ResponseTemplate::new(200).set_body_raw(
                "event: response.output_text.delta\ndata: {\"type\":\"response.output_text.delta\",\"delta\":\"hi\"}\n\n",
                "text/event-stream",
            ))
            .mount(&abort_engine)
            .await;
        let abort = streaming_client(&abort_engine.uri(), &abort_beacon.uri());
        let stream = abort
            .responses_stream(ResponsesRequest::text("model/a", "secret prompt"))
            .await
            .expect("stream opens");
        drop(stream);
        drop(abort);
        let batch = only_batch(&abort_beacon).await;
        assert_eq!(batch["events"][0]["final_outcome"], "aborted");

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("listener");
        let engine_address = listener.local_addr().expect("listener address");
        let broken_server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("connection");
            let mut request = vec![0_u8; 8192];
            let _ = socket.read(&mut request).await.expect("request read");
            socket
                .write_all(
                    b"HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\ntransfer-encoding: chunked\r\nconnection: close\r\n\r\n",
                )
                .await
                .expect("headers");
            let first = b"data: {\"choices\":[{\"delta\":{\"content\":\"hi\"}}]}\n\n";
            socket
                .write_all(format!("{:x}\r\n", first.len()).as_bytes())
                .await
                .expect("chunk size");
            socket.write_all(first).await.expect("first event");
            socket.write_all(b"\r\n").await.expect("chunk terminator");
            socket.flush().await.expect("flush");
            tokio::time::sleep(Duration::from_millis(20)).await;
            socket
                .write_all(b"20\r\ntruncated")
                .await
                .expect("broken chunk");
        });
        let broken_beacon = accepted_beacon().await;
        let broken = streaming_client(&format!("http://{engine_address}"), &broken_beacon.uri());
        let mut stream = broken
            .chat_completions_stream(ChatRequest::user("model/a", "secret prompt"))
            .await
            .expect("stream opens");
        assert!(stream.next().await.expect("first item").is_ok());
        let mut saw_error = false;
        while let Some(item) = stream.next().await {
            if item.is_err() {
                saw_error = true;
                break;
            }
        }
        assert!(saw_error);
        drop(stream);
        broken_server.await.expect("server task");
        drop(broken);
        let batch = only_batch(&broken_beacon).await;
        assert_eq!(batch["events"][0]["final_outcome"], "stream_broken");
        assert!(batch["events"][0]["ttft_ms"].is_number());
    }

    #[test]
    fn construction_is_lazy_and_no_runtime_leaves_final_flush_as_the_fallback() {
        let reporter = TelemetryReporter::new(config(Arc::new(ManualClock::new(0)), 0.0));
        assert!(!reporter.worker_started());
        reporter.on_request(event(AttemptOutcome::HttpError, "failure"), Vec::new());
        assert!(!reporter.worker_started());
        assert_eq!(reporter.buffered_events(), 1);

        let disabled = Client::builder()
            .api_key("sk-test")
            .telemetry(false)
            .build()
            .expect("client");
        assert!(disabled.telemetry_sink.is_none());
        assert!(!disabled.telemetry);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn close_attempts_one_final_flush_and_returns_within_the_bound() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(
                ResponseTemplate::new(202)
                    .set_delay(Duration::from_secs(5))
                    .set_body_json(json!({"policy": {}})),
            )
            .mount(&server)
            .await;
        let reporter = network_reporter(&server, Arc::new(ManualClock::new(0)));
        reporter.on_request(event(AttemptOutcome::HttpError, "failure"), Vec::new());
        let started = Instant::now();
        reporter.close(Duration::from_millis(100));
        assert!(started.elapsed() < Duration::from_millis(500));
    }
}
