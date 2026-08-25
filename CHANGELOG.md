# Changelog

## 0.3.0 — 2026-08-25

The client-events beacon channel and User-Agent runtime parity. This is the
first release published to crates.io; 0.1.0 and 0.2.0 were tagged but never
uploaded, because the registry credential was not configured. The C ABI
(`trusted_router.h`) is unchanged.

### Added

- Client-events beacon channel, client telemetry contract v1 §4–§6 (#25),
  completing the channel pair alongside the `x-tr-client` header shipped in
  0.2.0. `TelemetryReporter` owns its own HTTP client and never borrows the
  caller's, following the `credential_free_json` precedent; a single worker
  starts on the first record when a runtime is current. Failures, retried and
  failed-over attempts, and anything over 30 s are always recorded, while
  healthy fast successes are sampled at `telemetry_sample_rate` (default 0.01,
  set via `ClientBuilder::telemetry_sample_rate`). Exact per-minute counters
  fold error class, then endpoint, then an existing key at 256 keys; the event
  buffer holds 1 000 and drops the oldest success first; retention is 24 h and
  roughly 512 KiB, oldest first. Batches flush every 30 s, urgently at 50
  events or ~60 KiB, and are trimmed to 65 536 bytes. The server can quiet the
  channel: `x-tr-telemetry: off` is a kill switch; 400, 401, 403, 404 and 410
  disable that reporter rather than the process — a client and its clones
  share one, a separately built client is unaffected; 413 drops the oversized batch and counts the loss; anything else backs off, honouring `Retry-After` up to 600 s. `Drop`
  closes the reporter and attempts a final flush, bounded by a timeout rather
  than guaranteed to complete. Opting out disables both channels and starts no
  worker.

### Changed

- The `User-Agent` now carries the contract's optional runtime suffix (#26):
  `trusted-router-rust/<version> rustc/<release>`. Rust was the only SDK
  omitting it, so Rust was the only SDK whose requests landed with
  `client_sdk=tr-rust` and an empty `client_runtime` even though its own
  beacon reported the runtime correctly. The suffix is optional in the
  contract, so this is parity rather than a defect fix. The runtime token now
  comes from one shared builder used by the beacon identity and every
  User-Agent site, so the two channels cannot report different runtimes.

### Fixed

- The fallback JWKS client in `attestation.rs` sent no `User-Agent` at all
  (#26). It now uses the shared builder. A caller-injected client is left
  alone, since that one belongs to the caller.

### Packaging

- The published archive excludes `tests/**` (#27). The test fixtures include an
  RSA private key used to sign synthetic attestations, and `RELEASING.md`
  requires that no private fixture ship; a crates.io upload is permanent, so
  this has to hold before the first publish rather than be corrected after. CI
  now asserts the packaged file list carries no key material, since a checklist
  item did not catch it.
- The archive now carries the Apache-2.0 `LICENSE` text, which lives at the
  workspace root and so was not picked up from the crate directory (#27).

## 0.2.0 — 2026-08-21

Client telemetry header channel (contract v1), the cross-SDK hardening from the
review round, and domain failover. The `User-Agent` format is unchanged
(`trusted-router-rust/<version>`, §3.1) and the C ABI (`trusted_router.h`) is
unchanged.

### Added

- `x-tr-client` header channel, client telemetry contract v1 (#19). Every
  attempt of an inference call against a TrustedRouter host carries the
  bounded, content-free `x-tr-client` reliability header (§3.2 grammar, at most
  160 bytes; an out-of-grammar value sends nothing rather than failing the
  request). `ClientBuilder::telemetry` sets the switch, with precedence explicit
  argument > `TRUSTEDROUTER_TELEMETRY` > `DO_NOT_TRACK` > default on only for
  known TrustedRouter hosts. `/attestation` and `/internal/gateway/authorize`
  are always excluded; custom base URLs and control-plane calls send no header;
  the header name is SDK-reserved and a caller-supplied value is stripped. The
  closed vocabularies ship as public constants (`TELEMETRY_SCHEMA_VERSION`,
  `TELEMETRY_HOSTS`, `TELEMETRY_ENDPOINTS`, `TELEMETRY_OUTCOMES`,
  `TELEMETRY_ERROR_CLASSES`, `DEFAULT_TELEMETRY_PATH`). Beacons are
  deliberately absent per the contract rollout order; opting out never changes
  the `User-Agent`.
- Domain failover (#12, #13, #14). The request loop and the streaming open walk
  `ALIAS_API_BASE_URLS` (`api.allyrouter.com`, `api.uptimerouter.com`) after
  the primary on connection failures and `502`/`503`/`504`, subject to the
  replay-safety gate under Changed; a `500` is retried on the same host; a
  custom base URL is never rewritten.
  `ClientBuilder::regional_failover(false)` pins every attempt to one host and
  `Client::api_base_urls` exposes the candidate list.
- `x-should-retry` is honoured and `retry-after-ms` is parsed, winning over
  `retry-after` (#15).
- Accept the published attestation rollout pins (#11);
  `AttestationPolicy::pins_image_identity` (#17).
- `ClientBuilder::root_certificate_pem` and `ClientBuilder::resolve_hostname`,
  plus `validated_raw_sse` on the async and blocking clients (#21).

### Changed

- Cross-SDK hardening (#21):
  - Retries and domain failover are gated on replay safety: a failed attempt
    is re-sent only for `GET`/`HEAD`/`OPTIONS`/`TRACE` or when the request
    carries a non-empty `Idempotency-Key`; otherwise the first failure is
    returned. Generated keys now also cover `responses_input_tokens` and
    `logout`; in the C ABI, `tr_chat_completions`, `tr_responses`, and
    `tr_stream_json` generate an `Idempotency-Key` when the caller supplies
    none, while `tr_request_json` sends only a caller-supplied key, so a
    mutating raw call without one is not retried (the C header is unchanged).
  - The retryable status set is `429` or any status of `500` and above (was
    `429`, `500`, `502`, `503`, `504`), still overridden by `x-should-retry`;
    the failover set is unchanged.
  - A truncated or stalled diagnostic body on a retryable status consumes the
    attempt but no longer bypasses the retry policy.
  - SDK-owned API, metadata, and standalone JWKS transports never follow
    redirects, and an injected `reqwest` client is used verbatim as a
    caller-owned trust boundary; JWKS fetches are hardened; SSE streams are
    validated (in the C ABI as well) and strict streams are pinned to exact
    logical routes.
- `retry-after` (seconds and HTTP-date forms) is clamped to 60 s so one header
  cannot park a caller (#18).
- An attestation policy that pins no image identity is refused:
  `policy_from_trust_release` now returns `Result`, and verification rejects an
  unpinned policy (#17).
- Transport refactored into layered `policy`/`routing`/`engine`/`headers`
  modules with one retry/failover loop shared by the buffered and streaming
  paths and one idempotency-key generator; no intended behaviour change (#16).
- `h2` 0.4.15 → 0.4.16 for a RustSec advisory (#21).

### Repository

- FFI release artifacts are packaged per platform with checksums.
- SDK conformance gate on pull requests (#21, #22), CODEOWNERS, and a security
  policy with private vulnerability reporting and a 72-hour acknowledgement.

## 0.1.0

- Initial async and blocking Rust SDK.
- Chat Completions, Responses, Messages, embeddings, catalogs, credits,
  activity, billing, broadcast, auth, and OAuth delegation.
- Chat and Responses SSE streaming.
- Provider privacy, region, routing, and orchestration helpers.
- Google Confidential Space attestation verification.
- Stable C ABI for C and C++ applications.
