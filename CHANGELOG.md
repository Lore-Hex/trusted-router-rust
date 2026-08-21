# Changelog

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
