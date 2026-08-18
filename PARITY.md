# SDK parity

The Rust SDK follows the production-correct two-plane contract used by the Go
and Java SDKs. The table is a release gate, not a roadmap claim.

| Area | Rust surface | Status |
| --- | --- | --- |
| Chat Completions | `chat_completions`, JSON/chunk/text streams | Complete |
| Responses | create, SSE lifecycle stream, input token count | Complete |
| Anthropic Messages | `messages` | Complete |
| Embeddings | `embeddings` | Complete |
| Models | typed list and open-weight, jurisdiction, region filters | Complete |
| Providers and regions | typed lists | Complete |
| Credits and activity | typed envelopes | Complete |
| Broadcast | list, create, get, patch, delete, test | Complete |
| Billing | checkout and stablecoin checkout | Complete |
| Auth | session, logout, userinfo | Complete |
| OAuth delegation | PKCE, state, authorize URL, loopback, key exchange | Complete |
| Routing | provider order, only, ignore, fallback, sort, billing source, and quantization | Complete |
| Privacy | ZDR, confidential/E2E, and US filters; EU routing alias | Complete |
| Orchestration | Synth, Advisor, Selector, MapReduce, Subagent builders | Complete |
| Named models | constants for major TrustedRouter aliases | Complete |
| Error attribution | layer, source, provider, request ID, Retry-After | Complete |
| Reliability | retry, jitter, timeouts, idempotency, apex failover | Complete |
| Attestation | signature and complete production claim policy | Complete |
| Client telemetry | `x-tr-client` header channel, contract v1 | Complete |
| Blocking Rust | endpoint and callback facade | Complete |
| C/C++ | stable C ABI, JSON calls, Chat, Responses, SSE callback | Complete |

## Intentional boundaries

- Stateful Responses operations remain server-classified compatibility errors.
- Rust cannot portably extract a TLS exporter from an arbitrary caller-supplied
  Reqwest client. Full channel-bound verification therefore accepts the live
  certificate and exporter as explicit inputs and verifies them fail closed.
- The C ABI exposes forward-compatible JSON instead of mirroring every Rust
  response struct. This keeps the ABI stable as API response fields expand.
- Per-region host construction is not exposed. `api.trustedrouter.com` is the
  global load balancer and retries re-request the canonical attested endpoint.
- Client telemetry sends the per-attempt `x-tr-client` header only. The beacon
  channel is deliberately deferred until the Python contract has been live and
  calibrated (contract v1 rollout order); `credential_free_json` is the
  reserved out-of-engine attach point for it.
- SDK-owned API, metadata, and standalone JWKS transports do not follow
  redirects. An injected reqwest client is immutable and is therefore used
  verbatim for general API traffic (or when explicitly supplied to standalone
  attestation verification): its redirect policy, cookies, and
  `default_headers` are a caller-owned trust boundary. An occupied
  `x-tr-client` slot blocks a same-name default merge; a deliberately vacant
  slot on a suppressed attempt cannot, so callers must configure injected
  clients with `Policy::none()` and without ambient credential defaults when
  they need the SDK-owned transport guarantees.
- Telemetry `error_class` for TLS failures is only as specific as the error the
  TLS stack surfaces, and that varies by platform even with one stack (this
  crate pins rustls on every target). A peer whose plaintext record actually
  reaches rustls yields `tls`; a peer that resets mid-handshake — including the
  RST-instead-of-FIN a socket close with unread inbound data produces on
  Windows — yields `connect_error`, because no TLS marker exists to read. Both
  are TR-fault under the methodology, so availability arithmetic is unaffected,
  but per-class histograms for TLS failures are not directly comparable across
  client platforms. Server-side class comparisons should account for that.
