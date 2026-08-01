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
| Routing | provider order, only, ignore, fallback, sort, price caps | Complete |
| Privacy | ZDR, confidential/E2E, US, EU filters and aliases | Complete |
| Orchestration | Synth, Advisor, Selector, MapReduce, Subagent builders | Complete |
| Named models | constants for major TrustedRouter aliases | Complete |
| Error attribution | layer, source, provider, request ID, Retry-After | Complete |
| Reliability | retry, jitter, timeouts, idempotency, apex failover | Complete |
| Attestation | signature and complete production claim policy | Complete |
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
