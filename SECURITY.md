# Security

Report SDK or TrustedRouter security issues privately to
`security@trustedrouter.com`. Do not open public issues containing credentials,
prompts, outputs, exploit details, or unpublished findings.

## SDK boundaries

- Prompt-bearing calls go only to the configured inference plane.
- Account and catalog operations go only to the configured control plane.
- Authenticated request methods accept root-relative paths only.
- Status, trust release, and JWKS fetches never receive API-key, workspace, or
  idempotency headers.
- Retryable mutations carry idempotency keys.
- The SDK does not log request or response bodies.
- Attestation rejects debug workloads, insecure boot, unsupported hardware,
  expired signatures, pin mismatches, replayed nonces, and bad TLS bindings.
- C entry points contain panics and require explicit result ownership.

Applications must keep reusable API keys out of client-distributed binaries.
Desktop and mobile applications should use OAuth credit delegation and the
platform's protected credential store.
