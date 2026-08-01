# TrustedRouter Rust SDK

[![CI](https://github.com/Lore-Hex/trusted-router-rust/actions/workflows/ci.yml/badge.svg)](https://github.com/Lore-Hex/trusted-router-rust/actions/workflows/ci.yml)
[![crates.io](https://img.shields.io/crates/v/trusted-router.svg)](https://crates.io/crates/trusted-router)
[![docs.rs](https://docs.rs/trusted-router/badge.svg)](https://docs.rs/trusted-router)
[![MSRV](https://img.shields.io/badge/MSRV-1.82-blue)](Cargo.toml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)

Official Rust SDK and stable C ABI for [TrustedRouter](https://trustedrouter.com).

It supports async and blocking Rust, Chat Completions, Responses, Messages,
embeddings, streaming, routing filters, orchestration primitives, OAuth credit
delegation, billing and observability controls, and Google Confidential Space
attestation verification.

## Install

```sh
cargo add trusted-router
```

Rust 1.82 or newer is supported.

## Chat

```rust,no_run
use trusted_router::{ChatRequest, Client, FAST_MODEL};

#[tokio::main]
async fn main() -> trusted_router::Result<()> {
    let client = Client::new(std::env::var("TRUSTEDROUTER_API_KEY").unwrap())?;
    let response = client
        .chat_completions(ChatRequest::user(FAST_MODEL, "Reply with PONG"))
        .await?;
    println!("{}", response.choices[0].message.text_content().unwrap_or(""));
    Ok(())
}
```

## Streaming

```rust,no_run
use futures_util::StreamExt;
use trusted_router::{ChatRequest, Client, FAST_MODEL};

#[tokio::main]
async fn main() -> trusted_router::Result<()> {
    let client = Client::new(std::env::var("TRUSTEDROUTER_API_KEY").unwrap())?;
    let mut stream = client
        .chat_completions_text(ChatRequest::user(FAST_MODEL, "Write a haiku"))
        .await?;
    while let Some(delta) = stream.next().await {
        print!("{}", delta?);
    }
    Ok(())
}
```

Responses streaming preserves lifecycle event names such as
`response.output_text.delta`:

```rust,no_run
use futures_util::StreamExt;
use trusted_router::{Client, ResponsesRequest, FAST_MODEL};

# async fn run() -> trusted_router::Result<()> {
# let client = Client::new("sk-tr-example")?;
let mut events = client
    .responses_stream(ResponsesRequest::text(FAST_MODEL, "Reply with PONG"))
    .await?;
while let Some(event) = events.next().await {
    let event = event?;
    println!("{}: {}", event.event, event.data);
}
# Ok(()) }
```

## Privacy and routing

Privacy settings are hard routing requirements, not labels:

```rust,no_run
use trusted_router::{ChatRequest, Client, ProviderPreferences, E2E_MODEL};

# async fn run() -> trusted_router::Result<()> {
# let client = Client::new("sk-tr-example")?;
let mut request = ChatRequest::user(E2E_MODEL, "Analyze this document");
request.provider = Some(ProviderPreferences::confidential());
let response = client.chat_completions(request).await?;
# Ok(()) }
```

Available aliases include `trustedrouter/zdr`, `trustedrouter/e2e`,
`trustedrouter/confidential`, `trustedrouter/eu`, and `trustedrouter/us`.
Provider filters also support explicit order, allow and deny lists, billing
source, quantization, fallback policy, sort mode, and US jurisdiction.
Use `trustedrouter/eu` for the EU-focused routing pool.

## Orchestration

The SDK builds the five TrustedRouter orchestration primitives without custom
JSON string construction:

- `synth_tool`: parallel panel, judge, and final synthesis
- `advisor_tool`: worker plus one or more private advisors
- `selector_tool`: parallel answers with one verbatim selection
- `map_reduce_tool`: bounded mapping, parallel work, and reduction
- `subagent_tool`: delegated agent calls

```rust
use trusted_router::{advisor_tool, AdvisorToolOptions};

let tool = advisor_tool(AdvisorToolOptions {
    worker_models: vec!["deepseek/deepseek-v4-flash".into()],
    advisor_models: vec!["trustedrouter/zeus-1.0".into()],
    depth: Some(2),
    ..Default::default()
});
assert_eq!(tool["type"], "trustedrouter:advisor");
```

Named orchestration models, including Socrates, Prometheus, Zeus, and Athena,
are ordinary model IDs and do not require SDK-specific methods.

## Two API planes

The client deliberately separates:

- Inference: `https://api.trustedrouter.com/v1`
- Control: `https://trustedrouter.com/v1`

Prompt-bearing calls use only the inference plane. Catalog, credits, billing,
OAuth, activity, and broadcast configuration use only the control plane.
Authenticated low-level calls reject absolute and scheme-relative paths.
Trust and status URLs are fetched by a credential-free transport path.

## Retries and billing safety

The SDK retries connection failures, timeouts, `429`, and retryable `5xx`
responses with bounded full jitter. Mutating inference and billing helpers add
idempotency keys automatically. Errors retain `layer`, `source`, `provider`,
`request_id`, status, payload, and `Retry-After` so applications can make
actionable retry decisions.

Money remains JSON integer or decimal data. The SDK never converts account
balances or charges through floating point.

## Blocking Rust

The default `blocking` feature provides `BlockingClient`:

```rust,no_run
use trusted_router::{BlockingClient, ChatRequest, AUTO_MODEL};

fn main() -> trusted_router::Result<()> {
    let client = BlockingClient::new(std::env::var("TRUSTEDROUTER_API_KEY").unwrap())?;
    let response = client.chat_completions(ChatRequest::user(AUTO_MODEL, "Hello"))?;
    println!("{}", response.choices[0].message.text_content().unwrap_or(""));
    Ok(())
}
```

## C and C++

`trusted-router-ffi` builds a static and dynamic library with the checked-in
header at `crates/trusted-router-ffi/include/trusted_router.h`.

```sh
cargo build --release -p trusted-router-ffi
cc examples/c/chat.c \
  -I crates/trusted-router-ffi/include \
  -L target/release -ltrusted_router_ffi -o trusted-router-chat
```

The ABI uses an opaque client, explicit `TrResult` ownership, panic containment,
generic JSON calls, Chat and Responses helpers, and streaming callbacks. C++ can
link the same ABI directly.

## Attestation

`verify_gateway_attestation` verifies:

- Google RS256 signature, issuer, audience, and expiration
- production `dbgstat=disabled-since-boot`
- Confidential Space, Secure Boot, and supported SEV or TDX hardware
- image digest and image reference pins
- fresh nonce and optional RFC 9266 TLS exporter binding
- TLS leaf certificate SHA-256 binding

The certificate and exporter must come from the same TLS connection that fetched
the attestation. Supplying values from a separate connection weakens the binding
and is intentionally not presented as equivalent.

## More

- [API parity](PARITY.md)
- [Security policy](SECURITY.md)
- [Contributing](CONTRIBUTING.md)
- [TrustedRouter docs](https://trustedrouter.com/docs)
- [Model chooser](https://trustedrouter.com/choose)
- [Trust and source verification](https://trust.trustedrouter.com)

Licensed under Apache 2.0.
