# trusted-router

Official Rust SDK for [TrustedRouter](https://trustedrouter.com).

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

The crate includes async and blocking clients, SSE streaming, Chat Completions,
Responses, Messages, embeddings, model and provider catalogs, privacy filters,
orchestration builders, OAuth delegation, billing and broadcast helpers, and
Google Confidential Space attestation verification.

Receipt verification requires an explicit issuer pin (use
`https://api.trustedrouter.com` for production TrustedRouter receipts) and
requires request and response traffic bindings by default. The
`ReceiptVerificationOptions::require_bindings = false` escape hatch is for
intentional signature-only or partial-binding inspection.

See the [repository README](https://github.com/Lore-Hex/trusted-router-rust) for
the complete guide and C ABI.
