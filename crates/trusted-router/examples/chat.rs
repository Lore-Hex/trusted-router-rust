//! Sends one non-streaming chat completion.

use trusted_router::{ChatRequest, Client, FAST_MODEL};

#[tokio::main]
async fn main() -> trusted_router::Result<()> {
    let client = Client::new(std::env::var("TRUSTEDROUTER_API_KEY").map_err(|_| {
        trusted_router::Error::InvalidConfiguration(
            "set TRUSTEDROUTER_API_KEY before running this example".to_owned(),
        )
    })?)?;
    let response = client
        .chat_completions(ChatRequest::user(FAST_MODEL, "Reply with PONG"))
        .await?;
    println!(
        "{}",
        response.choices[0].message.text_content().unwrap_or("")
    );
    Ok(())
}
