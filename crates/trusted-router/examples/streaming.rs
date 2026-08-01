//! Streams text deltas from a chat completion.

use futures_util::StreamExt;
use trusted_router::{ChatRequest, Client, FAST_MODEL};

#[tokio::main]
async fn main() -> trusted_router::Result<()> {
    let client = Client::new(std::env::var("TRUSTEDROUTER_API_KEY").map_err(|_| {
        trusted_router::Error::InvalidConfiguration(
            "set TRUSTEDROUTER_API_KEY before running this example".to_owned(),
        )
    })?)?;
    let mut stream = client
        .chat_completions_text(ChatRequest::user(FAST_MODEL, "Write a short haiku"))
        .await?;
    while let Some(delta) = stream.next().await {
        print!("{}", delta?);
    }
    println!();
    Ok(())
}
