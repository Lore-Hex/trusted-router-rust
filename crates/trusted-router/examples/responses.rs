//! Streams events from the Responses API.

use futures_util::StreamExt;
use trusted_router::{Client, ResponsesRequest, FAST_MODEL};

#[tokio::main]
async fn main() -> trusted_router::Result<()> {
    let client = Client::new(std::env::var("TRUSTEDROUTER_API_KEY").map_err(|_| {
        trusted_router::Error::InvalidConfiguration(
            "set TRUSTEDROUTER_API_KEY before running this example".to_owned(),
        )
    })?)?;
    let mut events = client
        .responses_stream(ResponsesRequest::text(FAST_MODEL, "Reply with PONG"))
        .await?;
    while let Some(event) = events.next().await {
        let event = event?;
        println!("{}: {}", event.event, event.data);
    }
    Ok(())
}
