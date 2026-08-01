//! Optional production canary. Run explicitly with a funded smoke key.

use futures_util::StreamExt;
use trusted_router::{ChatRequest, Client, ResponsesRequest, FAST_MODEL};

#[tokio::test]
#[ignore = "requires TRUSTEDROUTER_API_KEY and production provider traffic"]
async fn production_chat_and_responses_streaming_smoke() -> trusted_router::Result<()> {
    let key = std::env::var("TRUSTEDROUTER_API_KEY")
        .expect("TRUSTEDROUTER_API_KEY must contain a funded smoke key");
    let client = Client::new(key)?;

    let chat = client
        .chat_completions(ChatRequest::user(FAST_MODEL, "Reply with exactly PONG"))
        .await?;
    assert_eq!(
        chat.choices
            .first()
            .and_then(|choice| choice.message.text_content()),
        Some("PONG")
    );

    let mut chat_stream = client
        .chat_completions_text(ChatRequest::user(FAST_MODEL, "Reply with exactly PONG"))
        .await?;
    let mut streamed_text = String::new();
    while let Some(delta) = chat_stream.next().await {
        streamed_text.push_str(&delta?);
    }
    assert_eq!(streamed_text.trim(), "PONG");

    let response = client
        .responses(ResponsesRequest::text(
            FAST_MODEL,
            "Reply with exactly PONG",
        ))
        .await?;
    assert_eq!(response.status, "completed");
    assert!(serde_json::to_string(&response.output)
        .expect("Responses output serializes")
        .contains("PONG"));

    let mut response_stream = client
        .responses_stream(ResponsesRequest::text(
            FAST_MODEL,
            "Reply with exactly PONG",
        ))
        .await?;
    let mut event_names = Vec::new();
    while let Some(event) = response_stream.next().await {
        event_names.push(event?.event);
    }
    assert!(event_names.iter().any(|name| name == "response.created"));
    assert!(event_names
        .iter()
        .any(|name| name == "response.output_text.delta"));
    assert!(event_names.iter().any(|name| name == "response.completed"));

    Ok(())
}
