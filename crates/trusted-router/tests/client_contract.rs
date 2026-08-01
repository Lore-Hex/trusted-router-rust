#![allow(missing_docs)]

use futures_util::StreamExt;
use http::Method;
use serde_json::{json, Value};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use trusted_router::{
    CallOptions, ChatMessage, ChatRequest, Client, ErrorKind, ModelFilters, Plane,
    ProviderPreferences, ResponsesRequest,
};
use wiremock::matchers::{body_json, header, method, path, query_param};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

fn client(server: &MockServer) -> Client {
    Client::builder()
        .api_key("sk-test")
        .workspace_id("workspace-default")
        .api_base_url(format!("{}/inference/v1", server.uri()))
        .control_base_url(format!("{}/control/v1", server.uri()))
        .max_retries(0)
        .build()
        .unwrap()
}

#[tokio::test]
async fn routes_inference_and_control_to_separate_planes() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/inference/v1/chat/completions"))
        .and(header("authorization", "Bearer sk-test"))
        .and(header("x-trustedrouter-workspace", "workspace-default"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "chat_1", "choices": [{"index": 0, "message": {"role": "assistant", "content": "PONG"}}]
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/control/v1/models"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"data": []})))
        .expect(1)
        .mount(&server)
        .await;

    let client = client(&server);
    let chat = client
        .chat_completions(ChatRequest::user("trustedrouter/auto", "ping"))
        .await
        .unwrap();
    assert_eq!(chat.choices[0].message.text_content(), Some("PONG"));
    assert!(client
        .models(ModelFilters::default())
        .await
        .unwrap()
        .data
        .is_empty());
}

#[tokio::test]
async fn per_call_workspace_and_idempotency_are_headers_not_body() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/inference/v1/chat/completions"))
        .and(header("x-trustedrouter-workspace", "workspace-call"))
        .and(header("idempotency-key", "request-123"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "chat_1", "choices": [{"index": 0, "message": {"role": "assistant", "content": "ok"}}]
        })))
        .mount(&server)
        .await;
    let mut request = ChatRequest::user("trustedrouter/auto", "hello");
    request.call_options.workspace_id = Some("workspace-call".to_owned());
    request.call_options.idempotency_key = Some("request-123".to_owned());
    client(&server).chat_completions(request).await.unwrap();
    let requests = server.received_requests().await.unwrap();
    let body: Value = serde_json::from_slice(&requests[0].body).unwrap();
    assert!(body.get("workspace_id").is_none());
    assert!(body.get("idempotency_key").is_none());
}

#[tokio::test]
async fn explicit_empty_overrides_suppress_credentials() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/control/v1/credits"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"data": {"total": "0"}})))
        .mount(&server)
        .await;
    client(&server)
        .credits(CallOptions {
            api_key: Some(String::new()),
            workspace_id: Some(String::new()),
            ..CallOptions::default()
        })
        .await
        .unwrap();
    let request = &server.received_requests().await.unwrap()[0];
    assert!(!request.headers.contains_key("authorization"));
    assert!(!request.headers.contains_key("x-trustedrouter-workspace"));
}

#[tokio::test]
async fn rejects_absolute_and_scheme_relative_request_paths() {
    let server = MockServer::start().await;
    let client = client(&server);
    for malicious in [
        "https://attacker.test/steal",
        "//attacker.test/steal",
        "models",
    ] {
        let error = client
            .request::<Value>(
                Plane::Control,
                Method::GET,
                malicious,
                None,
                CallOptions::default(),
            )
            .await
            .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidConfiguration);
    }
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn preserves_actionable_provider_error_fields() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/control/v1/providers"))
        .respond_with(ResponseTemplate::new(429).set_body_json(json!({
            "error": {
                "message": "quota exceeded", "layer": "provider", "source": "upstream",
                "provider": "example", "request_id": "req_123"
            }
        })))
        .mount(&server)
        .await;
    let error = client(&server).providers().await.unwrap_err();
    assert_eq!(error.kind(), ErrorKind::RateLimit);
    let api = error.api_error().unwrap();
    assert_eq!(api.layer.as_deref(), Some("provider"));
    assert_eq!(api.source.as_deref(), Some("upstream"));
    assert_eq!(api.provider.as_deref(), Some("example"));
    assert_eq!(api.request_id.as_deref(), Some("req_123"));
}

#[tokio::test]
async fn retries_retryable_status_then_succeeds() {
    let server = MockServer::start().await;
    let calls = Arc::new(AtomicUsize::new(0));
    let observed = Arc::clone(&calls);
    Mock::given(method("GET"))
        .and(path("/control/v1/providers"))
        .respond_with(move |_request: &Request| {
            if observed.fetch_add(1, Ordering::SeqCst) == 0 {
                ResponseTemplate::new(503).set_body_json(json!({"error": {"message": "retry"}}))
            } else {
                ResponseTemplate::new(200).set_body_json(json!({"data": []}))
            }
        })
        .mount(&server)
        .await;
    let client = Client::builder()
        .api_base_url(format!("{}/inference/v1", server.uri()))
        .control_base_url(format!("{}/control/v1", server.uri()))
        .max_retries(1)
        .build()
        .unwrap();
    assert!(client.providers().await.unwrap().data.is_empty());
    assert_eq!(calls.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn model_filters_are_encoded_without_hand_built_query_strings() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/control/v1/models"))
        .and(query_param("open_weights", "true"))
        .and(query_param("provider[jurisdiction]", "us"))
        .and(query_param("provider[region]", "eu"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"data": []})))
        .expect(1)
        .mount(&server)
        .await;
    client(&server)
        .models(ModelFilters {
            open_weights: Some(true),
            provider_jurisdiction: Some("us".to_owned()),
            provider_region: Some("eu".to_owned()),
        })
        .await
        .unwrap();
}

#[tokio::test]
async fn privacy_filters_serialize_as_hard_requirements() {
    let preferences = ProviderPreferences::confidential();
    assert_eq!(preferences.min_privacy.as_deref(), Some("confidential"));
    assert_eq!(preferences.data_collection.as_deref(), Some("deny"));
    let zdr = serde_json::to_value(ProviderPreferences::zdr()).unwrap();
    assert_eq!(zdr["min_privacy"], "zdr");
    assert_eq!(zdr["data_collection"], "deny");

    let advanced = ProviderPreferences {
        usage: Some("credits".to_owned()),
        quantizations: vec!["fp8".to_owned()],
        max_price: [
            ("prompt".to_owned(), json!(1.25)),
            ("completion".to_owned(), json!(4.5)),
        ]
        .into_iter()
        .collect(),
        ..ProviderPreferences::default()
    };
    let advanced = serde_json::to_value(advanced).unwrap();
    assert_eq!(advanced["usage"], "credits");
    assert_eq!(advanced["quantizations"], json!(["fp8"]));
    assert_eq!(
        advanced["max_price"],
        json!({"prompt": 1.25, "completion": 4.5})
    );
}

#[tokio::test]
async fn chat_and_responses_streams_parse_sse_and_done() {
    let server = MockServer::start().await;
    let chat_body = concat!(
        "data: {\"id\":\"chunk_1\",\"choices\":[{\"delta\":{\"content\":\"PO\"}}]}\n\n",
        "data: {\"id\":\"chunk_1\",\"choices\":[{\"delta\":{\"content\":\"NG\"}}]}\n\n",
        "data: [DONE]\n\n"
    );
    Mock::given(method("POST"))
        .and(path("/inference/v1/chat/completions"))
        .and(body_json(json!({
            "model": "trustedrouter/fast",
            "messages": [{"role": "user", "content": "ping"}],
            "stream": true,
            "stream_options": {"include_usage": true}
        })))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "text/event-stream")
                .set_body_raw(chat_body, "text/event-stream"),
        )
        .mount(&server)
        .await;
    let mut stream = client(&server)
        .chat_completions_text(ChatRequest::new(
            "trustedrouter/fast",
            vec![ChatMessage::user("ping")],
        ))
        .await
        .unwrap();
    let mut text = String::new();
    while let Some(delta) = stream.next().await {
        text.push_str(&delta.unwrap());
    }
    assert_eq!(text, "PONG");

    Mock::given(method("POST"))
        .and(path("/inference/v1/responses"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_raw(
                    "event: response.created\ndata: {\"type\":\"response.created\",\"response\":{\"id\":\"resp_1\"}}\n\ndata: [DONE]\n\n",
                    "text/event-stream",
                ),
        )
        .mount(&server)
        .await;
    let mut events = client(&server)
        .responses_stream(ResponsesRequest::text("trustedrouter/fast", "ping"))
        .await
        .unwrap();
    assert_eq!(
        events.next().await.unwrap().unwrap().event,
        "response.created"
    );
    assert!(events.next().await.is_none());
}

#[tokio::test]
async fn zero_timeout_disables_sdk_deadline() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/control/v1/providers"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_delay(Duration::from_millis(20))
                .set_body_json(json!({"data": []})),
        )
        .mount(&server)
        .await;
    let client = Client::builder()
        .control_base_url(format!("{}/control/v1", server.uri()))
        .timeout(Some(Duration::from_millis(1)))
        .max_retries(0)
        .build()
        .unwrap();
    let value: Value = client
        .request(
            Plane::Control,
            Method::GET,
            "/providers",
            None,
            CallOptions {
                timeout: Some(Duration::ZERO),
                ..CallOptions::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(value, json!({"data": []}));
}
