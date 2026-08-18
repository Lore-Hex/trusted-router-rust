#![allow(missing_docs)]

use futures_util::StreamExt;
use http::Method;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use trusted_router::{CallOptions, ChatRequest, Client, ErrorKind, OAuthKeyExchangeRequest, Plane};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

#[tokio::test]
async fn owned_client_does_not_follow_redirects() {
    let source = MockServer::start().await;
    let target = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(
            ResponseTemplate::new(307)
                .insert_header("location", format!("{}/captured", target.uri())),
        )
        .mount(&source)
        .await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"leaked": true})))
        .mount(&target)
        .await;

    let client = Client::builder()
        .api_key("secret")
        .workspace_id("workspace")
        .api_base_url(format!("{}/v1", source.uri()))
        .max_retries(0)
        .build()
        .unwrap();
    let error = client
        .request::<Value>(
            Plane::Inference,
            Method::GET,
            "/models",
            None,
            CallOptions::default(),
        )
        .await
        .unwrap_err();
    assert_eq!(error.status_code(), Some(307));
    assert!(target.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn credential_free_paths_ignore_injected_default_authorization() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/status.json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"ok": true})))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/v1/auth/keys"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"key": "delegated"})))
        .mount(&server)
        .await;

    let mut defaults = reqwest::header::HeaderMap::new();
    defaults.insert(
        reqwest::header::AUTHORIZATION,
        reqwest::header::HeaderValue::from_static("Bearer injected-secret"),
    );
    defaults.insert(
        reqwest::header::COOKIE,
        reqwest::header::HeaderValue::from_static("session=secret"),
    );
    let injected = reqwest::Client::builder()
        .default_headers(defaults)
        .build()
        .unwrap();
    let client = Client::builder()
        .api_key("sdk-secret")
        .workspace_id("workspace")
        .api_base_url(format!("{}/v1", server.uri()))
        .control_base_url(format!("{}/v1", server.uri()))
        .header("X-Conformance-Default", "public-client")
        .header("Proxy-Authorization", "Basic sdk-proxy-secret")
        .header("X-Api-Key", "sdk-alternate-secret")
        .header("Idempotency-Key", "sdk-stale-key")
        .header("X-Tr-Client", "sdk-stale-telemetry")
        .http_client(injected)
        .max_retries(0)
        .build()
        .unwrap();

    client
        .status(Some(&format!("{}/status.json", server.uri())))
        .await
        .unwrap();
    client
        .exchange_oauth_key(OAuthKeyExchangeRequest {
            code: "code".to_owned(),
            code_verifier: Some("verifier".to_owned()),
            code_challenge_method: Some("S256".to_owned()),
            call_options: CallOptions {
                headers: BTreeMap::from([
                    ("Authorization".to_owned(), "Bearer call-secret".to_owned()),
                    ("Cookie".to_owned(), "call=secret".to_owned()),
                    (
                        "Proxy-Authorization".to_owned(),
                        "Basic call-secret".to_owned(),
                    ),
                    ("X-Api-Key".to_owned(), "call-alternate-secret".to_owned()),
                    (
                        "X-TrustedRouter-Workspace".to_owned(),
                        "call-workspace".to_owned(),
                    ),
                    ("Idempotency-Key".to_owned(), "call-stale-key".to_owned()),
                    ("X-Tr-Client".to_owned(), "call-stale-telemetry".to_owned()),
                ]),
                ..CallOptions::default()
            },
        })
        .await
        .unwrap();

    let requests = server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 2);
    for request in requests {
        assert!(!request.headers.contains_key("authorization"));
        assert!(!request.headers.contains_key("cookie"));
        assert!(!request.headers.contains_key("proxy-authorization"));
        assert!(!request.headers.contains_key("x-api-key"));
        assert!(!request.headers.contains_key("x-trustedrouter-workspace"));
        assert!(!request.headers.contains_key("idempotency-key"));
        assert!(!request.headers.contains_key("x-tr-client"));
        if request.url.path() == "/v1/auth/keys" {
            assert_eq!(
                request
                    .headers
                    .get("x-conformance-default")
                    .unwrap()
                    .to_str()
                    .unwrap(),
                "public-client"
            );
        }
    }
}

#[tokio::test]
async fn generic_unsafe_disconnect_is_not_retried_without_a_key() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut first, _) = listener.accept().await.unwrap();
        let request = read_request(&mut first).await;
        assert!(request.starts_with(b"POST /v1/custom-mutation "));
        drop(first);
        tokio::time::timeout(Duration::from_millis(800), listener.accept())
            .await
            .ok()
            .map_or(1, |_| 2)
    });
    let client = Client::builder()
        .api_base_url(format!("http://{address}/v1"))
        .max_retries(2)
        .build()
        .unwrap();
    let error = client
        .request::<Value>(
            Plane::Inference,
            Method::POST,
            "/custom-mutation",
            Some(json!({"private": true})),
            CallOptions::default(),
        )
        .await
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Transport);
    assert_eq!(server.await.unwrap(), 1);
}

#[tokio::test]
async fn high_level_retry_reuses_one_generated_idempotency_key() {
    let server = MockServer::start().await;
    let calls = Arc::new(AtomicUsize::new(0));
    let observed = Arc::clone(&calls);
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(move |_request: &Request| {
            if observed.fetch_add(1, Ordering::SeqCst) == 0 {
                ResponseTemplate::new(503).set_body_json(json!({"error": {"message": "retry"}}))
            } else {
                ResponseTemplate::new(200).set_body_json(json!({
                    "id": "chat", "choices": [{"index": 0, "message": {"role": "assistant", "content": "ok"}}]
                }))
            }
        })
        .mount(&server)
        .await;
    let client = Client::builder()
        .api_base_url(format!("{}/v1", server.uri()))
        .max_retries(1)
        .build()
        .unwrap();
    client
        .chat_completions(ChatRequest::user("trustedrouter/fast", "ping"))
        .await
        .unwrap();
    let requests = server.received_requests().await.unwrap();
    let keys = requests
        .iter()
        .map(|request| {
            request
                .headers
                .get("idempotency-key")
                .unwrap()
                .to_str()
                .unwrap()
                .to_owned()
        })
        .collect::<Vec<_>>();
    assert_eq!(keys.len(), 2);
    assert_eq!(keys[0], keys[1]);
    assert!(keys[0].starts_with("tr-req-"));
}

#[tokio::test]
async fn retryable_truncated_error_body_consumes_an_attempt_and_retries() {
    retry_faulty_error_body(false).await;
}

#[tokio::test]
async fn retryable_stalled_error_body_consumes_an_attempt_and_retries() {
    retry_faulty_error_body(true).await;
}

#[tokio::test]
async fn parsed_chat_stream_rejects_malformed_json_and_premature_eof() {
    for (body, expected_kind) in [
        (
            "data: {not-json}\n\ndata: [DONE]\n\n",
            ErrorKind::Serialization,
        ),
        (
            "data: {\"id\":\"chunk\",\"choices\":[]}\n\n",
            ErrorKind::Transport,
        ),
    ] {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/chat/completions"))
            .respond_with(ResponseTemplate::new(200).set_body_raw(body, "text/event-stream"))
            .mount(&server)
            .await;
        let client = Client::builder()
            .api_base_url(format!("{}/v1", server.uri()))
            .max_retries(0)
            .build()
            .unwrap();
        let mut stream = client
            .chat_completions_stream(ChatRequest::user("trustedrouter/fast", "ping"))
            .await
            .unwrap();
        let mut last_error = None;
        while let Some(item) = stream.next().await {
            if let Err(error) = item {
                last_error = Some(error);
                break;
            }
        }
        assert_eq!(last_error.unwrap().kind(), expected_kind);
    }
}

#[tokio::test]
async fn wire_heartbeats_reset_the_sse_idle_deadline() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let _ = read_request(&mut socket).await;
        socket
            .write_all(
                b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nConnection: close\r\n\r\n",
            )
            .await
            .unwrap();
        for _ in 0..4 {
            socket.write_all(b": heartbeat\n\n").await.unwrap();
            socket.flush().await.unwrap();
            tokio::time::sleep(Duration::from_millis(30)).await;
        }
        socket
            .write_all(
                b"data: {\"choices\":[{\"delta\":{\"content\":\"ok\"}}]}\n\ndata: [DONE]\n\n",
            )
            .await
            .unwrap();
    });
    let mut request = ChatRequest::user("trustedrouter/fast", "ping");
    request.call_options.timeout = Some(Duration::from_millis(70));
    let client = Client::builder()
        .api_base_url(format!("http://{address}/v1"))
        .max_retries(0)
        .build()
        .unwrap();
    let mut stream = client.chat_completions_text(request).await.unwrap();
    let mut text = String::new();
    while let Some(item) = stream.next().await {
        text.push_str(&item.unwrap());
    }
    assert_eq!(text, "ok");
    server.await.unwrap();
}

async fn retry_faulty_error_body(stall: bool) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let mut keys = Vec::new();
        let (mut first, _) = listener.accept().await.unwrap();
        let request = String::from_utf8(read_request(&mut first).await).unwrap();
        keys.push(header_value(&request, "idempotency-key").unwrap());
        first
            .write_all(b"HTTP/1.1 503 Service Unavailable\r\nContent-Type: application/json\r\nContent-Length: 128\r\nConnection: close\r\n\r\n{")
            .await
            .unwrap();
        if stall {
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_secs(2)).await;
                drop(first);
            });
        } else {
            drop(first);
        }

        let (mut second, _) = tokio::time::timeout(Duration::from_secs(2), listener.accept())
            .await
            .unwrap()
            .unwrap();
        let request = String::from_utf8(read_request(&mut second).await).unwrap();
        keys.push(header_value(&request, "idempotency-key").unwrap());
        let body = b"{\"ok\":true}";
        second
            .write_all(
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        second.write_all(body).await.unwrap();
        keys
    });

    let client = Client::builder()
        .api_base_url(format!("http://{address}/v1"))
        .max_retries(1)
        .timeout(Some(Duration::from_millis(80)))
        .build()
        .unwrap();
    let result: Value = client
        .request(
            Plane::Inference,
            Method::POST,
            "/custom-mutation",
            Some(json!({"value": 1})),
            CallOptions {
                idempotency_key: Some("stable-key".to_owned()),
                ..CallOptions::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(result, json!({"ok": true}));
    assert_eq!(server.await.unwrap(), vec!["stable-key", "stable-key"]);
}

async fn read_request(socket: &mut TcpStream) -> Vec<u8> {
    let mut request = Vec::new();
    let mut buffer = [0_u8; 2048];
    loop {
        let read = socket.read(&mut buffer).await.unwrap();
        if read == 0 {
            break;
        }
        request.extend_from_slice(&buffer[..read]);
        if let Some(headers_end) = find_bytes(&request, b"\r\n\r\n") {
            let headers = String::from_utf8_lossy(&request[..headers_end]);
            let content_length = header_value(&headers, "content-length")
                .and_then(|value| value.parse::<usize>().ok())
                .unwrap_or(0);
            if request.len() >= headers_end + 4 + content_length {
                break;
            }
        }
    }
    request
}

fn header_value(request: &str, name: &str) -> Option<String> {
    request.lines().find_map(|line| {
        let (key, value) = line.split_once(':')?;
        key.eq_ignore_ascii_case(name)
            .then(|| value.trim().to_owned())
    })
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}
