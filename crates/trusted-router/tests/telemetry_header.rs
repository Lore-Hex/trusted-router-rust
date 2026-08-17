//! The `x-tr-client` header channel, client telemetry contract v1 (§6.4).
//!
//! Every wire test drives the real engine loop through the public API against
//! a live loopback mock — never a reimplementation of the header logic. The
//! real apex hostname reaches the mock through `reqwest`'s DNS override, so
//! the host mapping classifies exactly what production would see.

#![allow(missing_docs)]

use futures_util::StreamExt;
use http::Method;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::sync::Mutex;
use trusted_router::{
    CallOptions, ChatRequest, Client, ModelFilters, Plane, DEFAULT_TELEMETRY_PATH,
    TELEMETRY_ENDPOINTS, TELEMETRY_ERROR_CLASSES, TELEMETRY_HOSTS, TELEMETRY_OUTCOMES,
    TELEMETRY_SCHEMA_VERSION, VERSION,
};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

const APEX_HOST: &str = "api.trustedrouter.com";

/// One lock for every test that mutates process environment variables:
/// `cargo test` runs tests in this binary on parallel threads, and the
/// environment is process-global.
static ENV_LOCK: Mutex<()> = Mutex::const_new(());

fn resolving_http() -> reqwest::Client {
    reqwest::Client::builder()
        .resolve(APEX_HOST, std::net::SocketAddr::from(([127, 0, 0, 1], 0)))
        .build()
        .unwrap()
}

/// A client whose base URL carries the real apex hostname but whose traffic
/// lands on the loopback mock.
fn apex_client(server: &MockServer, telemetry: Option<bool>) -> Client {
    let mut builder = Client::builder()
        .api_key("sk-test")
        .api_base_url(format!("http://{APEX_HOST}:{}/v1", server.address().port()))
        .max_retries(0)
        .http_client(resolving_http());
    if let Some(value) = telemetry {
        builder = builder.telemetry(value);
    }
    builder.build().unwrap()
}

async fn mock_chat(server: &MockServer) {
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id": "chat_1",
            "choices": [{"index": 0, "message": {"role": "assistant", "content": "ok"}}]
        })))
        .mount(server)
        .await;
}

async fn header_values(server: &MockServer, name: &str) -> Vec<Option<String>> {
    server
        .received_requests()
        .await
        .unwrap()
        .iter()
        .map(|request| {
            request
                .headers
                .get(name)
                .map(|value| value.to_str().unwrap().to_owned())
        })
        .collect()
}

#[tokio::test]
async fn attempt_zero_buffered_header_is_exact_on_the_wire() {
    let server = MockServer::start().await;
    mock_chat(&server).await;
    apex_client(&server, Some(true))
        .chat_completions(ChatRequest::user("trustedrouter/auto", "ping"))
        .await
        .unwrap();
    assert_eq!(
        header_values(&server, "x-tr-client").await,
        vec![Some("v=1;a=0;s=0".to_owned())]
    );
}

#[tokio::test]
async fn attempt_zero_streaming_header_is_exact_on_the_wire() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "text/event-stream")
                .set_body_raw(
                    "data: {\"id\":\"chunk_1\",\"choices\":[{\"delta\":{\"content\":\"ok\"}}]}\n\ndata: [DONE]\n\n",
                    "text/event-stream",
                ),
        )
        .mount(&server)
        .await;
    let mut stream = apex_client(&server, Some(true))
        .chat_completions_text(ChatRequest::user("trustedrouter/auto", "ping"))
        .await
        .unwrap();
    while let Some(delta) = stream.next().await {
        delta.unwrap();
    }
    assert_eq!(
        header_values(&server, "x-tr-client").await,
        vec![Some("v=1;a=0;s=1".to_owned())]
    );
}

#[tokio::test]
async fn a_custom_base_url_sends_no_header_even_when_telemetry_is_on() {
    // A self-hosted gateway is not TrustedRouter's to measure (§3.2), and the
    // request must still go out unharmed. A caller-forged x-tr-client must
    // not slip through either: the live recorder owns the header outright.
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id": "chat_1",
            "choices": [{"index": 0, "message": {"role": "assistant", "content": "ok"}}]
        })))
        .mount(&server)
        .await;
    let client = Client::builder()
        .api_key("sk-test")
        .api_base_url(format!("{}/v1", server.uri()))
        .telemetry(true)
        .header("x-tr-client", "v=1;a=0;s=1")
        .max_retries(0)
        .build()
        .unwrap();
    client
        .chat_completions(ChatRequest::user("trustedrouter/auto", "ping"))
        .await
        .unwrap();
    assert_eq!(header_values(&server, "x-tr-client").await, vec![None]);
}

#[tokio::test]
async fn control_plane_calls_are_never_traced() {
    // Plane::Control never constructs a recorder, so there is no header and
    // no per-attempt recording at all (§3.2).
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/models"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"data": []})))
        .mount(&server)
        .await;
    let client = Client::builder()
        .api_key("sk-test")
        .control_base_url(format!("{}/v1", server.uri()))
        .telemetry(true)
        .max_retries(0)
        .build()
        .unwrap();
    assert!(client
        .models(ModelFilters::default())
        .await
        .unwrap()
        .data
        .is_empty());
    assert_eq!(header_values(&server, "x-tr-client").await, vec![None]);
}

#[tokio::test]
async fn the_attestation_fetch_is_never_traced() {
    // Attestation rides the inference plane in Rust but is fetched outside
    // the engine in the Python SDK; no SDK sends x-tr-client on it.
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/attestation"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(b"evidence".to_vec()))
        .mount(&server)
        .await;
    apex_client(&server, Some(true))
        .attestation(None)
        .await
        .unwrap();
    assert_eq!(header_values(&server, "x-tr-client").await, vec![None]);
}

#[tokio::test]
async fn the_user_agent_matches_the_contract_grammar() {
    // §3.1: trusted-router-rust/SEMVER( runtime/ver)?. The static identity
    // rides the User-Agent, never the x-tr-client header, and survives
    // telemetry opt-out.
    let server = MockServer::start().await;
    mock_chat(&server).await;
    apex_client(&server, Some(false))
        .chat_completions(ChatRequest::user("trustedrouter/auto", "ping"))
        .await
        .unwrap();
    let user_agents = header_values(&server, "user-agent").await;
    assert_eq!(
        user_agents,
        vec![Some(format!("trusted-router-rust/{VERSION}"))]
    );
    let mut parts = VERSION.split('.');
    let release: Vec<&str> = [parts.next(), parts.next(), parts.next()]
        .into_iter()
        .flatten()
        .collect();
    assert_eq!(release.len(), 3, "crate version {VERSION} is not SEMVER");
    assert!(parts.next().is_none());
    assert!(
        release
            .iter()
            .all(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit())),
        "crate version {VERSION} is not SEMVER"
    );
    // Opt-out suppressed the telemetry header but not the User-Agent.
    assert_eq!(header_values(&server, "x-tr-client").await, vec![None]);
}

#[tokio::test]
async fn opt_out_precedence_drives_the_real_builder() {
    // §6.3 precedence through Client::builder().build(), which reads the real
    // process environment: explicit argument > TRUSTEDROUTER_TELEMETRY >
    // DO_NOT_TRACK > default (on only for TR hosts). One test function so the
    // environment mutations cannot race a parallel test in this binary.
    let _guard = ENV_LOCK.lock().await;
    let saved_telemetry = std::env::var("TRUSTEDROUTER_TELEMETRY").ok();
    let saved_dnt = std::env::var("DO_NOT_TRACK").ok();
    let restore = |name: &str, value: &Option<String>| match value {
        Some(value) => std::env::set_var(name, value),
        None => std::env::remove_var(name),
    };

    let server = MockServer::start().await;
    mock_chat(&server).await;
    let call = |telemetry: Option<bool>| {
        let client = apex_client(&server, telemetry);
        async move {
            client
                .chat_completions(ChatRequest::user("trustedrouter/auto", "ping"))
                .await
                .unwrap();
        }
    };

    // Explicit false beats an enabling environment.
    std::env::set_var("TRUSTEDROUTER_TELEMETRY", "1");
    std::env::remove_var("DO_NOT_TRACK");
    call(Some(false)).await;
    // TRUSTEDROUTER_TELEMETRY=0 disables on its own, DO_NOT_TRACK unset.
    std::env::set_var("TRUSTEDROUTER_TELEMETRY", "0");
    call(None).await;
    // DO_NOT_TRACK=1 disables when TRUSTEDROUTER_TELEMETRY is unset.
    std::env::remove_var("TRUSTEDROUTER_TELEMETRY");
    std::env::set_var("DO_NOT_TRACK", "1");
    call(None).await;
    // Clean environment: default ON for a TrustedRouter host with the
    // default HTTPS control plane.
    std::env::remove_var("TRUSTEDROUTER_TELEMETRY");
    std::env::remove_var("DO_NOT_TRACK");
    call(None).await;

    restore("TRUSTEDROUTER_TELEMETRY", &saved_telemetry);
    restore("DO_NOT_TRACK", &saved_dnt);

    assert_eq!(
        header_values(&server, "x-tr-client").await,
        vec![None, None, None, Some("v=1;a=0;s=0".to_owned())]
    );
}

#[tokio::test]
async fn default_is_off_for_a_custom_base_url() {
    let _guard = ENV_LOCK.lock().await;
    let saved_telemetry = std::env::var("TRUSTEDROUTER_TELEMETRY").ok();
    let saved_dnt = std::env::var("DO_NOT_TRACK").ok();
    std::env::remove_var("TRUSTEDROUTER_TELEMETRY");
    std::env::remove_var("DO_NOT_TRACK");

    let server = MockServer::start().await;
    mock_chat(&server).await;
    let client = Client::builder()
        .api_key("sk-test")
        .api_base_url(format!("{}/v1", server.uri()))
        .max_retries(0)
        .build()
        .unwrap();
    client
        .chat_completions(ChatRequest::user("trustedrouter/auto", "ping"))
        .await
        .unwrap();

    match saved_telemetry {
        Some(value) => std::env::set_var("TRUSTEDROUTER_TELEMETRY", value),
        None => std::env::remove_var("TRUSTEDROUTER_TELEMETRY"),
    }
    match saved_dnt {
        Some(value) => std::env::set_var("DO_NOT_TRACK", value),
        None => std::env::remove_var("DO_NOT_TRACK"),
    }

    assert_eq!(header_values(&server, "x-tr-client").await, vec![None]);
}

#[tokio::test]
async fn a_forged_reserved_header_never_reaches_the_wire() {
    // §3.2: x-tr-client is SDK-owned unconditionally. With telemetry OFF on a
    // custom base — the weakest configuration — a caller-supplied value must
    // be dropped, and an unparseable one must not fail the request (§2.2).
    let server = MockServer::start().await;
    mock_chat(&server).await;
    let client = Client::builder()
        .api_key("sk-test")
        .api_base_url(format!("{}/v1", server.uri()))
        .telemetry(false)
        .header("x-tr-client", "v=1;a=0;s=1")
        .header("X-TR-CLIENT", "forged\nnewline value")
        .max_retries(0)
        .build()
        .unwrap();
    client
        .chat_completions(ChatRequest::user("trustedrouter/auto", "ping"))
        .await
        .unwrap();
    assert_eq!(header_values(&server, "x-tr-client").await, vec![None]);
}

#[tokio::test]
async fn a_forged_reserved_header_is_dropped_on_control_plane_calls() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/models"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"data": []})))
        .mount(&server)
        .await;
    let client = Client::builder()
        .api_key("sk-test")
        .control_base_url(format!("{}/v1", server.uri()))
        .header("x-tr-client", "v=1;a=0;s=0")
        .max_retries(0)
        .build()
        .unwrap();
    client.models(ModelFilters::default()).await.unwrap();
    assert_eq!(header_values(&server, "x-tr-client").await, vec![None]);
}

#[tokio::test]
async fn dot_segments_cannot_dodge_the_attestation_exclusion() {
    // /x/../attestation resolves to /v1/attestation inside the router; the
    // telemetry scope decision must see the resolved path, not the raw one.
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/attestation"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"ok": true})))
        .mount(&server)
        .await;
    apex_client(&server, Some(true))
        .request::<serde_json::Value>(
            Plane::Inference,
            Method::GET,
            "/x/../attestation",
            None,
            CallOptions::default(),
        )
        .await
        .unwrap();
    assert_eq!(header_values(&server, "x-tr-client").await, vec![None]);
}

#[tokio::test]
async fn an_injected_default_reserved_header_is_replaced_when_telemetry_is_active() {
    // The reservation is re-enforced on the BUILT request, so the slot is
    // occupied by the SDK's value and reqwest's insert-if-vacant defaults
    // merge cannot substitute a stale caller value.
    let server = MockServer::start().await;
    mock_chat(&server).await;
    let mut defaults = reqwest::header::HeaderMap::new();
    defaults.insert(
        "x-tr-client",
        reqwest::header::HeaderValue::from_static("v=9;a=9;s=9"),
    );
    let http = reqwest::Client::builder()
        .resolve(APEX_HOST, std::net::SocketAddr::from(([127, 0, 0, 1], 0)))
        .default_headers(defaults)
        .build()
        .unwrap();
    let client = Client::builder()
        .api_key("sk-test")
        .api_base_url(format!("http://{APEX_HOST}:{}/v1", server.address().port()))
        .telemetry(true)
        .max_retries(0)
        .http_client(http)
        .build()
        .unwrap();
    client
        .chat_completions(ChatRequest::user("trustedrouter/auto", "ping"))
        .await
        .unwrap();
    assert_eq!(
        header_values(&server, "x-tr-client").await,
        vec![Some("v=1;a=0;s=0".to_owned())]
    );
}

#[tokio::test]
async fn an_injected_default_reserved_header_on_suppressed_attempts_is_a_documented_boundary() {
    // reqwest merges an injected client's default_headers INSERT-IF-VACANT
    // inside its own execute path (reqwest 0.12 async_impl/client.rs,
    // execute_request), after the request has left the SDK. A suppressed
    // attempt deliberately leaves the slot vacant, so a caller who
    // configured x-tr-client as a client-wide default on their own injected
    // reqwest client ships that value themselves — the SDK cannot reach
    // past the merge without occupying the slot, i.e. sending bytes it must
    // not send. This canary pins the boundary: if reqwest's merge semantics
    // change or a per-request lever appears, this test fails and the
    // reservation should be extended.
    let server = MockServer::start().await;
    mock_chat(&server).await;
    let mut defaults = reqwest::header::HeaderMap::new();
    defaults.insert(
        "x-tr-client",
        reqwest::header::HeaderValue::from_static("v=9;a=9;s=9"),
    );
    let http = reqwest::Client::builder()
        .resolve(APEX_HOST, std::net::SocketAddr::from(([127, 0, 0, 1], 0)))
        .default_headers(defaults)
        .build()
        .unwrap();
    let client = Client::builder()
        .api_key("sk-test")
        .api_base_url(format!("http://{APEX_HOST}:{}/v1", server.address().port()))
        .telemetry(false)
        .max_retries(0)
        .http_client(http)
        .build()
        .unwrap();
    client
        .chat_completions(ChatRequest::user("trustedrouter/auto", "ping"))
        .await
        .unwrap();
    assert_eq!(
        header_values(&server, "x-tr-client").await,
        vec![Some("v=9;a=9;s=9".to_owned())],
        "if this starts failing, reqwest changed and the reservation can now be completed"
    );
}

#[tokio::test]
async fn dot_segments_cannot_dodge_the_authorize_exclusion() {
    // §2.2 hard MUST: client context is never sent on the authorize route,
    // whatever plane the caller labels the request with and however the
    // path is spelled.
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/internal/gateway/authorize"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"ok": true})))
        .mount(&server)
        .await;
    apex_client(&server, Some(true))
        .request::<serde_json::Value>(
            Plane::Inference,
            Method::POST,
            "/x/../internal/gateway/authorize",
            Some(serde_json::json!({})),
            CallOptions::default(),
        )
        .await
        .unwrap();
    assert_eq!(header_values(&server, "x-tr-client").await, vec![None]);
}

#[tokio::test]
async fn percent_encoded_spellings_cannot_dodge_the_authorize_exclusion() {
    // §2.2 is a hard MUST, so the exclusion has to survive every spelling of
    // the route that still reaches it — not just the dot-segment one that
    // Url::join happens to normalise. `Url::path` keeps percent escapes, so a
    // literal-text check let `%61uthorize` reach the wire with a header while
    // the gateway's request parser decoded it straight back to authorize.
    for spelling in [
        "/internal/gateway/%61uthorize",
        "/internal/gateway/authoriz%65",
        "/INTERNAL/GATEWAY/AUTHORIZE",
        "/internal//gateway/authorize",
    ] {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"ok": true})))
            .mount(&server)
            .await;
        apex_client(&server, Some(true))
            .request::<serde_json::Value>(
                Plane::Inference,
                Method::POST,
                spelling,
                Some(serde_json::json!({})),
                CallOptions::default(),
            )
            .await
            .unwrap();
        assert_eq!(
            header_values(&server, "x-tr-client").await,
            vec![None],
            "authorize spelled {spelling} must never carry client context"
        );
    }
}

#[tokio::test]
async fn a_percent_encoded_attestation_path_is_never_traced() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"ok": true})))
        .mount(&server)
        .await;
    apex_client(&server, Some(true))
        .request::<serde_json::Value>(
            Plane::Inference,
            Method::GET,
            "/%61ttestation",
            None,
            CallOptions::default(),
        )
        .await
        .unwrap();
    assert_eq!(header_values(&server, "x-tr-client").await, vec![None]);
}

#[tokio::test]
async fn a_forced_retry_after_a_sub_400_response_reports_po_none() {
    // A 302 without a Location header passes through reqwest untouched, and
    // x-should-retry: true forces the engine to retry it in place. §3.2's po
    // vocabulary has no "ok", so the retry header degrades to po=none;
    // pc=none instead of a value the enclave would drop the header for.
    let server = MockServer::start().await;
    let calls = Arc::new(AtomicUsize::new(0));
    let observed = Arc::clone(&calls);
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(move |_request: &Request| {
            if observed.fetch_add(1, Ordering::SeqCst) == 0 {
                ResponseTemplate::new(302)
                    .insert_header("x-should-retry", "true")
                    .set_body_json(serde_json::json!({}))
            } else {
                ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "id": "chat_1",
                    "choices": [{"index": 0, "message": {"role": "assistant", "content": "ok"}}]
                }))
            }
        })
        .mount(&server)
        .await;
    let client = Client::builder()
        .api_key("sk-test")
        .api_base_url(format!("http://{APEX_HOST}:{}/v1", server.address().port()))
        .max_retries(1)
        .telemetry(true)
        .http_client(resolving_http())
        .build()
        .unwrap();
    client
        .chat_completions(ChatRequest::user("trustedrouter/auto", "ping"))
        .await
        .unwrap();
    let headers = header_values(&server, "x-tr-client").await;
    assert_eq!(headers[0].as_deref(), Some("v=1;a=0;s=0"));
    let retry = headers[1]
        .as_deref()
        .expect("retry attempt sends the header");
    assert!(
        retry.starts_with("v=1;a=1;po=none;pc=none;ph=apex;pm="),
        "{retry}"
    );
    assert!(retry.ends_with(";s=0;fo=0"), "{retry}");
}

#[tokio::test]
async fn a_saturated_single_candidate_retry_reports_no_failover() {
    // One candidate, a 503, then success on the same host: the cursor's
    // advance saturates, so the retry header must say fo=0 with ph=apex.
    let server = MockServer::start().await;
    let calls = Arc::new(AtomicUsize::new(0));
    let observed = Arc::clone(&calls);
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(move |_request: &Request| {
            if observed.fetch_add(1, Ordering::SeqCst) == 0 {
                ResponseTemplate::new(503)
                    .set_body_json(serde_json::json!({"error": {"message": "unavailable"}}))
            } else {
                ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "id": "chat_1",
                    "choices": [{"index": 0, "message": {"role": "assistant", "content": "ok"}}]
                }))
            }
        })
        .mount(&server)
        .await;
    let client = Client::builder()
        .api_key("sk-test")
        .api_base_url(format!("http://{APEX_HOST}:{}/v1", server.address().port()))
        .max_retries(1)
        .telemetry(true)
        .http_client(resolving_http())
        .build()
        .unwrap();
    client
        .chat_completions(ChatRequest::user("trustedrouter/auto", "ping"))
        .await
        .unwrap();
    let headers = header_values(&server, "x-tr-client").await;
    assert_eq!(headers[0].as_deref(), Some("v=1;a=0;s=0"));
    let retry = headers[1]
        .as_deref()
        .expect("retry attempt sends the header");
    assert!(retry.starts_with("v=1;a=1;po=http_error;pc=none;ph=apex;pm="));
    assert!(
        retry.ends_with(";s=0;fo=0"),
        "saturated advance is not failover: {retry}"
    );
    assert!(retry.len() <= 160);
}

#[test]
fn parity_constants_pin_the_contract_vocabulary() {
    // §6.4: the beacon path, schema version, and closed enums are pinned so
    // the later beacon PR cannot drift from the vocabulary the header channel
    // already shipped.
    assert_eq!(TELEMETRY_SCHEMA_VERSION, 1);
    assert_eq!(DEFAULT_TELEMETRY_PATH, "/client-events");
    assert_eq!(
        TELEMETRY_HOSTS,
        [
            "apex",
            "ally",
            "uptime",
            "us_central1",
            "us_east4",
            "europe_west4",
            "control",
            "custom",
        ]
    );
    assert_eq!(
        TELEMETRY_ENDPOINTS,
        [
            "chat_completions",
            "messages",
            "responses",
            "embeddings",
            "images",
            "videos",
            "models",
            "fusion",
            "control_other",
            "inference_other",
        ]
    );
    assert_eq!(
        TELEMETRY_OUTCOMES,
        [
            "ok",
            "http_error",
            "transport_error",
            "timeout",
            "stream_broken",
            "aborted",
        ]
    );
    assert_eq!(
        TELEMETRY_ERROR_CLASSES,
        [
            "dns",
            "tls",
            "connect_refused",
            "connect_timeout",
            "connect_error",
            "read_timeout",
            "write_timeout",
            "pool_timeout",
            "protocol_error",
            "reset",
            "io_error",
            "proxy_error",
            "stream_stalled",
            "unknown",
        ]
    );
}
