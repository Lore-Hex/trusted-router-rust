//! L3 — the transport engine: THE single retry/failover loop.
//!
//! [`Client::execute`] is the only loop in the workspace that retries a
//! request. [`CandidateCursor::advance`] is the ONLY place a base-URL
//! candidate index advances, and the [`tokio::time::sleep`] below is the only
//! sleep. `request_bytes` and `open_stream` (in [`crate::transport`]) are
//! thin entry points over `execute`; the blocking facade and the FFI crate
//! inherit this exact loop with zero copies.
//!
//! The engine never drains a success body: `open_stream`'s contract is an
//! UNDRAINED [`reqwest::Response`], and draining here would pass wiremock
//! tests while breaking production streaming (that exact bug class is why the
//! 2xx arm returns immediately). It also never retries after the first
//! surfaced body byte — a broken open stream propagates, never reconnects
//! (invariant 6).

use crate::client::{CallOptions, Client, Plane};
use crate::telemetry::{self, ErrorClass, RequestRecorder};
use crate::transport::policy::{self, FailureDisposition};
use crate::{Error, Result};
use http::Method;
use serde_json::Value;
use std::time::Duration;
use tokio::time::{sleep, timeout};
use url::Url;

/// A `send` failure with its typed cause still intact. The telemetry class is
/// read off this BEFORE [`policy::map_reqwest_error`] flattens the error to a
/// message string — after that point the class is unrecoverable.
enum SendFailure {
    /// The SDK's own response-headers deadline elapsed.
    Deadline,
    /// The transport failed with a typed [`reqwest::Error`].
    Transport(reqwest::Error),
}

/// Saturating cursor over the candidate list.
///
/// `advance` never wraps and never runs past the final candidate: once the
/// list is exhausted the engine keeps retrying the last host in place. A
/// single-candidate list (control plane, pinned client, custom base URL)
/// therefore makes failover structurally impossible — the list length is the
/// gate, not a second flag.
struct CandidateCursor {
    index: usize,
    len: usize,
}

impl CandidateCursor {
    fn new(len: usize) -> Self {
        Self { index: 0, len }
    }

    fn index(&self) -> usize {
        self.index
    }

    /// The workspace's ONLY base-index advance site. Returns whether the
    /// index actually moved: a saturated advance at the end of the list is
    /// not a failover, and must not set the telemetry `fo` bit.
    fn advance(&mut self) -> bool {
        if self.index + 1 < self.len {
            self.index += 1;
            return true;
        }
        false
    }
}

impl Client {
    /// Drives one logical call to a terminal outcome: an undrained success
    /// [`reqwest::Response`], or the classified error of the final attempt.
    ///
    /// The load-bearing orderings, in loop order:
    /// 1. Candidates are resolved ONCE per logical call, never per attempt.
    /// 2. Each attempt targets `candidates[cursor.index()]` with per-attempt
    ///    headers and the per-attempt deadline.
    /// 3. 2xx returns the response UNTOUCHED — never drained here.
    /// 4. Non-2xx drains the failure body under the deadline BEFORE the
    ///    retry-ceiling check; a body-read error still propagates.
    /// 5. Transport errors always mark `failover` — no server saw the request,
    ///    so moving cannot double-execute anything.
    /// 6. The ceiling check makes total attempts `max_retries + 1`.
    /// 7. The cursor advances only on a failover-marked disposition.
    /// 8. The engine sleeps the jittered, retry-after-floored delay.
    /// 9. The attempt counter advances AFTER the sleep.
    ///
    /// This loop is also the SDK's single telemetry emit point (client
    /// telemetry contract v1, §6.1): the per-call [`RequestRecorder`] observes
    /// every attempt here, and nowhere else, so the `x-tr-client` header can
    /// never disagree with what the engine actually did. Control-plane calls
    /// and the attestation fetch get no recorder at all.
    pub(crate) async fn execute(
        &self,
        plane: Plane,
        method: Method,
        path: &str,
        body: Option<Value>,
        options: &CallOptions,
        streaming: bool,
    ) -> Result<reqwest::Response> {
        // Candidates, not one pinned URL: computing a single URL outside the
        // loop is how failover once could not move even in principle.
        let candidates = self.plane_urls(plane, path)?;
        // Telemetry scope is decided from the RESOLVED candidate path, not
        // the caller's raw string, so `/x/../attestation` cannot dodge the
        // attestation exclusion via Url::join's dot-segment normalisation.
        let resolved_path = candidates.first().map_or(path, Url::path);
        let mut recorder = self.request_recorder(plane, resolved_path, streaming);
        let mut cursor = CandidateCursor::new(candidates.len());
        let mut attempt = 0;
        loop {
            let url = candidates[cursor.index()].clone();
            if let Some(recorder) = recorder.as_mut() {
                recorder.begin_attempt(&url);
            }
            let disposition = match self
                .send_once(
                    method.clone(),
                    url,
                    body.clone(),
                    options,
                    recorder.as_mut(),
                )
                .await
            {
                Ok(response) if response.status().is_success() => {
                    if let Some(recorder) = recorder.as_mut() {
                        recorder.on_response(response.status().as_u16());
                    }
                    return Ok(response);
                }
                Ok(response) => {
                    let status = response.status();
                    if let Some(recorder) = recorder.as_mut() {
                        recorder.on_response(status.as_u16());
                    }
                    let headers = response.headers().clone();
                    // Drain the failure body before deciding anything: the
                    // classified error needs the payload, and a read failure
                    // must surface as itself, not as a retry decision.
                    let bytes = self.read_response(response, options).await?;
                    let payload = serde_json::from_slice::<Value>(&bytes).ok();
                    FailureDisposition::from_http(status.as_u16(), &headers, payload)
                }
                Err(error) => FailureDisposition::from_transport(error),
            };
            if attempt >= self.max_retries || !disposition.retry {
                return Err(disposition.error);
            }
            // Only gateway-level statuses (and transport errors) move domains.
            // A 500 means a server received and processed the request, and
            // inference is not idempotent, so retrying it elsewhere risks
            // running the work again: not a double charge to the caller, but a
            // second upstream generation we pay for.
            if disposition.failover && cursor.advance() {
                if let Some(recorder) = recorder.as_mut() {
                    recorder.on_moved();
                }
            }
            sleep(policy::retry_delay(attempt, disposition.retry_after)).await;
            attempt += 1;
        }
    }

    /// Builds the per-call recorder, or `None` when the call is out of the
    /// header channel's scope: telemetry opted out, a control-plane call, or
    /// the attestation fetch (out-of-engine in the Python SDK, so no SDK
    /// sends `x-tr-client` on it).
    fn request_recorder(
        &self,
        plane: Plane,
        path: &str,
        streaming: bool,
    ) -> Option<RequestRecorder> {
        if !self.telemetry || plane != Plane::Inference || !telemetry::tracked_inference_path(path)
        {
            return None;
        }
        Some(RequestRecorder::new(streaming))
    }

    async fn send_once(
        &self,
        method: Method,
        url: Url,
        body: Option<Value>,
        options: &CallOptions,
        recorder: Option<&mut RequestRecorder>,
    ) -> Result<reqwest::Response> {
        let headers = self.request_headers(options, recorder.as_deref())?;
        let mut request = self.http.request(method, url).headers(headers);
        if let Some(body) = body {
            request = request.json(&body);
        }
        let deadline = options.timeout.or(self.timeout);
        match Self::send_raw(request, deadline).await {
            Ok(response) => Ok(response),
            Err(failure) => {
                // Classify while the typed error still exists; the map below
                // flattens it to a string (§6.1 capture-before-flattening).
                if let Some(recorder) = recorder {
                    match &failure {
                        // The headers deadline bounds connect + time to first
                        // byte; the read wait is the phase it cuts short.
                        SendFailure::Deadline => {
                            recorder.on_transport_error(ErrorClass::ReadTimeout, true);
                        }
                        SendFailure::Transport(error) => recorder.on_transport_error(
                            telemetry::classify_transport_error(error),
                            error.is_timeout(),
                        ),
                    }
                }
                Err(match failure {
                    SendFailure::Deadline => {
                        Error::Timeout("response headers deadline exceeded".to_owned())
                    }
                    SendFailure::Transport(error) => policy::map_reqwest_error(error),
                })
            }
        }
    }

    /// Sends one attempt under the per-attempt deadline, keeping the typed
    /// failure. `Duration::ZERO` (like no configured deadline) disables the
    /// SDK timeout, preserving the documented `timeout` contract.
    async fn send_raw(
        request: reqwest::RequestBuilder,
        deadline: Option<Duration>,
    ) -> std::result::Result<reqwest::Response, SendFailure> {
        match deadline {
            Some(duration) if duration != Duration::ZERO => {
                match timeout(duration, request.send()).await {
                    Ok(sent) => sent.map_err(SendFailure::Transport),
                    Err(_) => Err(SendFailure::Deadline),
                }
            }
            _ => request.send().await.map_err(SendFailure::Transport),
        }
    }

    pub(crate) async fn read_response(
        &self,
        response: reqwest::Response,
        options: &CallOptions,
    ) -> Result<bytes::Bytes> {
        let deadline = options.timeout.or(self.timeout);
        if deadline == Some(Duration::ZERO) {
            return response.bytes().await.map_err(policy::map_reqwest_error);
        }
        match deadline {
            Some(duration) => timeout(duration, response.bytes())
                .await
                .map_err(|_| Error::Timeout("response body deadline exceeded".to_owned()))?
                .map_err(policy::map_reqwest_error),
            None => response.bytes().await.map_err(policy::map_reqwest_error),
        }
    }
}

/// End-to-end proof that the STREAMING open walks the candidate list too.
///
/// These live in the crate rather than `tests/` so they can set
/// `api_base_urls` directly: the aliases only activate for the real default
/// host, which no test can reach, so two local servers stand in for two
/// domains. Without this the streaming walk had no coverage at all — it was a
/// single pinned URL and nothing noticed.
///
/// The two domains carry the REAL apex and ally hostnames, DNS-overridden to
/// the loopback mocks via `reqwest`'s resolver: the telemetry host mapping
/// sees `api.trustedrouter.com`, so the same walk also proves the
/// `x-tr-client` header rides every attempt with the §3.2 facts.
#[cfg(test)]
mod candidate_walk_tests {
    use crate::client::{CallOptions, Client, Plane};
    use http::Method;
    use serde_json::json;
    use url::Url;
    use wiremock::matchers::method as method_matcher;
    use wiremock::{Mock, MockServer, Request, ResponseTemplate};

    const APEX_HOST: &str = "api.trustedrouter.com";
    const ALLY_HOST: &str = "api.allyrouter.com";

    fn base(host: &str, server: &MockServer) -> Url {
        // Trailing slash so `join` appends instead of replacing the last
        // segment, matching what parse_base_url does for real base URLs.
        // Real hostname, loopback socket: the port comes from the URL because
        // the DNS override below carries only the IP.
        Url::parse(&format!("http://{host}:{}/v1/", server.address().port())).unwrap()
    }

    fn loopback_resolver() -> reqwest::Client {
        let loopback = std::net::SocketAddr::from(([127, 0, 0, 1], 0));
        reqwest::Client::builder()
            .resolve(APEX_HOST, loopback)
            .resolve(ALLY_HOST, loopback)
            .build()
            .unwrap()
    }

    async fn two_hosts(first_status: u16) -> (MockServer, MockServer) {
        let down = MockServer::start().await;
        let up = MockServer::start().await;
        Mock::given(method_matcher("POST"))
            .respond_with(ResponseTemplate::new(first_status).set_body_json(json!({
                "error": {"message": "unavailable"}
            })))
            .mount(&down)
            .await;
        Mock::given(method_matcher("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_string("data: [DONE]\n\n"))
            .mount(&up)
            .await;
        (down, up)
    }

    fn client_over(down: &MockServer, up: &MockServer) -> Client {
        let mut client = Client::builder()
            .api_key("sk-test")
            .max_retries(2)
            .telemetry(true)
            .http_client(loopback_resolver())
            .build()
            .unwrap();
        // Set the singular base too. A regression back to a pinned
        // `relative_url` would otherwise fall through to the real default host
        // and put a live network call inside the test suite — the failure would
        // still show up, but for the wrong reason and off-machine.
        client.api_base_url = base(APEX_HOST, down);
        client.api_base_urls = vec![base(APEX_HOST, down), base(ALLY_HOST, up)];
        client
    }

    fn tr_client_header(request: &Request) -> Option<String> {
        request
            .headers
            .get("x-tr-client")
            .map(|value| value.to_str().unwrap().to_owned())
    }

    /// Splits a retry header into its §3.2 fields, asserting exact key order,
    /// the value grammar, and the 160-byte bound along the way.
    fn parsed_retry_header(header: &str) -> Vec<(String, String)> {
        assert!(header.len() <= 160, "{header:?} breaks the byte bound");
        let pairs: Vec<(String, String)> = header
            .split(';')
            .map(|part| {
                let (key, value) = part.split_once('=').expect("key=value");
                assert!(
                    !value.is_empty()
                        && value.len() <= 24
                        && value
                            .bytes()
                            .all(|byte| matches!(byte, b'a'..=b'z' | b'0'..=b'9' | b'_')),
                    "{value:?} breaks the value grammar"
                );
                (key.to_owned(), value.to_owned())
            })
            .collect();
        assert_eq!(
            pairs
                .iter()
                .map(|(key, _)| key.as_str())
                .collect::<Vec<_>>(),
            ["v", "a", "po", "pc", "ph", "pm", "sm", "s", "fo"],
            "§3.2 key order is exact"
        );
        pairs
    }

    fn field<'a>(pairs: &'a [(String, String)], name: &str) -> &'a str {
        pairs
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
            .unwrap()
    }

    #[tokio::test]
    async fn open_stream_moves_to_the_next_candidate_on_503() {
        let (down, up) = two_hosts(503).await;
        let client = client_over(&down, &up);

        let response = client
            .open_stream(
                Plane::Inference,
                Method::POST,
                "/chat/completions",
                json!({"model": "trustedrouter/auto"}),
                CallOptions::default(),
            )
            .await
            .expect("stream should open on the second candidate");

        assert!(response.status().is_success());
        let down_requests = down.received_requests().await.unwrap();
        assert_eq!(down_requests.len(), 1);
        let up_requests = up.received_requests().await.unwrap();
        assert_eq!(
            up_requests.len(),
            1,
            "streaming never reached the second domain"
        );
        // §6.4: attempt 0 pins the exact bytes; the alias attempt carries the
        // previous attempt's facts and the failover bit.
        assert_eq!(
            tr_client_header(&down_requests[0]).as_deref(),
            Some("v=1;a=0;s=1")
        );
        let retry = tr_client_header(&up_requests[0]).expect("alias attempt sends the header");
        let pairs = parsed_retry_header(&retry);
        assert_eq!(field(&pairs, "a"), "1");
        assert_eq!(field(&pairs, "po"), "http_error");
        assert_eq!(field(&pairs, "pc"), "none");
        assert_eq!(field(&pairs, "ph"), "apex");
        assert_eq!(field(&pairs, "s"), "1");
        assert_eq!(field(&pairs, "fo"), "1");
    }

    #[tokio::test]
    async fn open_stream_keeps_a_500_on_the_same_candidate() {
        // Same billing-safety rule as the non-streaming path.
        let (down, up) = two_hosts(500).await;
        let client = client_over(&down, &up);

        client
            .open_stream(
                Plane::Inference,
                Method::POST,
                "/chat/completions",
                json!({"model": "trustedrouter/auto"}),
                CallOptions::default(),
            )
            .await
            .expect_err("a 500 should surface, not move domains");

        assert_eq!(
            up.received_requests().await.unwrap().len(),
            0,
            "a 500 leaked to another domain"
        );
        assert!(
            down.received_requests().await.unwrap().len() > 1,
            "should retry in place"
        );
    }

    #[tokio::test]
    async fn request_bytes_moves_to_the_next_candidate_on_503() {
        // The buffered twin of the streaming walk above: without it, a future
        // re-fork of the buffered path could lose failover invisibly, because
        // only the streaming path proved the walk end to end.
        let (down, up) = two_hosts(503).await;
        let client = client_over(&down, &up);

        let bytes = client
            .request_bytes(
                Plane::Inference,
                Method::POST,
                "/chat/completions",
                Some(json!({"model": "trustedrouter/auto"})),
                CallOptions::default(),
            )
            .await
            .expect("the buffered call should succeed on the second candidate");

        assert!(!bytes.is_empty(), "the success body should be drained");
        let down_requests = down.received_requests().await.unwrap();
        assert_eq!(down_requests.len(), 1);
        let up_requests = up.received_requests().await.unwrap();
        assert_eq!(
            up_requests.len(),
            1,
            "the buffered path never reached the second domain"
        );
        assert_eq!(
            tr_client_header(&down_requests[0]).as_deref(),
            Some("v=1;a=0;s=0")
        );
        let retry = tr_client_header(&up_requests[0]).expect("alias attempt sends the header");
        let pairs = parsed_retry_header(&retry);
        assert_eq!(field(&pairs, "po"), "http_error");
        assert_eq!(field(&pairs, "ph"), "apex");
        assert_eq!(field(&pairs, "s"), "0");
        assert_eq!(field(&pairs, "fo"), "1");
    }

    #[tokio::test]
    async fn request_bytes_keeps_a_500_on_the_same_candidate() {
        // Same billing-safety rule, buffered path: a 500 retries in place and
        // never leaks the non-idempotent request to another domain.
        let (down, up) = two_hosts(500).await;
        let client = client_over(&down, &up);

        client
            .request_bytes(
                Plane::Inference,
                Method::POST,
                "/chat/completions",
                Some(json!({"model": "trustedrouter/auto"})),
                CallOptions::default(),
            )
            .await
            .expect_err("a 500 should surface, not move domains");

        assert_eq!(
            up.received_requests().await.unwrap().len(),
            0,
            "a 500 leaked to another domain"
        );
        let down_requests = down.received_requests().await.unwrap();
        assert!(down_requests.len() > 1, "should retry in place");
        // A retry that stayed put must say so: same host, no failover bit.
        let retry = tr_client_header(&down_requests[1]).expect("the in-place retry has a header");
        let pairs = parsed_retry_header(&retry);
        assert_eq!(field(&pairs, "a"), "1");
        assert_eq!(field(&pairs, "po"), "http_error");
        assert_eq!(field(&pairs, "ph"), "apex");
        assert_eq!(field(&pairs, "fo"), "0");
    }

    #[tokio::test]
    async fn a_transport_error_carries_its_class_to_the_next_attempt() {
        // Attempt 0 hits a port nobody listens on; the classified refusal
        // must survive into the alias attempt's header — after the policy
        // kernel flattens the error only a message string remains, so this
        // pins that the class was captured before that point.
        let up = MockServer::start().await;
        Mock::given(method_matcher("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"ok": true})))
            .mount(&up)
            .await;
        let dead_port = {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            listener.local_addr().unwrap().port()
        };
        let mut client = Client::builder()
            .api_key("sk-test")
            .max_retries(2)
            .telemetry(true)
            .http_client(loopback_resolver())
            .build()
            .unwrap();
        client.api_base_url = Url::parse(&format!("http://{APEX_HOST}:{dead_port}/v1/")).unwrap();
        client.api_base_urls = vec![client.api_base_url.clone(), base(ALLY_HOST, &up)];

        client
            .request_bytes(
                Plane::Inference,
                Method::POST,
                "/chat/completions",
                Some(json!({"model": "trustedrouter/auto"})),
                CallOptions::default(),
            )
            .await
            .expect("the call should succeed on the second candidate");

        let up_requests = up.received_requests().await.unwrap();
        assert_eq!(up_requests.len(), 1);
        let retry = tr_client_header(&up_requests[0]).expect("alias attempt sends the header");
        let pairs = parsed_retry_header(&retry);
        assert_eq!(field(&pairs, "a"), "1");
        assert_eq!(field(&pairs, "po"), "transport_error");
        assert_eq!(field(&pairs, "pc"), "connect_refused");
        assert_eq!(field(&pairs, "ph"), "apex");
        assert_eq!(field(&pairs, "fo"), "1");
    }

    #[tokio::test]
    async fn the_sdk_deadline_is_recorded_as_a_timeout() {
        // The response-headers deadline elapses on the apex; the alias
        // attempt names the timeout and its phase class.
        let down = MockServer::start().await;
        let up = MockServer::start().await;
        Mock::given(method_matcher("POST"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_delay(std::time::Duration::from_secs(5))
                    .set_body_json(json!({"ok": true})),
            )
            .mount(&down)
            .await;
        Mock::given(method_matcher("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"ok": true})))
            .mount(&up)
            .await;
        let mut client = Client::builder()
            .api_key("sk-test")
            .max_retries(1)
            .telemetry(true)
            .http_client(loopback_resolver())
            .build()
            .unwrap();
        client.api_base_url = base(APEX_HOST, &down);
        client.api_base_urls = vec![base(APEX_HOST, &down), base(ALLY_HOST, &up)];

        client
            .request_bytes(
                Plane::Inference,
                Method::POST,
                "/chat/completions",
                Some(json!({"model": "trustedrouter/auto"})),
                CallOptions {
                    timeout: Some(std::time::Duration::from_millis(100)),
                    ..CallOptions::default()
                },
            )
            .await
            .expect("the call should succeed on the second candidate");

        let up_requests = up.received_requests().await.unwrap();
        assert_eq!(up_requests.len(), 1);
        let retry = tr_client_header(&up_requests[0]).expect("alias attempt sends the header");
        let pairs = parsed_retry_header(&retry);
        assert_eq!(field(&pairs, "po"), "timeout");
        assert_eq!(field(&pairs, "pc"), "read_timeout");
        assert_eq!(field(&pairs, "ph"), "apex");
        assert_eq!(field(&pairs, "fo"), "1");
    }
}
