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
use crate::transport::policy::{self, FailureDisposition};
use crate::{Error, Result};
use http::Method;
use serde_json::Value;
use std::time::Duration;
use tokio::time::{sleep, timeout};
use url::Url;

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

    /// The workspace's ONLY base-index advance site.
    fn advance(&mut self) {
        if self.index + 1 < self.len {
            self.index += 1;
        }
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
    pub(crate) async fn execute(
        &self,
        plane: Plane,
        method: Method,
        path: &str,
        body: Option<Value>,
        options: &CallOptions,
    ) -> Result<reqwest::Response> {
        // Candidates, not one pinned URL: computing a single URL outside the
        // loop is how failover once could not move even in principle.
        let candidates = self.plane_urls(plane, path)?;
        let mut cursor = CandidateCursor::new(candidates.len());
        let mut attempt = 0;
        loop {
            let url = candidates[cursor.index()].clone();
            let disposition = match self
                .send_once(method.clone(), url, body.clone(), options)
                .await
            {
                Ok(response) if response.status().is_success() => return Ok(response),
                Ok(response) => {
                    let status = response.status();
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
            if disposition.failover {
                cursor.advance();
            }
            sleep(policy::retry_delay(attempt, disposition.retry_after)).await;
            attempt += 1;
        }
    }

    async fn send_once(
        &self,
        method: Method,
        url: Url,
        body: Option<Value>,
        options: &CallOptions,
    ) -> Result<reqwest::Response> {
        let headers = self.request_headers(options)?;
        let mut request = self.http.request(method, url).headers(headers);
        if let Some(body) = body {
            request = request.json(&body);
        }
        let deadline = options.timeout.or(self.timeout);
        if deadline == Some(Duration::ZERO) {
            return request.send().await.map_err(policy::map_reqwest_error);
        }
        match deadline {
            Some(duration) => timeout(duration, request.send())
                .await
                .map_err(|_| Error::Timeout("response headers deadline exceeded".to_owned()))?
                .map_err(policy::map_reqwest_error),
            None => request.send().await.map_err(policy::map_reqwest_error),
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
#[cfg(test)]
mod candidate_walk_tests {
    use crate::client::{CallOptions, Client, Plane};
    use http::Method;
    use serde_json::json;
    use url::Url;
    use wiremock::matchers::method as method_matcher;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn base(server: &MockServer) -> Url {
        // Trailing slash so `join` appends instead of replacing the last
        // segment, matching what parse_base_url does for real base URLs.
        Url::parse(&format!("{}/v1/", server.uri())).unwrap()
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
            .build()
            .unwrap();
        // Set the singular base too. A regression back to a pinned
        // `relative_url` would otherwise fall through to the real default host
        // and put a live network call inside the test suite — the failure would
        // still show up, but for the wrong reason and off-machine.
        client.api_base_url = base(down);
        client.api_base_urls = vec![base(down), base(up)];
        client
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
        assert_eq!(down.received_requests().await.unwrap().len(), 1);
        assert_eq!(
            up.received_requests().await.unwrap().len(),
            1,
            "streaming never reached the second domain"
        );
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
        assert_eq!(down.received_requests().await.unwrap().len(), 1);
        assert_eq!(
            up.received_requests().await.unwrap().len(),
            1,
            "the buffered path never reached the second domain"
        );
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
        assert!(
            down.received_requests().await.unwrap().len() > 1,
            "should retry in place"
        );
    }
}
