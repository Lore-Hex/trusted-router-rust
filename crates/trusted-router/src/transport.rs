//! Shared HTTP transport, retries, and credential boundaries.

use crate::client::{CallOptions, Client, Plane};
use crate::error::classify_api_error;
use crate::{Error, Result};
use http::Method;
use rand::Rng;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue, RETRY_AFTER};
use serde::de::DeserializeOwned;
use serde_json::Value;
use std::time::{Duration, SystemTime};
use tokio::time::{sleep, timeout};
use url::Url;

impl Client {
    pub(crate) async fn request_bytes(
        &self,
        plane: Plane,
        method: Method,
        path: &str,
        body: Option<Value>,
        options: CallOptions,
    ) -> Result<Vec<u8>> {
        // Candidates, not one pinned URL. This was `let url = ...` computed
        // once outside the loop, so every retry re-hit the same host and
        // failover could not move even in principle.
        let candidates = self.plane_urls(plane, path)?;
        let mut base_index = 0usize;
        let mut attempt = 0;
        loop {
            let url = candidates[base_index].clone();
            let result = self
                .send_once(method.clone(), url.clone(), body.clone(), &options)
                .await;
            match result {
                Ok(response) if response.status().is_success() => {
                    let bytes = self.read_response(response, &options).await?;
                    return Ok(bytes.to_vec());
                }
                Ok(response) => {
                    let status = response.status();
                    let headers = response.headers().clone();
                    let retry_after = parse_retry_after(&headers);
                    let bytes = self.read_response(response, &options).await?;
                    let payload = serde_json::from_slice::<Value>(&bytes).ok();
                    let error = classify_api_error(status.as_u16(), payload, retry_after);
                    if attempt >= self.max_retries || !retryable_status(status.as_u16()) {
                        return Err(error);
                    }
                    // Only gateway-level statuses move domains. A 500 means a
                    // server received and processed the request, and inference
                    // is not idempotent, so retrying it elsewhere risks
                    // charging twice.
                    if failoverable_status(status.as_u16()) && base_index + 1 < candidates.len() {
                        base_index += 1;
                    }
                    sleep(retry_delay(attempt, retry_after)).await;
                }
                Err(error) => {
                    if attempt >= self.max_retries || !retryable_transport(&error) {
                        return Err(error);
                    }
                    // A transport failure means no server saw the request, so
                    // moving to another domain cannot double-execute anything.
                    if base_index + 1 < candidates.len() {
                        base_index += 1;
                    }
                    sleep(retry_delay(attempt, None)).await;
                }
            }
            attempt += 1;
        }
    }

    pub(crate) async fn open_stream(
        &self,
        plane: Plane,
        method: Method,
        path: &str,
        body: Value,
        options: CallOptions,
    ) -> Result<reqwest::Response> {
        // Same candidate walk as request_bytes. This was a single pinned URL,
        // so a stream that failed to open re-opened against the host that had
        // just refused it — the non-streaming path could move domains and the
        // streaming path could not.
        let candidates = self.plane_urls(plane, path)?;
        let mut base_index = 0usize;
        let mut attempt = 0;
        loop {
            let url = candidates[base_index].clone();
            match self
                .send_once(method.clone(), url.clone(), Some(body.clone()), &options)
                .await
            {
                Ok(response) if response.status().is_success() => return Ok(response),
                Ok(response) => {
                    let status = response.status();
                    let headers = response.headers().clone();
                    let retry_after = parse_retry_after(&headers);
                    let bytes = self.read_response(response, &options).await?;
                    let payload = serde_json::from_slice::<Value>(&bytes).ok();
                    let error = classify_api_error(status.as_u16(), payload, retry_after);
                    if attempt >= self.max_retries || !retryable_status(status.as_u16()) {
                        return Err(error);
                    }
                    // The response never opened, so nothing was streamed and
                    // moving hosts cannot duplicate a delivered stream.
                    if failoverable_status(status.as_u16()) && base_index + 1 < candidates.len() {
                        base_index += 1;
                    }
                    sleep(retry_delay(attempt, retry_after)).await;
                }
                Err(error) => {
                    if attempt >= self.max_retries || !retryable_transport(&error) {
                        return Err(error);
                    }
                    if base_index + 1 < candidates.len() {
                        base_index += 1;
                    }
                    sleep(retry_delay(attempt, None)).await;
                }
            }
            attempt += 1;
        }
    }

    pub(crate) async fn credential_free_json<T: DeserializeOwned>(
        &self,
        target: &str,
    ) -> Result<T> {
        let url = Url::parse(target)
            .map_err(|error| Error::InvalidConfiguration(format!("invalid public URL: {error}")))?;
        if url.scheme() != "https"
            && url.host_str() != Some("127.0.0.1")
            && url.host_str() != Some("localhost")
        {
            return Err(Error::InvalidConfiguration(
                "public metadata URL must use HTTPS".to_owned(),
            ));
        }
        let response = self
            .http
            .get(url)
            .header(
                "user-agent",
                format!("trusted-router-rust/{}", env!("CARGO_PKG_VERSION")),
            )
            .send()
            .await
            .map_err(map_reqwest_error)?;
        let status = response.status();
        let bytes = response.bytes().await.map_err(map_reqwest_error)?;
        if !status.is_success() {
            return Err(classify_api_error(
                status.as_u16(),
                serde_json::from_slice(&bytes).ok(),
                None,
            ));
        }
        serde_json::from_slice(&bytes).map_err(|error| Error::Serialization(error.to_string()))
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
            return request.send().await.map_err(map_reqwest_error);
        }
        match deadline {
            Some(duration) => timeout(duration, request.send())
                .await
                .map_err(|_| Error::Timeout("response headers deadline exceeded".to_owned()))?
                .map_err(map_reqwest_error),
            None => request.send().await.map_err(map_reqwest_error),
        }
    }

    async fn read_response(
        &self,
        response: reqwest::Response,
        options: &CallOptions,
    ) -> Result<bytes::Bytes> {
        let deadline = options.timeout.or(self.timeout);
        if deadline == Some(Duration::ZERO) {
            return response.bytes().await.map_err(map_reqwest_error);
        }
        match deadline {
            Some(duration) => timeout(duration, response.bytes())
                .await
                .map_err(|_| Error::Timeout("response body deadline exceeded".to_owned()))?
                .map_err(map_reqwest_error),
            None => response.bytes().await.map_err(map_reqwest_error),
        }
    }

    /// Every candidate URL for a plane, in preference order.
    ///
    /// Inference walks the alias domains; the control plane keeps its single
    /// endpoint, because those calls are not what a domain outage strands.
    fn plane_urls(&self, plane: Plane, path: &str) -> Result<Vec<Url>> {
        match plane {
            Plane::Control => Ok(vec![self.relative_url(plane, path)?]),
            Plane::Inference => {
                let trimmed = path.trim_start_matches('/');
                if !path.starts_with('/') || path.starts_with("//") || path.contains('\\') {
                    return Err(Error::InvalidConfiguration(
                        "API path must be a root-relative path".to_owned(),
                    ));
                }
                let mut out = Vec::with_capacity(self.api_base_urls.len());
                for base in &self.api_base_urls {
                    out.push(
                        base.join(trimmed)
                            .map_err(|error| Error::InvalidConfiguration(error.to_string()))?,
                    );
                }
                Ok(out)
            }
        }
    }

    fn relative_url(&self, plane: Plane, path: &str) -> Result<Url> {
        if !path.starts_with('/') || path.starts_with("//") || path.contains('\\') {
            return Err(Error::InvalidConfiguration(
                "API path must be a root-relative path".to_owned(),
            ));
        }
        let base = match plane {
            Plane::Inference => &self.api_base_url,
            Plane::Control => &self.control_base_url,
        };
        base.join(path.trim_start_matches('/'))
            .map_err(|error| Error::InvalidConfiguration(error.to_string()))
    }

    fn request_headers(&self, options: &CallOptions) -> Result<HeaderMap> {
        let mut headers = HeaderMap::new();
        for (name, value) in self.headers.iter().chain(options.headers.iter()) {
            headers.insert(parse_header_name(name)?, parse_header_value(value)?);
        }
        headers.insert(
            reqwest::header::USER_AGENT,
            parse_header_value(&format!(
                "trusted-router-rust/{}",
                env!("CARGO_PKG_VERSION")
            ))?,
        );
        let api_key = options.api_key.as_ref().or(self.api_key.as_ref());
        if let Some(api_key) = api_key.filter(|value| !value.is_empty()) {
            headers.insert(
                reqwest::header::AUTHORIZATION,
                parse_header_value(&format!("Bearer {api_key}"))?,
            );
        }
        let workspace = options.workspace_id.as_ref().or(self.workspace_id.as_ref());
        if let Some(workspace) = workspace.filter(|value| !value.is_empty()) {
            headers.insert(
                HeaderName::from_static("x-trustedrouter-workspace"),
                parse_header_value(workspace)?,
            );
        }
        if let Some(key) = options
            .idempotency_key
            .as_ref()
            .filter(|value| !value.is_empty())
        {
            headers.insert(
                HeaderName::from_static("idempotency-key"),
                parse_header_value(key)?,
            );
        }
        Ok(headers)
    }
}

fn parse_header_name(value: &str) -> Result<HeaderName> {
    HeaderName::from_bytes(value.as_bytes())
        .map_err(|error| Error::InvalidConfiguration(format!("invalid header name: {error}")))
}

fn parse_header_value(value: &str) -> Result<HeaderValue> {
    HeaderValue::from_str(value)
        .map_err(|error| Error::InvalidConfiguration(format!("invalid header value: {error}")))
}

fn retryable_status(status: u16) -> bool {
    status == 429 || matches!(status, 500 | 502 | 503 | 504)
}

fn retryable_transport(error: &Error) -> bool {
    matches!(error, Error::Transport(_) | Error::Timeout(_))
}

fn retry_delay(attempt: usize, retry_after: Option<Duration>) -> Duration {
    let exponent = u32::try_from(attempt.min(6)).unwrap_or(6);
    let ceiling_ms = 500_u64.saturating_mul(2_u64.pow(exponent)).min(30_000);
    let jitter_ms = rand::thread_rng().gen_range(0..=ceiling_ms);
    retry_after
        .unwrap_or_default()
        .max(Duration::from_millis(jitter_ms))
}

fn parse_retry_after(headers: &HeaderMap) -> Option<Duration> {
    let value = headers.get(RETRY_AFTER)?.to_str().ok()?;
    if let Ok(seconds) = value.trim().parse::<u64>() {
        return Some(Duration::from_secs(seconds));
    }
    let timestamp = httpdate::parse_http_date(value).ok()?;
    timestamp.duration_since(SystemTime::now()).ok()
}

fn map_reqwest_error(error: reqwest::Error) -> Error {
    if error.is_timeout() {
        Error::Timeout(error.to_string())
    } else {
        Error::Transport(error.to_string())
    }
}

/// Statuses that justify moving to a different domain.
///
/// Deliberately narrower than [`retryable_status`], which also covers 429 and
/// 500. A 429 should back off against the same host, and a 500 means a server
/// received and processed a non-idempotent inference request.
fn failoverable_status(status: u16) -> bool {
    // 502..=504 rather than 502 | 503 | 504 only because clippy's
    // manual_range_patterns is denied here. The set is the same three statuses,
    // and 500 stays outside it deliberately.
    matches!(status, 502..=504)
}

#[cfg(test)]
mod failover_tests {
    use super::{failoverable_status, retryable_status};

    #[test]
    fn only_gateway_statuses_move_domains() {
        for status in [502u16, 503, 504] {
            assert!(failoverable_status(status), "{status} should fail over");
        }
    }

    #[test]
    fn a_500_does_not_move_domains() {
        // A 500 means a server received and processed the request. Inference is
        // not idempotent, so retrying it on another domain risks charging
        // twice. It stays RETRYABLE against the same host.
        assert!(!failoverable_status(500), "500 must not move domains");
        assert!(retryable_status(500), "500 should still retry in place");
    }

    #[test]
    fn a_429_does_not_move_domains() {
        // Rate limiting is not a reason to spread load onto another domain;
        // back off against the same host instead.
        assert!(!failoverable_status(429));
        assert!(retryable_status(429));
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
}
