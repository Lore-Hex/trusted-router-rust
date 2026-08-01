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
        let url = self.relative_url(plane, path)?;
        let mut attempt = 0;
        loop {
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
                    sleep(retry_delay(attempt, retry_after)).await;
                }
                Err(error) => {
                    if attempt >= self.max_retries || !retryable_transport(&error) {
                        return Err(error);
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
        let url = self.relative_url(plane, path)?;
        let mut attempt = 0;
        loop {
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
                    sleep(retry_delay(attempt, retry_after)).await;
                }
                Err(error) => {
                    if attempt >= self.max_retries || !retryable_transport(&error) {
                        return Err(error);
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
