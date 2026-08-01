//! Typed SDK errors.

use serde_json::Value;
use std::time::Duration;

/// SDK result type.
pub type Result<T> = std::result::Result<T, Error>;

/// HTTP/API error classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorKind {
    /// Invalid request or another 4xx response.
    BadRequest,
    /// Invalid or missing API key.
    Authentication,
    /// Authenticated but unauthorized.
    PermissionDenied,
    /// Missing route or object.
    NotFound,
    /// Rate limit response.
    RateLimit,
    /// Endpoint deliberately unsupported.
    EndpointNotSupported,
    /// `TrustedRouter` or upstream 5xx response.
    Internal,
    /// Non-HTTP transport failure.
    Transport,
    /// SDK deadline or stream idle deadline.
    Timeout,
    /// JSON encoding or decoding failure.
    Serialization,
    /// Invalid local SDK configuration.
    InvalidConfiguration,
    /// Attestation verification failure.
    Attestation,
    /// OAuth flow failure.
    OAuth,
}

/// Structured API failure preserving routing/provider attribution.
#[derive(Debug, Clone)]
pub struct ApiError {
    /// HTTP response status.
    pub status_code: u16,
    /// Human-readable message.
    pub message: String,
    /// Full parsed response when it was JSON.
    pub payload: Option<Value>,
    /// Numeric Retry-After value.
    pub retry_after: Option<Duration>,
    /// Error layer reported by the API, such as `routing` or `provider`.
    pub layer: Option<String>,
    /// Error source reported by the API.
    pub source: Option<String>,
    /// Provider identifier when reported.
    pub provider: Option<String>,
    /// Request identifier when reported.
    pub request_id: Option<String>,
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}", self.message)
    }
}

impl std::error::Error for ApiError {}

/// Error returned by the SDK.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// HTTP/API response failure.
    #[error("{kind:?}: {error}")]
    Api {
        /// Classified error kind.
        kind: ErrorKind,
        /// Structured API details.
        error: Box<ApiError>,
    },
    /// HTTP transport failure.
    #[error("TrustedRouter endpoint unavailable: {0}")]
    Transport(String),
    /// SDK or stream timeout.
    #[error("TrustedRouter request timed out: {0}")]
    Timeout(String),
    /// JSON encoding or decoding failure.
    #[error("TrustedRouter JSON error: {0}")]
    Serialization(String),
    /// Invalid SDK configuration or request path.
    #[error("Invalid TrustedRouter configuration: {0}")]
    InvalidConfiguration(String),
    /// Attestation verification failure.
    #[error("TrustedRouter attestation verification failed: {0}")]
    Attestation(String),
    /// OAuth helper failure.
    #[error("TrustedRouter OAuth error: {0}")]
    OAuth(String),
}

impl Error {
    /// Returns the stable error classification.
    pub fn kind(&self) -> ErrorKind {
        match self {
            Self::Api { kind, .. } => *kind,
            Self::Transport(_) => ErrorKind::Transport,
            Self::Timeout(_) => ErrorKind::Timeout,
            Self::Serialization(_) => ErrorKind::Serialization,
            Self::InvalidConfiguration(_) => ErrorKind::InvalidConfiguration,
            Self::Attestation(_) => ErrorKind::Attestation,
            Self::OAuth(_) => ErrorKind::OAuth,
        }
    }

    /// Returns the HTTP status when this came from an API response.
    pub fn status_code(&self) -> Option<u16> {
        match self {
            Self::Api { error, .. } => Some(error.status_code),
            _ => None,
        }
    }

    /// Returns structured API details when available.
    pub fn api_error(&self) -> Option<&ApiError> {
        match self {
            Self::Api { error, .. } => Some(error.as_ref()),
            _ => None,
        }
    }
}

pub(crate) fn classify_api_error(
    status_code: u16,
    payload: Option<Value>,
    retry_after: Option<Duration>,
) -> Error {
    let message = payload
        .as_ref()
        .and_then(error_object)
        .and_then(|error| error.get("message"))
        .and_then(Value::as_str)
        .or_else(|| {
            payload
                .as_ref()
                .and_then(|value| value.get("message"))
                .and_then(Value::as_str)
        })
        .unwrap_or("TrustedRouter error")
        .to_owned();
    let string_field = |name: &str| -> Option<String> {
        payload
            .as_ref()
            .and_then(error_object)
            .and_then(|value| value.get(name))
            .or_else(|| payload.as_ref().and_then(|value| value.get(name)))
            .and_then(Value::as_str)
            .map(str::to_owned)
    };
    let layer = string_field("layer");
    let source = string_field("source");
    let provider = string_field("provider");
    let request_id = string_field("request_id");
    let kind = match status_code {
        401 => ErrorKind::Authentication,
        403 => ErrorKind::PermissionDenied,
        404 => ErrorKind::NotFound,
        429 => ErrorKind::RateLimit,
        501 => ErrorKind::EndpointNotSupported,
        400..=499 => ErrorKind::BadRequest,
        _ => ErrorKind::Internal,
    };
    Error::Api {
        kind,
        error: Box::new(ApiError {
            status_code,
            message,
            payload,
            retry_after,
            layer,
            source,
            provider,
            request_id,
        }),
    }
}

fn error_object(payload: &Value) -> Option<&serde_json::Map<String, Value>> {
    payload.get("error")?.as_object()
}
