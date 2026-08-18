//! OAuth credit delegation helpers with PKCE and loopback callbacks.

use crate::client::{CallOptions, Client};
use crate::{Error, Result};
use base64::Engine;
use http::Method;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use url::Url;

/// Default loopback port allow-listed by `TrustedRouter`.
pub const DEFAULT_OAUTH_LOOPBACK_PORT: u16 = 3000;

/// PKCE verifier and S256 challenge.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OAuthPkcePair {
    /// Secret verifier retained by the client.
    pub code_verifier: String,
    /// URL-safe SHA-256 challenge sent to `TrustedRouter`.
    pub code_challenge: String,
    /// Always `S256`.
    pub code_challenge_method: String,
}

/// Options used to build an OAuth authorization URL.
#[derive(Debug, Clone)]
pub struct OAuthAuthorizeOptions {
    /// Loopback or application callback URL.
    pub callback_url: String,
    /// PKCE challenge.
    pub code_challenge: String,
    /// PKCE method; defaults to `S256` when a challenge is supplied.
    pub code_challenge_method: Option<String>,
    /// Label for the delegated key.
    pub key_label: Option<String>,
    /// Decimal dollar limit, encoded without float conversion.
    pub limit: Option<String>,
    /// Usage-limit cadence.
    pub usage_limit_type: Option<String>,
    /// Optional expiry.
    pub expires_at: Option<String>,
    /// Optional agent spawn hint.
    pub spawn_agent: Option<String>,
    /// Optional cloud spawn hint.
    pub spawn_cloud: Option<String>,
    /// Anti-CSRF state included in both URLs.
    pub state: Option<String>,
}

/// Complete values needed to begin and finish an OAuth flow.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OAuthAuthorization {
    /// Browser authorization URL.
    pub url: Url,
    /// PKCE values.
    pub pkce: OAuthPkcePair,
    /// Anti-CSRF state.
    pub state: String,
}

/// OAuth key exchange request.
#[derive(Debug, Clone, Serialize)]
pub struct OAuthKeyExchangeRequest {
    /// Authorization code from the callback.
    pub code: String,
    /// Original PKCE verifier.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code_verifier: Option<String>,
    /// PKCE method.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code_challenge_method: Option<String>,
    /// Per-call transport options.
    #[serde(skip)]
    pub call_options: CallOptions,
}

/// OAuth key exchange response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthKeyExchangeResponse {
    /// One-time delegated `TrustedRouter` key.
    pub key: String,
    /// Owning user ID when present.
    #[serde(default)]
    pub user_id: Option<String>,
    /// Verified identity when present.
    #[serde(default)]
    pub identity: Option<Value>,
    /// Opaque response data.
    #[serde(default)]
    pub data: Option<Value>,
    /// Future response fields.
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

/// Creates or derives a PKCE S256 pair.
pub fn create_pkce_pair(verifier: Option<&str>) -> OAuthPkcePair {
    let code_verifier = verifier.map_or_else(|| random_url_token(32), str::to_owned);
    let challenge = Sha256::digest(code_verifier.as_bytes());
    OAuthPkcePair {
        code_verifier,
        code_challenge: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(challenge),
        code_challenge_method: "S256".to_owned(),
    }
}

/// Generates an opaque URL-safe anti-CSRF state token.
pub fn random_oauth_state() -> String {
    random_url_token(24)
}

impl Client {
    /// Builds an OAuth authorize URL without opening a browser.
    pub fn oauth_authorize_url(&self, options: OAuthAuthorizeOptions) -> Result<Url> {
        if options.callback_url.is_empty() {
            return Err(Error::OAuth("callback_url is required".to_owned()));
        }
        let mut callback = Url::parse(&options.callback_url)
            .map_err(|error| Error::OAuth(format!("invalid callback URL: {error}")))?;
        if let Some(state) = options.state.as_ref() {
            callback.query_pairs_mut().append_pair("state", state);
        }
        let method = options
            .code_challenge_method
            .clone()
            .or_else(|| (!options.code_challenge.is_empty()).then(|| "S256".to_owned()));
        if method.is_some() && options.code_challenge.is_empty() {
            return Err(Error::OAuth(
                "code_challenge is required when a challenge method is set".to_owned(),
            ));
        }
        let mut authorize = self
            .control_base_url
            .join("auth")
            .map_err(|error| Error::OAuth(error.to_string()))?;
        {
            let mut query = authorize.query_pairs_mut();
            query.append_pair("callback_url", callback.as_str());
            if !options.code_challenge.is_empty() {
                query.append_pair("code_challenge", &options.code_challenge);
            }
            append_option(&mut query, "code_challenge_method", method.as_deref());
            append_option(&mut query, "key_label", options.key_label.as_deref());
            append_option(&mut query, "limit", options.limit.as_deref());
            append_option(
                &mut query,
                "usage_limit_type",
                options.usage_limit_type.as_deref(),
            );
            append_option(&mut query, "expires_at", options.expires_at.as_deref());
            append_option(&mut query, "spawn_agent", options.spawn_agent.as_deref());
            append_option(&mut query, "spawn_cloud", options.spawn_cloud.as_deref());
        }
        Ok(authorize)
    }

    /// Generates state and PKCE, then builds an OAuth authorize URL.
    pub fn create_oauth_authorization(
        &self,
        callback_url: impl Into<String>,
        key_label: Option<String>,
    ) -> Result<OAuthAuthorization> {
        let pkce = create_pkce_pair(None);
        let state = random_oauth_state();
        let url = self.oauth_authorize_url(OAuthAuthorizeOptions {
            callback_url: callback_url.into(),
            code_challenge: pkce.code_challenge.clone(),
            code_challenge_method: Some(pkce.code_challenge_method.clone()),
            key_label,
            limit: None,
            usage_limit_type: None,
            expires_at: None,
            spawn_agent: None,
            spawn_cloud: None,
            state: Some(state.clone()),
        })?;
        Ok(OAuthAuthorization { url, pkce, state })
    }

    /// Exchanges an OAuth code for a delegated API key without sending the client's key.
    pub async fn exchange_oauth_key(
        &self,
        request: OAuthKeyExchangeRequest,
    ) -> Result<OAuthKeyExchangeResponse> {
        if request.code.is_empty() {
            return Err(Error::OAuth("code is required".to_owned()));
        }
        let mut options = request.call_options.clone();
        options.api_key = Some(String::new());
        options.workspace_id = Some(String::new());
        let body = serde_json::to_value(request)
            .map_err(|error| Error::Serialization(error.to_string()))?;
        self.credential_free_control_request(Method::POST, "/auth/keys", Some(body), options)
            .await
    }
}

/// Captured loopback OAuth callback.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OAuthCallback {
    /// Authorization code.
    pub code: String,
    /// Callback state.
    pub state: Option<String>,
}

/// Localhost OAuth callback listener settings.
#[derive(Debug, Clone)]
pub struct OAuthLoopbackOptions {
    /// Port to bind; defaults to 3000. Zero requests an ephemeral test port.
    pub port: u16,
    /// Callback path.
    pub path: String,
    /// Expected anti-CSRF state.
    pub expected_state: Option<String>,
}

impl Default for OAuthLoopbackOptions {
    fn default() -> Self {
        Self {
            port: DEFAULT_OAUTH_LOOPBACK_PORT,
            path: "/callback".to_owned(),
            expected_state: None,
        }
    }
}

/// One-shot localhost OAuth callback listener.
#[derive(Debug)]
pub struct OAuthLoopback {
    listener: TcpListener,
    callback_url: Url,
    path: String,
    expected_state: Option<String>,
}

impl OAuthLoopback {
    /// Binds a loopback callback listener.
    pub async fn bind(mut options: OAuthLoopbackOptions) -> Result<Self> {
        if !options.path.starts_with('/') {
            options.path.insert(0, '/');
        }
        let listener = TcpListener::bind(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            options.port,
        ))
        .await
        .map_err(|error| Error::OAuth(format!("cannot bind OAuth loopback: {error}")))?;
        let port = listener
            .local_addr()
            .map_err(|error| Error::OAuth(error.to_string()))?
            .port();
        let callback_url = Url::parse(&format!("http://localhost:{port}{}", options.path))
            .map_err(|error| Error::OAuth(error.to_string()))?;
        Ok(Self {
            listener,
            callback_url,
            path: options.path,
            expected_state: options.expected_state,
        })
    }

    /// URL supplied to the authorization flow.
    pub fn callback_url(&self) -> &Url {
        &self.callback_url
    }

    /// Waits for one callback, validates state, and closes the listener.
    pub async fn wait(self) -> Result<OAuthCallback> {
        let (mut socket, _) = self
            .listener
            .accept()
            .await
            .map_err(|error| Error::OAuth(error.to_string()))?;
        let mut buffer = vec![0_u8; 16 * 1024];
        let read = socket
            .read(&mut buffer)
            .await
            .map_err(|error| Error::OAuth(error.to_string()))?;
        let line = std::str::from_utf8(&buffer[..read])
            .map_err(|error| Error::OAuth(error.to_string()))?
            .lines()
            .next()
            .ok_or_else(|| Error::OAuth("empty OAuth callback".to_owned()))?;
        let target = line
            .split_whitespace()
            .nth(1)
            .ok_or_else(|| Error::OAuth("malformed OAuth callback".to_owned()))?;
        let url = Url::parse(&format!("http://localhost{target}"))
            .map_err(|error| Error::OAuth(error.to_string()))?;
        let result = validate_callback(&url, &self.path, self.expected_state.as_deref());
        let (status, heading) = if result.is_ok() {
            ("200 OK", "Signed in with TrustedRouter")
        } else {
            ("400 Bad Request", "TrustedRouter sign in failed")
        };
        let body = format!("<!doctype html><title>{heading}</title><h1>{heading}</h1><p>You can close this tab.</p>");
        let response = format!(
            "HTTP/1.1 {status}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        let _ = socket.write_all(response.as_bytes()).await;
        result
    }
}

fn validate_callback(url: &Url, path: &str, expected_state: Option<&str>) -> Result<OAuthCallback> {
    if url.path() != path {
        return Err(Error::OAuth("unexpected callback path".to_owned()));
    }
    let params = url.query_pairs().collect::<BTreeMap<_, _>>();
    if let Some(error) = params.get("error") {
        return Err(Error::OAuth(format!("authorization denied: {error}")));
    }
    let code = params
        .get("code")
        .filter(|value| !value.is_empty())
        .ok_or_else(|| Error::OAuth("callback is missing code".to_owned()))?;
    let state = params.get("state").map(ToString::to_string);
    if let Some(expected) = expected_state {
        if state.as_deref() != Some(expected) {
            return Err(Error::OAuth("state mismatch (possible CSRF)".to_owned()));
        }
    }
    Ok(OAuthCallback {
        code: code.to_string(),
        state,
    })
}

fn random_url_token(bytes: usize) -> String {
    let mut value = vec![0_u8; bytes];
    rand::thread_rng().fill_bytes(&mut value);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(value)
}

fn append_option(
    query: &mut url::form_urlencoded::Serializer<'_, url::UrlQuery<'_>>,
    name: &str,
    value: Option<&str>,
) {
    if let Some(value) = value.filter(|value| !value.is_empty()) {
        query.append_pair(name, value);
    }
}
