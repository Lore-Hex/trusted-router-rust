//! Asynchronous `TrustedRouter` client and typed endpoint methods.

use crate::constants::{
    ALIAS_API_BASE_URLS,
    DEFAULT_API_BASE_URL, DEFAULT_CONTROL_BASE_URL, DEFAULT_MAX_RETRIES, DEFAULT_REQUEST_TIMEOUT,
    DEFAULT_STATUS_URL, DEFAULT_TRUST_RELEASE_URL,
};
use crate::types::{
    ActivityResponse, AuthSessionResponse, BroadcastDestination, BroadcastDestinationList,
    ChatCompletion, ChatRequest, CheckoutResponse, CreditsBalance, EmbeddingResponse,
    EmbeddingsRequest, MessagesRequest, MessagesResponse, ModelFilters, ModelList, ProviderList,
    RegionList, ResponseInputTokens, ResponseObject, ResponsesRequest, UserInfoResponse,
};
use crate::TrustRelease;
use crate::{Error, Result};
use http::Method;
use serde::de::DeserializeOwned;
use serde_json::{json, Map, Value};
use std::collections::BTreeMap;
use std::time::Duration;
use url::Url;

/// API plane selected for a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Plane {
    /// Attested inference plane. Prompt-bearing calls belong here.
    Inference,
    /// Dashboard, billing, catalog, and account control plane.
    Control,
}

/// Per-call transport overrides.
#[derive(Debug, Clone, Default)]
pub struct CallOptions {
    /// API key override. An empty string deliberately suppresses authentication.
    pub api_key: Option<String>,
    /// Workspace override. An empty string deliberately suppresses the header.
    pub workspace_id: Option<String>,
    /// Idempotency key sent as `Idempotency-Key`.
    pub idempotency_key: Option<String>,
    /// Per-attempt timeout override. `Duration::ZERO` disables the SDK timeout.
    pub timeout: Option<Duration>,
    /// Additional request headers.
    pub headers: BTreeMap<String, String>,
}

/// Builder for an asynchronous [`Client`].
#[derive(Debug, Clone)]
pub struct ClientBuilder {
    pub(crate) api_key: Option<String>,
    pub(crate) api_base_url: String,
    pub(crate) control_base_url: String,
    pub(crate) workspace_id: Option<String>,
    pub(crate) timeout: Option<Duration>,
    pub(crate) max_retries: usize,
    pub(crate) headers: BTreeMap<String, String>,
    pub(crate) http_client: Option<reqwest::Client>,
}

impl Default for ClientBuilder {
    fn default() -> Self {
        Self {
            api_key: std::env::var("TRUSTEDROUTER_API_KEY").ok(),
            api_base_url: DEFAULT_API_BASE_URL.to_owned(),
            control_base_url: DEFAULT_CONTROL_BASE_URL.to_owned(),
            workspace_id: None,
            timeout: Some(DEFAULT_REQUEST_TIMEOUT),
            max_retries: DEFAULT_MAX_RETRIES,
            headers: BTreeMap::new(),
            http_client: None,
        }
    }
}

impl ClientBuilder {
    /// Sets the default API key.
    pub fn api_key(mut self, value: impl Into<String>) -> Self {
        self.api_key = Some(value.into());
        self
    }

    /// Sets the inference base URL.
    pub fn api_base_url(mut self, value: impl Into<String>) -> Self {
        self.api_base_url = value.into();
        self
    }

    /// Sets the control-plane base URL.
    pub fn control_base_url(mut self, value: impl Into<String>) -> Self {
        self.control_base_url = value.into();
        self
    }

    /// Sets the default workspace selector.
    pub fn workspace_id(mut self, value: impl Into<String>) -> Self {
        self.workspace_id = Some(value.into());
        self
    }

    /// Sets the per-attempt request timeout. `None` disables it.
    pub fn timeout(mut self, value: Option<Duration>) -> Self {
        self.timeout = value;
        self
    }

    /// Sets the number of retries after the initial attempt.
    pub fn max_retries(mut self, value: usize) -> Self {
        self.max_retries = value;
        self
    }

    /// Adds a default header.
    pub fn header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.insert(name.into(), value.into());
        self
    }

    /// Uses a caller-supplied Reqwest client.
    pub fn http_client(mut self, value: reqwest::Client) -> Self {
        self.http_client = Some(value);
        self
    }

    /// Validates configuration and constructs the client.
    pub fn build(self) -> Result<Client> {
        let api_base_url = parse_base_url(&self.api_base_url, "inference")?;
        let control_base_url = parse_base_url(&self.control_base_url, "control")?;
        let http = match self.http_client {
            Some(client) => client,
            None => reqwest::Client::builder()
                .user_agent(format!("trusted-router-rust/{}", env!("CARGO_PKG_VERSION")))
                .build()
                .map_err(|error| Error::InvalidConfiguration(error.to_string()))?,
        };
        Ok(Client {
            api_key: self.api_key,
            api_base_urls: inference_base_urls(&api_base_url),
            api_base_url,
            control_base_url,
            workspace_id: self.workspace_id,
            timeout: self.timeout,
            max_retries: self.max_retries,
            headers: self.headers,
            http,
        })
    }
}

/// Asynchronous `TrustedRouter` SDK client.
#[derive(Debug, Clone)]
pub struct Client {
    pub(crate) api_key: Option<String>,
    pub(crate) api_base_url: Url,
    /// Inference candidates: `api_base_url` first, then the alias domains.
    ///
    /// This must hold MORE THAN ONE entry or failover cannot engage — the
    /// request loop advances only while another candidate remains.
    pub(crate) api_base_urls: Vec<Url>,
    pub(crate) control_base_url: Url,
    pub(crate) workspace_id: Option<String>,
    pub(crate) timeout: Option<Duration>,
    pub(crate) max_retries: usize,
    pub(crate) headers: BTreeMap<String, String>,
    pub(crate) http: reqwest::Client,
}

impl Client {
    /// Starts a client builder.
    pub fn builder() -> ClientBuilder {
        ClientBuilder::default()
    }

    /// Constructs a client with the supplied API key and production defaults.
    pub fn new(api_key: impl Into<String>) -> Result<Self> {
        Self::builder().api_key(api_key).build()
    }

    /// Returns the configured inference base URL.
    pub fn api_base_url(&self) -> &Url {
        &self.api_base_url
    }

    /// Returns every inference candidate in preference order: the configured
    /// base URL first, then the alias domains when the default host is in use.
    pub fn api_base_urls(&self) -> &[Url] {
        &self.api_base_urls
    }

    /// Returns the configured control-plane base URL.
    pub fn control_base_url(&self) -> &Url {
        &self.control_base_url
    }

    /// Sends a typed JSON request to either `TrustedRouter` plane.
    pub async fn request<T: DeserializeOwned>(
        &self,
        plane: Plane,
        method: Method,
        path: &str,
        body: Option<Value>,
        options: CallOptions,
    ) -> Result<T> {
        let bytes = self
            .request_bytes(plane, method, path, body, options)
            .await?;
        serde_json::from_slice(&bytes).map_err(|error| Error::Serialization(error.to_string()))
    }

    /// Creates a non-streaming OpenAI-compatible chat completion.
    pub async fn chat_completions(&self, request: ChatRequest) -> Result<ChatCompletion> {
        let options = with_generated_idempotency(request.call_options.clone());
        self.request(
            Plane::Inference,
            Method::POST,
            "/chat/completions",
            Some(crate::types::with_stream(&request, false)?),
            options,
        )
        .await
    }

    /// Creates a non-streaming stateless Responses API response.
    pub async fn responses(&self, request: ResponsesRequest) -> Result<ResponseObject> {
        let options = with_generated_idempotency(request.call_options.clone());
        self.request(
            Plane::Inference,
            Method::POST,
            "/responses",
            Some(crate::types::with_stream(&request, false)?),
            options,
        )
        .await
    }

    /// Counts input tokens for a Responses request.
    pub async fn responses_input_tokens(
        &self,
        request: ResponsesRequest,
    ) -> Result<ResponseInputTokens> {
        self.request(
            Plane::Inference,
            Method::POST,
            "/responses/input_tokens",
            Some(crate::types::with_stream(&request, false)?),
            request.call_options.clone(),
        )
        .await
    }

    /// Sends an Anthropic-compatible Messages request.
    pub async fn messages(&self, request: MessagesRequest) -> Result<MessagesResponse> {
        let options = with_generated_idempotency(request.call_options.clone());
        let body = serde_json::to_value(&request)
            .map_err(|error| Error::Serialization(error.to_string()))?;
        self.request(
            Plane::Inference,
            Method::POST,
            "/messages",
            Some(body),
            options,
        )
        .await
    }

    /// Creates embeddings.
    pub async fn embeddings(&self, request: EmbeddingsRequest) -> Result<EmbeddingResponse> {
        let options = with_generated_idempotency(request.call_options.clone());
        let body = serde_json::to_value(&request)
            .map_err(|error| Error::Serialization(error.to_string()))?;
        self.request(
            Plane::Inference,
            Method::POST,
            "/embeddings",
            Some(body),
            options,
        )
        .await
    }

    /// Fetches the model catalog.
    pub async fn models(&self, filters: ModelFilters) -> Result<ModelList> {
        let mut query = Vec::new();
        if let Some(value) = filters.open_weights {
            query.push(("open_weights", value.to_string()));
        }
        if let Some(value) = filters.provider_jurisdiction {
            query.push(("provider[jurisdiction]", value));
        }
        if let Some(value) = filters.provider_region {
            query.push(("provider[region]", value));
        }
        let path = query_path("/models", &query)?;
        self.request(
            Plane::Control,
            Method::GET,
            &path,
            None,
            CallOptions::default(),
        )
        .await
    }

    /// Fetches the provider catalog.
    pub async fn providers(&self) -> Result<ProviderList> {
        self.request(
            Plane::Control,
            Method::GET,
            "/providers",
            None,
            CallOptions::default(),
        )
        .await
    }

    /// Fetches published gateway regions.
    pub async fn regions(&self) -> Result<RegionList> {
        self.request(
            Plane::Control,
            Method::GET,
            "/regions",
            None,
            CallOptions::default(),
        )
        .await
    }

    /// Fetches credits for the selected workspace.
    pub async fn credits(&self, options: CallOptions) -> Result<CreditsBalance> {
        self.request(Plane::Control, Method::GET, "/credits", None, options)
            .await
    }

    /// Fetches activity metadata. Prompt and output content are not returned.
    pub async fn activity(
        &self,
        query: &BTreeMap<String, String>,
        options: CallOptions,
    ) -> Result<ActivityResponse> {
        let pairs = query
            .iter()
            .map(|(key, value)| (key.as_str(), value.clone()))
            .collect::<Vec<_>>();
        let path = query_path("/activity", &pairs)?;
        self.request(Plane::Control, Method::GET, &path, None, options)
            .await
    }

    /// Fetches the current browser auth session.
    pub async fn auth_session(&self) -> Result<AuthSessionResponse> {
        self.request(
            Plane::Control,
            Method::GET,
            "/auth/session",
            None,
            CallOptions::default(),
        )
        .await
    }

    /// Fetches OIDC-style key-bound user information.
    pub async fn user_info(&self) -> Result<UserInfoResponse> {
        self.request(
            Plane::Control,
            Method::GET,
            "/auth/userinfo",
            None,
            CallOptions::default(),
        )
        .await
    }

    /// Logs out the current browser session.
    pub async fn logout(&self) -> Result<Value> {
        self.request(
            Plane::Control,
            Method::POST,
            "/auth/logout",
            None,
            CallOptions::default(),
        )
        .await
    }

    /// Lists workspace broadcast destinations.
    pub async fn broadcast_destinations(
        &self,
        options: CallOptions,
    ) -> Result<BroadcastDestinationList> {
        self.request(
            Plane::Control,
            Method::GET,
            "/broadcast/destinations",
            None,
            options,
        )
        .await
    }

    /// Creates a workspace broadcast destination.
    pub async fn create_broadcast_destination(
        &self,
        body: Value,
        options: CallOptions,
    ) -> Result<BroadcastDestination> {
        self.request(
            Plane::Control,
            Method::POST,
            "/broadcast/destinations",
            Some(body),
            with_generated_idempotency(options),
        )
        .await
    }

    /// Fetches one broadcast destination.
    pub async fn broadcast_destination(
        &self,
        id: &str,
        options: CallOptions,
    ) -> Result<BroadcastDestination> {
        self.request(
            Plane::Control,
            Method::GET,
            &resource_path("/broadcast/destinations", id)?,
            None,
            options,
        )
        .await
    }

    /// Patches one broadcast destination.
    pub async fn update_broadcast_destination(
        &self,
        id: &str,
        patch: Value,
        options: CallOptions,
    ) -> Result<BroadcastDestination> {
        self.request(
            Plane::Control,
            Method::PATCH,
            &resource_path("/broadcast/destinations", id)?,
            Some(patch),
            with_generated_idempotency(options),
        )
        .await
    }

    /// Deletes one broadcast destination.
    pub async fn delete_broadcast_destination(
        &self,
        id: &str,
        options: CallOptions,
    ) -> Result<Value> {
        self.request(
            Plane::Control,
            Method::DELETE,
            &resource_path("/broadcast/destinations", id)?,
            None,
            with_generated_idempotency(options),
        )
        .await
    }

    /// Tests one broadcast destination.
    pub async fn test_broadcast_destination(
        &self,
        id: &str,
        options: CallOptions,
    ) -> Result<Value> {
        let path = format!("{}/test", resource_path("/broadcast/destinations", id)?);
        self.request(
            Plane::Control,
            Method::POST,
            &path,
            None,
            with_generated_idempotency(options),
        )
        .await
    }

    /// Creates a card, `PayPal`, or stablecoin checkout session.
    pub async fn billing_checkout(
        &self,
        amount: Value,
        payment_method: Option<&str>,
        options: CallOptions,
    ) -> Result<CheckoutResponse> {
        let mut body = Map::new();
        body.insert("amount".to_owned(), amount);
        if let Some(value) = payment_method {
            body.insert("payment_method".to_owned(), Value::String(value.to_owned()));
        }
        self.request(
            Plane::Control,
            Method::POST,
            "/billing/checkout",
            Some(Value::Object(body)),
            with_generated_idempotency(options),
        )
        .await
    }

    /// Creates a stablecoin checkout session.
    pub async fn stablecoin_checkout(
        &self,
        amount: Value,
        options: CallOptions,
    ) -> Result<CheckoutResponse> {
        self.billing_checkout(amount, Some("stablecoin"), options)
            .await
    }

    /// Fetches the signed trust release without sending credentials.
    pub async fn trust_release(&self, url: Option<&str>) -> Result<TrustRelease> {
        self.credential_free_json(url.unwrap_or(DEFAULT_TRUST_RELEASE_URL))
            .await
    }

    /// Fetches public status without sending credentials.
    pub async fn status(&self, url: Option<&str>) -> Result<Value> {
        self.credential_free_json(url.unwrap_or(DEFAULT_STATUS_URL))
            .await
    }

    /// Fetches live attestation evidence from the inference plane.
    pub async fn attestation(&self, nonce_hex: Option<&str>) -> Result<Vec<u8>> {
        let path = match nonce_hex {
            Some(nonce) if !nonce.is_empty() => {
                query_path("/attestation", &[("nonce", nonce.to_owned())])?
            }
            _ => "/attestation".to_owned(),
        };
        self.request_bytes(
            Plane::Inference,
            Method::GET,
            &path,
            None,
            CallOptions {
                api_key: Some(String::new()),
                workspace_id: Some(String::new()),
                ..CallOptions::default()
            },
        )
        .await
    }

    /// Convenience JSON body for a provider privacy filter.
    pub fn provider_filter(min_privacy: &str) -> Value {
        json!({"provider": {"min_privacy": min_privacy, "data_collection": "deny"}})
    }
}

fn parse_base_url(value: &str, name: &str) -> Result<Url> {
    let mut url = Url::parse(value).map_err(|error| {
        Error::InvalidConfiguration(format!("invalid {name} base URL: {error}"))
    })?;
    if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
        return Err(Error::InvalidConfiguration(format!(
            "{name} base URL must be an HTTP(S) origin"
        )));
    }
    if !url.path().ends_with('/') {
        url.set_path(&format!("{}/", url.path()));
    }
    Ok(url)
}

fn with_generated_idempotency(mut options: CallOptions) -> CallOptions {
    if options.idempotency_key.is_none() {
        options.idempotency_key = Some(format!("tr-req-{}", uuid::Uuid::new_v4().simple()));
    }
    options
}

fn resource_path(prefix: &str, id: &str) -> Result<String> {
    if id.is_empty() || id.contains('/') || id.contains('?') || id.contains('#') {
        return Err(Error::InvalidConfiguration(
            "invalid resource ID".to_owned(),
        ));
    }
    Ok(format!("{prefix}/{id}"))
}

fn query_path<T: AsRef<str>>(path: &str, pairs: &[(T, String)]) -> Result<String> {
    let mut url = Url::parse("https://sdk.invalid")
        .map_err(|error| Error::InvalidConfiguration(error.to_string()))?;
    url.set_path(path);
    if !pairs.is_empty() {
        let mut query = url.query_pairs_mut();
        for (key, value) in pairs {
            query.append_pair(key.as_ref(), value);
        }
    }
    Ok(match url.query() {
        Some(query) => format!("{path}?{query}"),
        None => path.to_owned(),
    })
}

/// Builds the inference candidate list: primary first, then the alias domains.
///
/// Aliases are added ONLY for the default host. A caller who configured their
/// own base URL — a private deployment, a test server, a regional pin — gets
/// exactly that; silently redirecting their traffic to a public alias would be
/// worse than failing.
pub(crate) fn inference_base_urls(primary: &Url) -> Vec<Url> {
    // Compare through parse_base_url, not the raw constant: the builder
    // normalises a trailing slash onto the base so `join` resolves correctly,
    // so the parsed default and the stored primary differ textually even when
    // they are the same endpoint.
    let default = parse_base_url(DEFAULT_API_BASE_URL, "inference").ok();
    if default.as_ref() != Some(primary) {
        return vec![primary.clone()];
    }
    let mut out = vec![primary.clone()];
    for alias in ALIAS_API_BASE_URLS {
        if let Ok(url) = parse_base_url(alias, "inference") {
            out.push(url);
        }
    }
    out
}
