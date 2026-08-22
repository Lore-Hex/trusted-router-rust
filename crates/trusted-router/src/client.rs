//! Asynchronous `TrustedRouter` client and typed endpoint methods.

use crate::constants::{
    DEFAULT_API_BASE_URL, DEFAULT_CONTROL_BASE_URL, DEFAULT_MAX_RETRIES, DEFAULT_REQUEST_TIMEOUT,
    DEFAULT_STATUS_URL, DEFAULT_TRUST_RELEASE_URL,
};
use crate::telemetry::reporter::{OwnedTransport, ReporterConfig, TelemetryReporter};
use crate::telemetry::wire::{sdk_identity, sdk_user_agent};
use crate::telemetry::TelemetrySink;
use crate::transport::headers::ensure_idempotency_key;
use crate::transport::routing::{inference_base_urls, parse_base_url};
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
use std::net::SocketAddr;
use std::sync::Arc;
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
    pub(crate) regional_failover: bool,
    pub(crate) telemetry: Option<bool>,
    pub(crate) telemetry_sample_rate: f64,
    pub(crate) headers: BTreeMap<String, String>,
    pub(crate) http_client: Option<reqwest::Client>,
    pub(crate) root_certificate_pems: Vec<Vec<u8>>,
    pub(crate) host_resolutions: BTreeMap<String, SocketAddr>,
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
            regional_failover: true,
            telemetry: None,
            telemetry_sample_rate: DEFAULT_TELEMETRY_SAMPLE_RATE,
            headers: BTreeMap::new(),
            http_client: None,
            root_certificate_pems: Vec::new(),
            host_resolutions: BTreeMap::new(),
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

    /// Pins the client to a single host when set to `false`.
    ///
    /// Defaults to `true`, which lets an inference request move to
    /// [`ALIAS_API_BASE_URLS`] after a connection failure or a 502/503/504.
    /// Setting `false` collapses the candidate list to the configured base URL,
    /// so every attempt goes to the host you named. Retries still happen; they
    /// just stay put.
    ///
    /// [`ALIAS_API_BASE_URLS`]: crate::ALIAS_API_BASE_URLS
    pub fn regional_failover(mut self, value: bool) -> Self {
        self.regional_failover = value;
        self
    }

    /// Enables or disables client-observed reliability telemetry explicitly.
    ///
    /// Telemetry is content-free by construction (client-telemetry contract
    /// v1): closed enums and bounded counters only, no prompt or completion
    /// data, no free text. It has two channels. The per-attempt
    /// `x-tr-client` header rides the calls you already make. The beacon
    /// `POST`s a bounded batch of sampled request events and exact
    /// per-minute counters to `{control_base_url}/client-events` from a
    /// single background task on the client's own HTTP transport — never
    /// through the retry engine, never on an injected client, at most once
    /// per flush interval (30 s, or sooner when 50 events are waiting), with
    /// one final flush bounded to 2 s when the last handle to the client is
    /// dropped. `TRUSTEDROUTER_TELEMETRY_DEBUG=1` echoes every batch to
    /// stderr before it is sent.
    ///
    /// Precedence when this option is not set: `TRUSTEDROUTER_TELEMETRY`
    /// (`0`/`false`/`off`/`no` disable, `1`/`true`/`on`/`yes` enable), then
    /// `DO_NOT_TRACK=1` disables, then the default — on only when the
    /// inference base URL is a known `TrustedRouter` host AND the control
    /// base is the HTTPS `trustedrouter.com` plane. Opting out disables BOTH
    /// channels and never changes the `User-Agent`. Custom base URLs never
    /// send the header, and control-plane calls are never traced or
    /// beaconed, regardless of this setting.
    pub fn telemetry(mut self, value: bool) -> Self {
        self.telemetry = Some(value);
        self
    }

    /// Sets the random sampling rate for otherwise healthy, fast,
    /// first-attempt calls in the telemetry beacon (default `0.01`).
    ///
    /// Failures, retried or failed-over calls, and slow successes (over
    /// 30 s) are always kept; the exact per-minute counters are never
    /// sampled. Values are clamped to `[0, 1]`; `0` keeps no routine
    /// successes. The control plane may lower the rate further but never
    /// raise it.
    pub fn telemetry_sample_rate(mut self, value: f64) -> Self {
        self.telemetry_sample_rate = value;
        self
    }

    /// Adds a default header.
    pub fn header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.insert(name.into(), value.into());
        self
    }

    /// Uses a caller-supplied Reqwest client for general API traffic.
    ///
    /// Reqwest clients are immutable, so the SDK cannot disable redirects,
    /// remove a cookie store, or remove default headers from this client.
    /// Configure [`reqwest::redirect::Policy::none`] and avoid ambient
    /// credential defaults when those guarantees are required. Credential-free
    /// SDK operations such as status metadata and OAuth exchange continue to
    /// use a separate SDK-owned, non-redirecting transport.
    pub fn http_client(mut self, value: reqwest::Client) -> Self {
        self.http_client = Some(value);
        self
    }

    /// Adds a PEM-encoded root certificate to SDK-owned HTTP transports.
    ///
    /// This applies both to the default API transport and to the isolated
    /// credential-free transport used for public metadata and OAuth. It does
    /// not alter a caller-supplied [`reqwest::Client`].
    pub fn root_certificate_pem(mut self, value: impl Into<Vec<u8>>) -> Self {
        self.root_certificate_pems.push(value.into());
        self
    }

    /// Overrides DNS resolution for SDK-owned HTTP transports.
    ///
    /// This is useful for private deployments and local TLS test servers that
    /// must retain their logical hostname for certificate verification. It
    /// does not alter a caller-supplied [`reqwest::Client`].
    pub fn resolve_hostname(mut self, host: impl Into<String>, address: SocketAddr) -> Self {
        self.host_resolutions.insert(host.into(), address);
        self
    }

    /// Validates configuration and constructs the client.
    pub fn build(self) -> Result<Client> {
        let api_base_url = parse_base_url(&self.api_base_url, "inference")?;
        let control_base_url = parse_base_url(&self.control_base_url, "control")?;
        let telemetry = crate::telemetry::resolve_telemetry_enabled(
            self.telemetry,
            &self.api_base_url,
            &self.control_base_url,
            &|name| std::env::var(name).ok(),
        );
        // Public metadata and credential-free OAuth/attestation requests must
        // not inherit defaults, cookies, or redirect policy from an injected
        // client. They always use this SDK-owned, non-redirecting transport.
        let credential_free_http =
            build_owned_http(&self.root_certificate_pems, &self.host_resolutions)?;
        let http = self
            .http_client
            .unwrap_or_else(|| credential_free_http.clone());
        // The beacon reporter is plain state until the first recorded call:
        // no worker, no HTTP client, nothing on the wire (§6.2). When
        // telemetry is off there is no reporter at all.
        let telemetry_sink: Option<Arc<dyn TelemetrySink>> = telemetry.then(|| {
            let mut config = ReporterConfig::new(
                control_base_url.clone(),
                self.api_key.clone(),
                sdk_identity(),
            );
            config.workspace_id.clone_from(&self.workspace_id);
            config.success_sample_rate = self.telemetry_sample_rate;
            config.debug = std::env::var("TRUSTEDROUTER_TELEMETRY_DEBUG")
                .is_ok_and(|value| value.trim() == "1");
            config.transport = OwnedTransport {
                root_certificate_pems: self.root_certificate_pems.clone(),
                host_resolutions: self.host_resolutions.clone(),
            };
            Arc::new(TelemetryReporter::new(config)) as Arc<dyn TelemetrySink>
        });
        Ok(Client {
            api_key: self.api_key,
            api_base_urls: if self.regional_failover {
                inference_base_urls(&api_base_url)
            } else {
                vec![api_base_url.clone()]
            },
            api_base_url,
            control_base_url,
            workspace_id: self.workspace_id,
            timeout: self.timeout,
            max_retries: self.max_retries,
            telemetry,
            telemetry_sink,
            headers: self.headers,
            http,
            credential_free_http,
        })
    }
}

/// Default random sampling rate for routine successes in the beacon.
const DEFAULT_TELEMETRY_SAMPLE_RATE: f64 = 0.01;

/// The builder every SDK-owned transport starts from: the SDK `User-Agent`,
/// no redirects, the configured root certificates and DNS overrides.
pub(crate) fn owned_http_builder(
    root_certificate_pems: &[Vec<u8>],
    host_resolutions: &BTreeMap<String, SocketAddr>,
) -> Result<reqwest::ClientBuilder> {
    let mut builder = reqwest::Client::builder()
        .user_agent(sdk_user_agent())
        .redirect(reqwest::redirect::Policy::none());
    for pem in root_certificate_pems {
        let certificate = reqwest::Certificate::from_pem(pem).map_err(|error| {
            Error::InvalidConfiguration(format!("invalid root certificate PEM: {error}"))
        })?;
        builder = builder.add_root_certificate(certificate);
    }
    for (host, address) in host_resolutions {
        builder = builder.resolve(host, *address);
    }
    Ok(builder)
}

fn build_owned_http(
    root_certificate_pems: &[Vec<u8>],
    host_resolutions: &BTreeMap<String, SocketAddr>,
) -> Result<reqwest::Client> {
    owned_http_builder(root_certificate_pems, host_resolutions)?
        .build()
        .map_err(|error| Error::InvalidConfiguration(error.to_string()))
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
    /// Resolved once at build time (§6.3 precedence); `false` suppresses the
    /// `x-tr-client` header and the beacon, never the `User-Agent`.
    pub(crate) telemetry: bool,
    /// Where finished inference calls are reported: the beacon reporter,
    /// shared by every clone of this client, or `None` when telemetry is
    /// off. Dropping the last holder performs the bounded exit flush.
    pub(crate) telemetry_sink: Option<Arc<dyn TelemetrySink>>,
    pub(crate) headers: BTreeMap<String, String>,
    pub(crate) http: reqwest::Client,
    pub(crate) credential_free_http: reqwest::Client,
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
        let options = ensure_idempotency_key(request.call_options.clone());
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
        let options = ensure_idempotency_key(request.call_options.clone());
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
        let options = ensure_idempotency_key(request.call_options.clone());
        self.request(
            Plane::Inference,
            Method::POST,
            "/responses/input_tokens",
            Some(crate::types::with_stream(&request, false)?),
            options,
        )
        .await
    }

    /// Sends an Anthropic-compatible Messages request.
    pub async fn messages(&self, request: MessagesRequest) -> Result<MessagesResponse> {
        let options = ensure_idempotency_key(request.call_options.clone());
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
        let options = ensure_idempotency_key(request.call_options.clone());
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
            ensure_idempotency_key(CallOptions::default()),
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
            ensure_idempotency_key(options),
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
            ensure_idempotency_key(options),
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
            ensure_idempotency_key(options),
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
            ensure_idempotency_key(options),
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
            ensure_idempotency_key(options),
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
        self.credential_free_plane_bytes(
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
