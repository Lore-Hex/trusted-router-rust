//! Request and response models.

use crate::client::CallOptions;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

/// OpenAI-compatible message supporting text, multimodal content, and tools.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatMessage {
    /// Message role.
    pub role: String,
    /// String, array, object, or null content.
    pub content: Value,
    /// Optional participant name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Assistant tool calls.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tool_calls: Vec<Value>,
    /// Tool call answered by this message.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_call_id: Option<String>,
    /// Provider- or protocol-specific extension fields.
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

impl ChatMessage {
    /// Creates a text message.
    pub fn text(role: impl Into<String>, content: impl Into<String>) -> Self {
        Self {
            role: role.into(),
            content: Value::String(content.into()),
            name: None,
            tool_calls: Vec::new(),
            tool_call_id: None,
            extra: BTreeMap::new(),
        }
    }

    /// Creates a user text message.
    pub fn user(content: impl Into<String>) -> Self {
        Self::text("user", content)
    }

    /// Creates a system text message.
    pub fn system(content: impl Into<String>) -> Self {
        Self::text("system", content)
    }

    /// Returns string content when this message is text-only.
    pub fn text_content(&self) -> Option<&str> {
        self.content.as_str()
    }
}

/// Provider routing preferences shared by chat, Responses, messages, and embeddings.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProviderPreferences {
    /// Ordered preferred providers.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub order: Vec<String>,
    /// Hard provider allow-list.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub only: Vec<String>,
    /// Provider deny-list.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ignore: Vec<String>,
    /// Provider sort mode such as `price`, `throughput`, or `latency`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sort: Option<String>,
    /// Whether provider fallback is permitted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allow_fallbacks: Option<bool>,
    /// Require providers to support every request parameter.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub require_parameters: Option<bool>,
    /// Data-collection preference, including `deny`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data_collection: Option<String>,
    /// Hard privacy tier: `zdr`, `confidential`, or another published tier.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_privacy: Option<String>,
    /// Provider legal jurisdiction filter, currently including `us`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jurisdiction: Option<String>,
    /// Billing source, `credits` or `byok`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub usage: Option<String>,
    /// Accepted provider quantizations.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub quantizations: Vec<String>,
    /// OpenRouter-compatible maximum price object.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub max_price: BTreeMap<String, Value>,
    /// Future provider settings are preserved.
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

impl ProviderPreferences {
    /// Requires zero data retention.
    pub fn zdr() -> Self {
        Self {
            min_privacy: Some("zdr".to_owned()),
            data_collection: Some("deny".to_owned()),
            ..Self::default()
        }
    }

    /// Requires confidential compute plus provider-side end-to-end encryption.
    pub fn confidential() -> Self {
        Self {
            min_privacy: Some("confidential".to_owned()),
            data_collection: Some("deny".to_owned()),
            ..Self::default()
        }
    }

    /// Requires US-based providers.
    pub fn us_only() -> Self {
        Self {
            jurisdiction: Some("us".to_owned()),
            ..Self::default()
        }
    }
}

/// Chat Completions request.
#[derive(Debug, Clone, Serialize)]
pub struct ChatRequest {
    /// Model ID.
    pub model: String,
    /// OpenAI-compatible messages.
    pub messages: Vec<Value>,
    /// Model fallback list.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub models: Vec<String>,
    /// Caller tools and `TrustedRouter` orchestration tools.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tools: Vec<Value>,
    /// Provider routing preferences.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider: Option<ProviderPreferences>,
    /// Request metadata.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Value>,
    /// Orchestration recursion depth.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub depth: Option<u8>,
    /// Additional OpenAI/TrustedRouter body fields.
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
    /// Per-call transport options, never serialized.
    #[serde(skip)]
    pub call_options: CallOptions,
}

impl ChatRequest {
    /// Creates a request from typed messages.
    pub fn new(model: impl Into<String>, messages: Vec<ChatMessage>) -> Self {
        Self {
            model: model.into(),
            messages: messages
                .into_iter()
                .map(|message| serde_json::to_value(message).expect("ChatMessage serializes"))
                .collect(),
            models: Vec::new(),
            tools: Vec::new(),
            provider: None,
            metadata: None,
            depth: None,
            extra: BTreeMap::new(),
            call_options: CallOptions::default(),
        }
    }

    /// Creates a one-message request.
    pub fn user(model: impl Into<String>, prompt: impl Into<String>) -> Self {
        Self::new(model, vec![ChatMessage::user(prompt)])
    }

    /// Adds or replaces an arbitrary request field.
    pub fn with_field(mut self, name: impl Into<String>, value: Value) -> Self {
        self.extra.insert(name.into(), value);
        self
    }
}

/// Non-streaming Chat Completions response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatCompletion {
    /// Completion ID.
    #[serde(default)]
    pub id: String,
    /// Object type.
    #[serde(default)]
    pub object: String,
    /// Creation timestamp.
    #[serde(default)]
    pub created: i64,
    /// Requested model or returned model identifier.
    #[serde(default)]
    pub model: String,
    /// Choices.
    #[serde(default)]
    pub choices: Vec<ChatChoice>,
    /// Token, cost, cache, and orchestration usage.
    #[serde(default)]
    pub usage: Option<ChatUsage>,
    /// Response extensions.
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

/// One non-streaming chat choice.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatChoice {
    /// Choice index.
    #[serde(default)]
    pub index: u32,
    /// Assistant message.
    pub message: ChatMessage,
    /// Provider finish reason.
    #[serde(default)]
    pub finish_reason: Option<String>,
    /// Optional log-probability payload.
    #[serde(default)]
    pub logprobs: Option<Value>,
    /// Choice extensions.
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

/// Token, caching, cost, and orchestration usage.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ChatUsage {
    /// Prompt tokens.
    #[serde(default)]
    pub prompt_tokens: u64,
    /// Completion tokens.
    #[serde(default)]
    pub completion_tokens: u64,
    /// Total tokens.
    #[serde(default)]
    pub total_tokens: u64,
    /// Integer microdollar charge.
    #[serde(default)]
    pub cost_microdollars: Option<i64>,
    /// Provider and orchestration subcall accounting.
    #[serde(default)]
    pub provider_usage: Option<Value>,
    /// Usage extensions, including cache token details.
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

/// Streaming Chat Completions chunk.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatCompletionChunk {
    /// Chunk ID.
    #[serde(default)]
    pub id: String,
    /// Object type.
    #[serde(default)]
    pub object: String,
    /// Creation timestamp.
    #[serde(default)]
    pub created: i64,
    /// Response model.
    #[serde(default)]
    pub model: String,
    /// Streaming choices.
    #[serde(default)]
    pub choices: Vec<ChatChunkChoice>,
    /// Final usage, when present.
    #[serde(default)]
    pub usage: Option<ChatUsage>,
    /// Chunk extensions, including `TrustedRouter` thinking/progress events.
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

/// One streaming choice.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatChunkChoice {
    /// Choice index.
    #[serde(default)]
    pub index: u32,
    /// Streaming delta.
    #[serde(default)]
    pub delta: ChatDelta,
    /// Finish reason.
    #[serde(default)]
    pub finish_reason: Option<String>,
    /// Choice extensions.
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

/// Streaming message delta.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ChatDelta {
    /// Delta role.
    #[serde(default)]
    pub role: Option<String>,
    /// Text delta.
    #[serde(default)]
    pub content: Option<String>,
    /// Tool-call deltas.
    #[serde(default)]
    pub tool_calls: Vec<Value>,
    /// Delta extensions such as reasoning/thinking.
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

/// `OpenAI` Responses request with forward-compatible fields.
#[derive(Debug, Clone, Serialize)]
pub struct ResponsesRequest {
    /// Model ID.
    pub model: String,
    /// String or structured Responses input.
    pub input: Value,
    /// Optional system/developer instructions.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instructions: Option<String>,
    /// Model fallback list.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub models: Vec<String>,
    /// Function or server tools.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tools: Vec<Value>,
    /// Provider routing preferences.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider: Option<ProviderPreferences>,
    /// Request metadata.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Value>,
    /// Stateless mode. `TrustedRouter` currently requires false.
    #[serde(default)]
    pub store: bool,
    /// Additional Responses fields.
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
    /// Per-call transport options, never serialized.
    #[serde(skip)]
    pub call_options: CallOptions,
}

impl ResponsesRequest {
    /// Creates a stateless text Responses request.
    pub fn text(model: impl Into<String>, input: impl Into<String>) -> Self {
        Self {
            model: model.into(),
            input: Value::String(input.into()),
            instructions: None,
            models: Vec::new(),
            tools: Vec::new(),
            provider: None,
            metadata: None,
            store: false,
            extra: BTreeMap::new(),
            call_options: CallOptions::default(),
        }
    }
}

/// Responses API result. Output items remain typed JSON for protocol evolution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseObject {
    /// Response ID.
    pub id: String,
    /// Object type.
    #[serde(default)]
    pub object: String,
    /// Unix creation timestamp.
    #[serde(default)]
    pub created_at: i64,
    /// Lifecycle status.
    #[serde(default)]
    pub status: String,
    /// Returned model.
    #[serde(default)]
    pub model: String,
    /// Output items.
    #[serde(default)]
    pub output: Vec<Value>,
    /// Responses usage object.
    #[serde(default)]
    pub usage: Option<Value>,
    /// Response extensions.
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

/// Parsed Responses streaming event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseEvent {
    /// SSE event name or payload `type`.
    pub event: String,
    /// Full event payload.
    pub data: Value,
}

/// Result of `/responses/input_tokens`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseInputTokens {
    /// Input token count.
    pub input_tokens: u64,
    /// Additional accounting fields.
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

/// Anthropic Messages request.
#[derive(Debug, Clone, Serialize)]
pub struct MessagesRequest {
    /// Model ID.
    pub model: String,
    /// Message array.
    pub messages: Vec<Value>,
    /// Maximum output tokens.
    pub max_tokens: u32,
    /// Optional system prompt.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub system: Option<Value>,
    /// Provider routing preferences.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider: Option<ProviderPreferences>,
    /// Additional Anthropic fields.
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
    /// Per-call transport options, never serialized.
    #[serde(skip)]
    pub call_options: CallOptions,
}

/// Anthropic Messages response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessagesResponse {
    /// Message ID.
    pub id: String,
    /// Response model.
    #[serde(default)]
    pub model: String,
    /// Content blocks.
    #[serde(default)]
    pub content: Vec<Value>,
    /// Stop reason.
    #[serde(default)]
    pub stop_reason: Option<String>,
    /// Usage object.
    #[serde(default)]
    pub usage: Option<Value>,
    /// Response extensions.
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

/// Embeddings request.
#[derive(Debug, Clone, Serialize)]
pub struct EmbeddingsRequest {
    /// Embedding model ID.
    pub model: String,
    /// String or string-array input.
    pub input: Value,
    /// Provider preferences.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider: Option<ProviderPreferences>,
    /// Additional embedding fields.
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
    /// Per-call transport options, never serialized.
    #[serde(skip)]
    pub call_options: CallOptions,
}

/// Embeddings response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmbeddingResponse {
    /// OpenAI-compatible data array.
    #[serde(default)]
    pub data: Vec<Value>,
    /// Model identifier.
    #[serde(default)]
    pub model: String,
    /// Usage object.
    #[serde(default)]
    pub usage: Option<Value>,
    /// Response extensions.
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

/// Model catalog envelope.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelList {
    /// Catalog models.
    #[serde(default)]
    pub data: Vec<ModelInfo>,
    /// Envelope extensions.
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

impl ModelList {
    /// Finds one catalog model by ID.
    pub fn by_id(&self, model_id: &str) -> Option<&ModelInfo> {
        self.data.iter().find(|model| model.id == model_id)
    }
}

/// Model catalog entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelInfo {
    /// Model identifier.
    pub id: String,
    /// Display name.
    #[serde(default)]
    pub name: String,
    /// Description.
    #[serde(default)]
    pub description: String,
    /// Context length.
    #[serde(default)]
    pub context_length: Option<u64>,
    /// Pricing decimal strings.
    #[serde(default)]
    pub pricing: Option<Value>,
    /// Architecture metadata.
    #[serde(default)]
    pub architecture: Option<Value>,
    /// `TrustedRouter` model metadata.
    #[serde(default)]
    pub trustedrouter: Option<Value>,
    /// Catalog extensions.
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

/// Provider catalog envelope.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderList {
    /// Providers.
    #[serde(default)]
    pub data: Vec<ProviderInfo>,
    /// Envelope extensions.
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

/// Provider catalog entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderInfo {
    /// Provider identifier.
    pub id: String,
    /// Display name.
    #[serde(default)]
    pub name: String,
    /// Provider metadata and posture fields.
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

/// Region catalog envelope.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegionList {
    /// Published regions.
    #[serde(default)]
    pub data: Vec<RegionInfo>,
    /// Envelope extensions.
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

/// Region entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegionInfo {
    /// Region identifier.
    pub id: String,
    /// Region display name.
    #[serde(default)]
    pub name: String,
    /// Region metadata.
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

/// Credits envelope. Money remains integer/decimal JSON, never an SDK float.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreditsBalance {
    /// Credits payload.
    pub data: Value,
    /// Envelope extensions.
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

/// Activity envelope.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActivityResponse {
    /// Recent generation metadata.
    #[serde(default)]
    pub activities: Vec<Value>,
    /// Envelope extensions.
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

/// Broadcast destination.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BroadcastDestination {
    /// Destination ID.
    pub id: String,
    /// Destination type.
    #[serde(rename = "type")]
    pub destination_type: String,
    /// Display name.
    #[serde(default)]
    pub name: Option<String>,
    /// Endpoint URL.
    #[serde(default)]
    pub endpoint: Option<String>,
    /// Enabled state.
    #[serde(default)]
    pub enabled: Option<bool>,
    /// Prompt/output content export state.
    #[serde(default)]
    pub include_content: Option<bool>,
    /// HTTP method for webhooks.
    #[serde(default)]
    pub method: Option<String>,
    /// Destination extensions. Secrets remain redacted by the API.
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

/// Broadcast destination list.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BroadcastDestinationList {
    /// Destinations.
    #[serde(default)]
    pub data: Vec<BroadcastDestination>,
    /// Envelope extensions.
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

/// Checkout response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckoutResponse {
    /// Hosted checkout URL.
    #[serde(default)]
    pub url: Option<String>,
    /// Checkout status.
    #[serde(default)]
    pub status: Option<String>,
    /// Response extensions.
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

/// Browser session response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthSessionResponse {
    /// Whether the browser session is authenticated.
    pub authenticated: bool,
    /// Authenticated user.
    #[serde(default)]
    pub user: Option<Value>,
    /// Response extensions.
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

/// OAuth-style user-info envelope.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserInfoResponse {
    /// Identity claims.
    pub data: Value,
    /// Response extensions.
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

/// Model catalog query filters.
#[derive(Debug, Clone, Default)]
pub struct ModelFilters {
    /// Filter by open-weight status.
    pub open_weights: Option<bool>,
    /// Filter by provider jurisdiction.
    pub provider_jurisdiction: Option<String>,
    /// Filter by serving region.
    pub provider_region: Option<String>,
}

/// Convenience conversion for arbitrary JSON messages.
pub fn messages_to_values(messages: impl IntoIterator<Item = ChatMessage>) -> Vec<Value> {
    messages
        .into_iter()
        .map(|message| serde_json::to_value(message).expect("ChatMessage serializes"))
        .collect()
}

pub(crate) fn with_stream<T: Serialize>(request: &T, stream: bool) -> crate::Result<Value> {
    let mut value = serde_json::to_value(request)
        .map_err(|error| crate::Error::Serialization(error.to_string()))?;
    let object = value
        .as_object_mut()
        .ok_or_else(|| crate::Error::Serialization("request is not a JSON object".to_owned()))?;
    object.insert("stream".to_owned(), Value::Bool(stream));
    Ok(value)
}
