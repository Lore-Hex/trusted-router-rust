//! Blocking facade for applications that do not use an async runtime.

use crate::client::{CallOptions, Client, ClientBuilder, Plane};
use crate::types::{
    ChatCompletion, ChatRequest, CreditsBalance, EmbeddingResponse, EmbeddingsRequest,
    MessagesRequest, MessagesResponse, ModelFilters, ModelList, ProviderList, RegionList,
    ResponseEvent, ResponseObject, ResponsesRequest,
};
use crate::Result;
use futures_util::StreamExt;
use http::Method;
use serde::de::DeserializeOwned;
use serde_json::Value;

/// Blocking wrapper around the asynchronous [`Client`].
#[derive(Debug)]
pub struct BlockingClient {
    client: Client,
    runtime: tokio::runtime::Runtime,
}

impl BlockingClient {
    /// Constructs a blocking client with production defaults.
    pub fn new(api_key: impl Into<String>) -> Result<Self> {
        Self::from_builder(Client::builder().api_key(api_key))
    }

    /// Constructs a blocking client from a configured async client builder.
    pub fn from_builder(builder: ClientBuilder) -> Result<Self> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .map_err(|error| crate::Error::InvalidConfiguration(error.to_string()))?;
        Ok(Self {
            client: builder.build()?,
            runtime,
        })
    }

    /// Returns the underlying asynchronous client.
    pub fn asynchronous(&self) -> &Client {
        &self.client
    }

    /// Sends a typed JSON request.
    pub fn request<T: DeserializeOwned>(
        &self,
        plane: Plane,
        method: Method,
        path: &str,
        body: Option<Value>,
        options: CallOptions,
    ) -> Result<T> {
        self.runtime
            .block_on(self.client.request(plane, method, path, body, options))
    }

    /// Creates a chat completion.
    pub fn chat_completions(&self, request: ChatRequest) -> Result<ChatCompletion> {
        self.runtime.block_on(self.client.chat_completions(request))
    }

    /// Streams chat completion JSON chunks to a callback.
    pub fn chat_completions_stream<F>(&self, request: ChatRequest, mut callback: F) -> Result<()>
    where
        F: FnMut(Value) -> bool,
    {
        self.runtime.block_on(async {
            let mut stream = self.client.chat_completions_stream(request).await?;
            while let Some(item) = stream.next().await {
                if !callback(item?) {
                    break;
                }
            }
            Ok(())
        })
    }

    /// Creates a non-streaming Responses API result.
    pub fn responses(&self, request: ResponsesRequest) -> Result<ResponseObject> {
        self.runtime.block_on(self.client.responses(request))
    }

    /// Streams Responses events to a callback.
    pub fn responses_stream<F>(&self, request: ResponsesRequest, mut callback: F) -> Result<()>
    where
        F: FnMut(ResponseEvent) -> bool,
    {
        self.runtime.block_on(async {
            let mut stream = self.client.responses_stream(request).await?;
            while let Some(item) = stream.next().await {
                if !callback(item?) {
                    break;
                }
            }
            Ok(())
        })
    }

    /// Sends an Anthropic-compatible Messages request.
    pub fn messages(&self, request: MessagesRequest) -> Result<MessagesResponse> {
        self.runtime.block_on(self.client.messages(request))
    }

    /// Creates embeddings.
    pub fn embeddings(&self, request: EmbeddingsRequest) -> Result<EmbeddingResponse> {
        self.runtime.block_on(self.client.embeddings(request))
    }

    /// Fetches the model catalog.
    pub fn models(&self, filters: ModelFilters) -> Result<ModelList> {
        self.runtime.block_on(self.client.models(filters))
    }

    /// Fetches the provider catalog.
    pub fn providers(&self) -> Result<ProviderList> {
        self.runtime.block_on(self.client.providers())
    }

    /// Fetches published regions.
    pub fn regions(&self) -> Result<RegionList> {
        self.runtime.block_on(self.client.regions())
    }

    /// Fetches workspace credits.
    pub fn credits(&self, options: CallOptions) -> Result<CreditsBalance> {
        self.runtime.block_on(self.client.credits(options))
    }

    /// Streams raw SSE events from an inference endpoint to a callback.
    pub fn raw_sse<F>(
        &self,
        path: &str,
        body: Value,
        options: CallOptions,
        mut callback: F,
    ) -> Result<()>
    where
        F: FnMut(crate::SseEvent) -> bool,
    {
        self.runtime.block_on(async {
            let mut stream = self.client.raw_sse(path, body, options).await?;
            while let Some(item) = stream.next().await {
                if !callback(item?) {
                    break;
                }
            }
            Ok(())
        })
    }
}
