//! Server-sent event streaming for Chat Completions and Responses.

use crate::client::{CallOptions, Client, Plane};
use crate::types::{ChatCompletionChunk, ChatRequest, ResponseEvent, ResponsesRequest};
use crate::{Error, Result};
use eventsource_stream::Eventsource;
use futures_core::Stream;
use futures_util::StreamExt;
use http::Method;
use serde_json::Value;
use std::pin::Pin;
use std::time::Duration;

/// Parsed server-sent event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SseEvent {
    /// Optional SSE event name.
    pub event: Option<String>,
    /// Event data after SSE framing is removed.
    pub data: String,
    /// Optional SSE event ID.
    pub id: Option<String>,
}

/// Stream of raw parsed SSE events.
pub type SseStream = Pin<Box<dyn Stream<Item = Result<SseEvent>> + Send>>;

/// Stream of arbitrary JSON payloads.
pub type JsonStream = Pin<Box<dyn Stream<Item = Result<Value>> + Send>>;

/// Stream of Responses API lifecycle events.
pub type ResponseEventStream = Pin<Box<dyn Stream<Item = Result<ResponseEvent>> + Send>>;

/// Stream of visible chat text deltas.
pub type TextStream = Pin<Box<dyn Stream<Item = Result<String>> + Send>>;

impl Client {
    /// Opens parsed Chat Completions chunks. Final usage is requested automatically.
    pub async fn chat_completions_stream(&self, request: ChatRequest) -> Result<JsonStream> {
        let options = stream_options(request.call_options.clone());
        let mut body = crate::types::with_stream(&request, true)?;
        if let Some(object) = body.as_object_mut() {
            object
                .entry("stream_options")
                .or_insert_with(|| serde_json::json!({"include_usage": true}));
        }
        let response = self
            .open_stream(
                Plane::Inference,
                Method::POST,
                "/chat/completions",
                body,
                options.clone(),
            )
            .await?;
        let idle_timeout = options.timeout.or(self.timeout);
        let stream = parse_sse(response, idle_timeout);
        Ok(Box::pin(stream.filter_map(|item| async move {
            match item {
                Ok(event) if event.data == "[DONE]" => None,
                Ok(event) => Some(parse_json_event(&event.data)),
                Err(error) => Some(Err(error)),
            }
        })))
    }

    /// Opens typed Chat Completions chunks.
    pub async fn chat_completion_chunks(
        &self,
        request: ChatRequest,
    ) -> Result<Pin<Box<dyn Stream<Item = Result<ChatCompletionChunk>> + Send>>> {
        let stream = self.chat_completions_stream(request).await?;
        Ok(Box::pin(stream.map(|item| {
            item.and_then(|value| {
                serde_json::from_value(value)
                    .map_err(|error| Error::Serialization(error.to_string()))
            })
        })))
    }

    /// Streams only visible chat completion text deltas.
    pub async fn chat_completions_text(&self, request: ChatRequest) -> Result<TextStream> {
        let stream = self.chat_completions_stream(request).await?;
        Ok(Box::pin(stream.filter_map(|item| async move {
            match item {
                Ok(value) => value
                    .pointer("/choices/0/delta/content")
                    .and_then(Value::as_str)
                    .map(|text| Ok(text.to_owned())),
                Err(error) => Some(Err(error)),
            }
        })))
    }

    /// Opens `OpenAI` Responses API lifecycle events.
    pub async fn responses_stream(&self, request: ResponsesRequest) -> Result<ResponseEventStream> {
        let options = stream_options(request.call_options.clone());
        let body = crate::types::with_stream(&request, true)?;
        let response = self
            .open_stream(
                Plane::Inference,
                Method::POST,
                "/responses",
                body,
                options.clone(),
            )
            .await?;
        let idle_timeout = options.timeout.or(self.timeout);
        let stream = parse_sse(response, idle_timeout);
        Ok(Box::pin(stream.filter_map(|item| async move {
            match item {
                Ok(event) if event.data == "[DONE]" => None,
                Ok(event) => {
                    let value = match parse_json_event(&event.data) {
                        Ok(value) => value,
                        Err(error) => return Some(Err(error)),
                    };
                    let event_name = event
                        .event
                        .filter(|name| !name.is_empty() && name != "message")
                        .or_else(|| value.get("type").and_then(Value::as_str).map(str::to_owned))
                        .unwrap_or_else(|| "message".to_owned());
                    Some(Ok(ResponseEvent {
                        event: event_name,
                        data: value,
                    }))
                }
                Err(error) => Some(Err(error)),
            }
        })))
    }

    /// Opens a raw SSE stream for a supported inference route.
    pub async fn raw_sse(
        &self,
        path: &str,
        body: Value,
        options: CallOptions,
    ) -> Result<SseStream> {
        let options = stream_options(options);
        let response = self
            .open_stream(Plane::Inference, Method::POST, path, body, options.clone())
            .await?;
        Ok(Box::pin(parse_sse(
            response,
            options.timeout.or(self.timeout),
        )))
    }
}

fn parse_sse(response: reqwest::Response, idle_timeout: Option<Duration>) -> SseStream {
    let mut source = response.bytes_stream().eventsource();
    Box::pin(async_stream::stream! {
        loop {
            let next = match idle_timeout {
                Some(duration) if duration != Duration::ZERO => {
                    if let Ok(value) = tokio::time::timeout(duration, source.next()).await {
                        value
                    } else {
                        yield Err(Error::Timeout("SSE stream idle deadline exceeded".to_owned()));
                        break;
                    }
                }
                _ => source.next().await,
            };
            match next {
                Some(Ok(event)) => yield Ok(SseEvent {
                    event: Some(event.event),
                    data: event.data,
                    id: Some(event.id),
                }),
                Some(Err(error)) => {
                    yield Err(Error::Transport(format!("invalid SSE stream: {error}")));
                    break;
                }
                None => break,
            }
        }
    })
}

fn parse_json_event(data: &str) -> Result<Value> {
    let value: Value = serde_json::from_str(data)
        .map_err(|error| Error::Serialization(format!("invalid SSE JSON: {error}")))?;
    if value.get("error").is_some() {
        let status = value
            .pointer("/error/status")
            .and_then(Value::as_u64)
            .and_then(|status| u16::try_from(status).ok())
            .unwrap_or(502);
        return Err(crate::error::classify_api_error(status, Some(value), None));
    }
    Ok(value)
}

fn stream_options(mut options: CallOptions) -> CallOptions {
    if options.idempotency_key.is_none() {
        options.idempotency_key = Some(format!("tr-req-{}", uuid::Uuid::new_v4().simple()));
    }
    options
}
