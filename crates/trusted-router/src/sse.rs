//! Server-sent event streaming for Chat Completions and Responses.

use crate::client::{CallOptions, Client, Plane};
use crate::transport::headers::ensure_idempotency_key;
use crate::types::{ChatCompletionChunk, ChatRequest, ResponseEvent, ResponsesRequest};
use crate::{Error, Result};
use eventsource_stream::{EventStreamError, Eventsource};
use futures_core::Stream;
use futures_util::StreamExt;
use http::Method;
use serde_json::Value;
use std::fmt;
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
        let options = ensure_idempotency_key(request.call_options.clone());
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
        Ok(validate_chat_stream(stream))
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
        let options = ensure_idempotency_key(request.call_options.clone());
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
        Ok(validate_responses_stream(stream))
    }

    /// Opens a raw SSE stream for a supported inference route.
    pub async fn raw_sse(
        &self,
        path: &str,
        body: Value,
        options: CallOptions,
    ) -> Result<SseStream> {
        let options = ensure_idempotency_key(options);
        let response = self
            .open_stream(Plane::Inference, Method::POST, path, body, options.clone())
            .await?;
        Ok(Box::pin(parse_sse(
            response,
            options.timeout.or(self.timeout),
        )))
    }

    /// Opens raw SSE events while applying the strict terminal, JSON, and API
    /// error validation required by known prompt endpoints. Unknown routes
    /// retain the framing-only behavior of [`Self::raw_sse`].
    pub async fn validated_raw_sse(
        &self,
        path: &str,
        body: Value,
        options: CallOptions,
    ) -> Result<SseStream> {
        let stream = self.raw_sse(path, body, options).await?;
        match prompt_stream_kind(path) {
            Some(PromptStreamKind::Chat) => Ok(validate_raw_chat_stream(stream)),
            Some(PromptStreamKind::Responses) => Ok(validate_raw_responses_stream(stream)),
            None => Ok(stream),
        }
    }
}

fn parse_sse(response: reqwest::Response, idle_timeout: Option<Duration>) -> SseStream {
    let mut bytes = Box::pin(response.bytes_stream());
    // Apply the idle deadline to raw body activity, not parsed events. SSE
    // comments and partial frames are valid heartbeats and must reset it.
    let wire = async_stream::stream! {
        loop {
            let next = match idle_timeout {
                Some(duration) if duration != Duration::ZERO => {
                    let Ok(value) = tokio::time::timeout(duration, bytes.next()).await else {
                        yield Err(SseWireError::IdleTimeout);
                        break;
                    };
                    value
                }
                _ => bytes.next().await,
            };
            match next {
                Some(Ok(chunk)) => yield Ok(chunk),
                Some(Err(error)) => {
                    yield Err(SseWireError::Transport(error));
                    break;
                }
                None => break,
            }
        }
    };
    let mut source = Box::pin(wire.eventsource());
    Box::pin(async_stream::stream! {
        while let Some(next) = source.next().await {
            match next {
                Ok(event) => yield Ok(SseEvent {
                    event: Some(event.event),
                    data: event.data,
                    id: Some(event.id),
                }),
                Err(EventStreamError::Transport(SseWireError::IdleTimeout)) => {
                    yield Err(Error::Timeout("SSE stream idle deadline exceeded".to_owned()));
                    break;
                }
                Err(EventStreamError::Transport(SseWireError::Transport(error))) => {
                    yield Err(crate::transport::policy::map_reqwest_error(error));
                    break;
                }
                Err(error) => {
                    yield Err(Error::Transport(format!("invalid SSE stream: {error}")));
                    break;
                }
            }
        }
    })
}

fn validate_chat_stream(mut stream: SseStream) -> JsonStream {
    Box::pin(async_stream::stream! {
        let mut terminated = false;
        while let Some(item) = stream.next().await {
            match item {
                Ok(event) if event.data.trim() == "[DONE]" => {
                    terminated = true;
                    break;
                }
                Ok(event) => match parse_json_event(&event.data) {
                    Ok(value) => yield Ok(value),
                    Err(error) => {
                        yield Err(error);
                        return;
                    }
                },
                Err(error) => {
                    yield Err(error);
                    return;
                }
            }
        }
        if !terminated {
            yield Err(Error::Transport("SSE stream ended before [DONE]".to_owned()));
        }
    })
}

fn validate_responses_stream(mut stream: SseStream) -> ResponseEventStream {
    Box::pin(async_stream::stream! {
        let mut terminated = false;
        while let Some(item) = stream.next().await {
            let event = match item {
                Ok(event) => event,
                Err(error) => {
                    yield Err(error);
                    return;
                }
            };
            if event.data.trim() == "[DONE]" {
                terminated = true;
                break;
            }
            let value = match parse_json_event(&event.data) {
                Ok(value) => value,
                Err(error) => {
                    yield Err(error);
                    return;
                }
            };
            let event_name = event
                .event
                .filter(|name| !name.is_empty() && name != "message")
                .or_else(|| value.get("type").and_then(Value::as_str).map(str::to_owned))
                .unwrap_or_else(|| "message".to_owned());
            let is_terminal = matches!(
                event_name.as_str(),
                "response.completed" | "response.failed" | "response.incomplete" | "error"
            );
            yield Ok(ResponseEvent {
                event: event_name,
                data: value,
            });
            if is_terminal {
                terminated = true;
                break;
            }
        }
        if !terminated {
            yield Err(Error::Transport("SSE stream ended before a terminal event".to_owned()));
        }
    })
}

fn validate_raw_chat_stream(mut stream: SseStream) -> SseStream {
    Box::pin(async_stream::stream! {
        let mut terminated = false;
        while let Some(item) = stream.next().await {
            match item {
                Ok(event) if event.data.trim() == "[DONE]" => {
                    terminated = true;
                    yield Ok(event);
                    break;
                }
                Ok(event) => match parse_json_event(&event.data) {
                    Ok(_) => yield Ok(event),
                    Err(error) => {
                        yield Err(error);
                        return;
                    }
                },
                Err(error) => {
                    yield Err(error);
                    return;
                }
            }
        }
        if !terminated {
            yield Err(Error::Transport("SSE stream ended before [DONE]".to_owned()));
        }
    })
}

fn validate_raw_responses_stream(mut stream: SseStream) -> SseStream {
    Box::pin(async_stream::stream! {
        let mut terminated = false;
        while let Some(item) = stream.next().await {
            let event = match item {
                Ok(event) => event,
                Err(error) => {
                    yield Err(error);
                    return;
                }
            };
            if event.data.trim() == "[DONE]" {
                terminated = true;
                yield Ok(event);
                break;
            }
            let value = match parse_json_event(&event.data) {
                Ok(value) => value,
                Err(error) => {
                    yield Err(error);
                    return;
                }
            };
            let event_name = event
                .event
                .as_deref()
                .filter(|name| !name.is_empty() && *name != "message")
                .map(str::to_owned)
                .or_else(|| value.get("type").and_then(Value::as_str).map(str::to_owned))
                .unwrap_or_else(|| "message".to_owned());
            let is_terminal = matches!(
                event_name.as_str(),
                "response.completed" | "response.failed" | "response.incomplete" | "error"
            );
            yield Ok(event);
            if is_terminal {
                terminated = true;
                break;
            }
        }
        if !terminated {
            yield Err(Error::Transport("SSE stream ended before a terminal event".to_owned()));
        }
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PromptStreamKind {
    Chat,
    Responses,
}

fn prompt_stream_kind(path: &str) -> Option<PromptStreamKind> {
    let path = path.split('?').next().unwrap_or(path).trim_matches('/');
    match path {
        "chat/completions" => Some(PromptStreamKind::Chat),
        "responses" => Some(PromptStreamKind::Responses),
        _ => None,
    }
}

#[derive(Debug)]
enum SseWireError {
    Transport(reqwest::Error),
    IdleTimeout,
}

impl fmt::Display for SseWireError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Transport(error) => error.fmt(formatter),
            Self::IdleTimeout => formatter.write_str("SSE wire idle deadline exceeded"),
        }
    }
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
