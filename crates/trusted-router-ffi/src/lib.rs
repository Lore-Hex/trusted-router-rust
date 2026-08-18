//! Stable C ABI for the `TrustedRouter` Rust SDK.

use serde_json::Value;
use std::ffi::{c_char, c_int, c_void, CStr, CString};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::ptr;
use trusted_router::{BlockingClient, CallOptions, Client, Error, Plane};

/// Opaque client owned by C callers.
pub struct TrClient {
    inner: BlockingClient,
}

/// Heap-owned C result. Release it exactly once with [`tr_result_free`].
#[repr(C)]
pub struct TrResult {
    /// Zero on success; otherwise a stable SDK error-kind number.
    pub code: c_int,
    /// HTTP status or zero for local/transport failures.
    pub http_status: c_int,
    /// UTF-8 JSON on success, otherwise null.
    pub data: *mut c_char,
    /// UTF-8 error message on failure, otherwise null.
    pub error: *mut c_char,
}

/// Streaming callback. Return nonzero to continue or zero to cancel cleanly.
pub type TrStreamCallback =
    Option<unsafe extern "C" fn(event_json: *const c_char, user_data: *mut c_void) -> c_int>;

/// Creates a client. Optional base URLs may be null. Returns null on invalid input.
///
/// # Safety
/// Every non-null argument must point to a valid NUL-terminated UTF-8 string.
#[no_mangle]
pub unsafe extern "C" fn tr_client_new(
    api_key: *const c_char,
    api_base_url: *const c_char,
    control_base_url: *const c_char,
) -> *mut TrClient {
    match catch_unwind(AssertUnwindSafe(|| {
        let key = unsafe { optional_string(api_key) }
            .ok()?
            .unwrap_or_default();
        let mut builder = Client::builder().api_key(key);
        if let Some(value) = unsafe { optional_string(api_base_url) }.ok()? {
            builder = builder.api_base_url(value);
        }
        if let Some(value) = unsafe { optional_string(control_base_url) }.ok()? {
            builder = builder.control_base_url(value);
        }
        let client = BlockingClient::from_builder(builder).ok()?;
        Some(Box::into_raw(Box::new(TrClient { inner: client })))
    })) {
        Ok(Some(client)) => client,
        _ => ptr::null_mut(),
    }
}

/// Releases a client. Passing null is allowed.
///
/// # Safety
/// `client` must be null or a pointer returned by [`tr_client_new`] that has not
/// already been released.
#[no_mangle]
pub unsafe extern "C" fn tr_client_free(client: *mut TrClient) {
    if !client.is_null() {
        let _ = catch_unwind(AssertUnwindSafe(|| {
            // SAFETY: guaranteed by this function's contract.
            drop(unsafe { Box::from_raw(client) });
        }));
    }
}

/// Sends an arbitrary JSON request through the inference or control plane.
///
/// `plane` is 0 for inference and 1 for control. `body_json` may be null.
///
/// # Safety
/// Pointers must satisfy the ownership and UTF-8 requirements documented in
/// `trusted_router.h`. The client must remain alive for the call.
#[no_mangle]
pub unsafe extern "C" fn tr_request_json(
    client: *mut TrClient,
    plane: c_int,
    method: *const c_char,
    path: *const c_char,
    body_json: *const c_char,
    workspace_id: *const c_char,
    idempotency_key: *const c_char,
) -> TrResult {
    unsafe {
        tr_request_json_with_policy(
            client,
            plane,
            method,
            path,
            body_json,
            workspace_id,
            idempotency_key,
            false,
        )
    }
}

#[allow(clippy::too_many_arguments)]
unsafe fn tr_request_json_with_policy(
    client: *mut TrClient,
    plane: c_int,
    method: *const c_char,
    path: *const c_char,
    body_json: *const c_char,
    workspace_id: *const c_char,
    idempotency_key: *const c_char,
    auto_idempotency: bool,
) -> TrResult {
    guarded(|| {
        let client = unsafe { client_ref(client) }?;
        let method = unsafe { required_string(method, "method") }?;
        let method = http::Method::from_bytes(method.as_bytes())
            .map_err(|error| local_error(format!("invalid method: {error}")))?;
        let path = unsafe { required_string(path, "path") }?;
        let body = unsafe { optional_string(body_json) }?
            .map(|value| serde_json::from_str(&value))
            .transpose()
            .map_err(|error| local_error(format!("invalid body JSON: {error}")))?;
        let mut options = unsafe { call_options(workspace_id, idempotency_key) }?;
        if auto_idempotency && options.idempotency_key.is_none() {
            options.idempotency_key = Some(generated_idempotency_key());
        }
        let plane = match plane {
            0 => Plane::Inference,
            1 => Plane::Control,
            _ => return Err(local_error("plane must be 0 or 1".to_owned())),
        };
        let response: Value = client.inner.request(plane, method, &path, body, options)?;
        success_json(response)
    })
}

/// Calls `/chat/completions` with an OpenAI-compatible request body.
///
/// # Safety
/// Same pointer requirements as [`tr_request_json`].
#[no_mangle]
pub unsafe extern "C" fn tr_chat_completions(
    client: *mut TrClient,
    request_json: *const c_char,
    workspace_id: *const c_char,
    idempotency_key: *const c_char,
) -> TrResult {
    unsafe {
        tr_request_json_with_policy(
            client,
            0,
            c"POST".as_ptr(),
            c"/chat/completions".as_ptr(),
            request_json,
            workspace_id,
            idempotency_key,
            true,
        )
    }
}

/// Calls `/responses` with an OpenAI-compatible request body.
///
/// # Safety
/// Same pointer requirements as [`tr_request_json`].
#[no_mangle]
pub unsafe extern "C" fn tr_responses(
    client: *mut TrClient,
    request_json: *const c_char,
    workspace_id: *const c_char,
    idempotency_key: *const c_char,
) -> TrResult {
    unsafe {
        tr_request_json_with_policy(
            client,
            0,
            c"POST".as_ptr(),
            c"/responses".as_ptr(),
            request_json,
            workspace_id,
            idempotency_key,
            true,
        )
    }
}

/// Streams SSE events from a prompt endpoint.
///
/// The callback receives one temporary JSON string per event with `event`,
/// `data`, and `id` fields. It must copy data it retains.
///
/// # Safety
/// Same pointer requirements as [`tr_request_json`]. `callback` must be a valid
/// function pointer for the duration of this call.
#[no_mangle]
pub unsafe extern "C" fn tr_stream_json(
    client: *mut TrClient,
    path: *const c_char,
    body_json: *const c_char,
    workspace_id: *const c_char,
    idempotency_key: *const c_char,
    callback: TrStreamCallback,
    user_data: *mut c_void,
) -> TrResult {
    guarded(|| {
        let client = unsafe { client_ref(client) }?;
        let path = unsafe { required_string(path, "path") }?;
        let body_text = unsafe { required_string(body_json, "body_json") }?;
        let mut body: Value = serde_json::from_str(&body_text)
            .map_err(|error| local_error(format!("invalid body JSON: {error}")))?;
        if let Some(object) = body.as_object_mut() {
            object.insert("stream".to_owned(), Value::Bool(true));
        }
        let mut options = unsafe { call_options(workspace_id, idempotency_key) }?;
        if options.idempotency_key.is_none() {
            options.idempotency_key = Some(generated_idempotency_key());
        }
        let callback = callback.ok_or_else(|| local_error("callback is required".to_owned()))?;
        client
            .inner
            .validated_raw_sse(&path, body, options, |event| {
                let value = serde_json::json!({
                    "event": event.event,
                    "data": event.data,
                    "id": event.id,
                });
                let Ok(text) = serde_json::to_string(&value) else {
                    return false;
                };
                let Ok(text) = CString::new(text) else {
                    return false;
                };
                // SAFETY: the caller supplied the callback; the string lives through the call.
                unsafe { callback(text.as_ptr(), user_data) != 0 }
            })?;
        success_json(serde_json::json!({"completed": true}))
    })
}

/// Releases strings held by a [`TrResult`]. Passing a zeroed result is allowed.
///
/// # Safety
/// Each non-null pointer must originate from a result returned by this library
/// and must not already have been freed.
#[no_mangle]
pub unsafe extern "C" fn tr_result_free(result: TrResult) {
    let _ = catch_unwind(AssertUnwindSafe(|| {
        if !result.data.is_null() {
            // SAFETY: guaranteed by this function's contract.
            drop(unsafe { CString::from_raw(result.data) });
        }
        if !result.error.is_null() {
            // SAFETY: guaranteed by this function's contract.
            drop(unsafe { CString::from_raw(result.error) });
        }
    }));
}

fn guarded(operation: impl FnOnce() -> Result<TrResult, Error>) -> TrResult {
    match catch_unwind(AssertUnwindSafe(operation)) {
        Ok(Ok(result)) => result,
        Ok(Err(error)) => failure_result(error),
        Err(_) => failure_result(local_error("panic contained at C ABI boundary".to_owned())),
    }
}

fn success_json(value: Value) -> Result<TrResult, Error> {
    let text = serde_json::to_string(&value)
        .map_err(|error| local_error(format!("cannot encode response: {error}")))?;
    Ok(TrResult {
        code: 0,
        http_status: 200,
        data: owned_c_string(text),
        error: ptr::null_mut(),
    })
}

fn failure_result(error: Error) -> TrResult {
    TrResult {
        code: error_code(&error),
        http_status: error.status_code().map_or(0, i32::from),
        data: ptr::null_mut(),
        error: owned_c_string(error.to_string()),
    }
}

fn error_code(error: &Error) -> c_int {
    use trusted_router::ErrorKind;
    match error.kind() {
        ErrorKind::BadRequest => 1,
        ErrorKind::Authentication => 2,
        ErrorKind::PermissionDenied => 3,
        ErrorKind::NotFound => 4,
        ErrorKind::RateLimit => 5,
        ErrorKind::EndpointNotSupported => 6,
        ErrorKind::Internal => 7,
        ErrorKind::Transport => 8,
        ErrorKind::Timeout => 9,
        ErrorKind::Serialization => 10,
        ErrorKind::InvalidConfiguration => 11,
        ErrorKind::Attestation => 12,
        ErrorKind::OAuth => 13,
    }
}

unsafe fn client_ref<'a>(client: *mut TrClient) -> Result<&'a TrClient, Error> {
    // SAFETY: caller contract requires a live client pointer.
    unsafe { client.as_ref() }.ok_or_else(|| local_error("client is null".to_owned()))
}

unsafe fn optional_string(pointer: *const c_char) -> Result<Option<String>, Error> {
    if pointer.is_null() {
        return Ok(None);
    }
    // SAFETY: caller contract requires valid NUL-terminated memory.
    unsafe { CStr::from_ptr(pointer) }
        .to_str()
        .map(|value| Some(value.to_owned()))
        .map_err(|error| local_error(format!("C string is not UTF-8: {error}")))
}

unsafe fn required_string(pointer: *const c_char, name: &str) -> Result<String, Error> {
    unsafe { optional_string(pointer) }?
        .ok_or_else(|| local_error(format!("{name} is null or not UTF-8")))
}

unsafe fn call_options(
    workspace_id: *const c_char,
    idempotency_key: *const c_char,
) -> Result<CallOptions, Error> {
    let workspace_id = unsafe { optional_string(workspace_id) }?;
    let idempotency_key = unsafe { optional_string(idempotency_key) }?;
    Ok(CallOptions {
        workspace_id,
        idempotency_key,
        ..CallOptions::default()
    })
}

fn owned_c_string(value: String) -> *mut c_char {
    let safe = value.replace('\0', "\\u0000");
    CString::new(safe).map_or(ptr::null_mut(), CString::into_raw)
}

fn local_error(message: String) -> Error {
    Error::InvalidConfiguration(message)
}

fn generated_idempotency_key() -> String {
    format!("tr-req-{}", uuid::Uuid::new_v4().simple())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::thread;

    unsafe extern "C" fn continue_stream_callback(
        _event_json: *const c_char,
        user_data: *mut c_void,
    ) -> c_int {
        // SAFETY: `invoke_stream` passes a live AtomicUsize for the call.
        let count = unsafe { &*user_data.cast::<AtomicUsize>() };
        count.fetch_add(1, Ordering::SeqCst);
        1
    }

    unsafe extern "C" fn cancel_stream_callback(
        _event_json: *const c_char,
        user_data: *mut c_void,
    ) -> c_int {
        // SAFETY: `invoke_stream` passes a live AtomicUsize for the call.
        let count = unsafe { &*user_data.cast::<AtomicUsize>() };
        count.fetch_add(1, Ordering::SeqCst);
        0
    }

    #[derive(Debug)]
    struct StreamOutcome {
        code: c_int,
        http_status: c_int,
        data: Option<String>,
        error: Option<String>,
        callbacks: usize,
        wire_path: String,
    }

    fn invoke_stream(path: &str, sse_body: &str, callback: TrStreamCallback) -> StreamOutcome {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let sse_body = sse_body.to_owned();
        let server = thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            let mut request = [0_u8; 8192];
            let read = socket.read(&mut request).unwrap();
            let request = String::from_utf8_lossy(&request[..read]);
            let wire_path = request
                .lines()
                .next()
                .and_then(|line| line.split_whitespace().nth(1))
                .expect("HTTP request line should contain a path")
                .to_owned();
            write!(
                socket,
                "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                sse_body.len(),
                sse_body
            )
            .unwrap();
            wire_path
        });

        let key = CString::new("sk-c-stream-test").unwrap();
        let base = CString::new(format!("http://{address}/v1")).unwrap();
        let path = CString::new(path).unwrap();
        let body = CString::new(r#"{"model":"trustedrouter/fast"}"#).unwrap();
        let callbacks = AtomicUsize::new(0);
        // SAFETY: all pointers remain live for the duration of the synchronous call.
        let client = unsafe { tr_client_new(key.as_ptr(), base.as_ptr(), base.as_ptr()) };
        assert!(!client.is_null());
        // SAFETY: the client, strings, callback, and user-data pointer are valid.
        let result = unsafe {
            tr_stream_json(
                client,
                path.as_ptr(),
                body.as_ptr(),
                ptr::null(),
                ptr::null(),
                callback,
                (&raw const callbacks).cast_mut().cast(),
            )
        };
        let data = (!result.data.is_null()).then(|| {
            // SAFETY: non-null result data is a live SDK-owned C string.
            unsafe { CStr::from_ptr(result.data) }
                .to_string_lossy()
                .into_owned()
        });
        let error = (!result.error.is_null()).then(|| {
            // SAFETY: non-null result errors are live SDK-owned C strings.
            unsafe { CStr::from_ptr(result.error) }
                .to_string_lossy()
                .into_owned()
        });
        // Join before constructing the outcome so the request's resolved wire
        // path is available to route-normalisation assertions.
        let wire_path = server.join().unwrap();
        let outcome = StreamOutcome {
            code: result.code,
            http_status: result.http_status,
            data,
            error,
            callbacks: callbacks.load(Ordering::SeqCst),
            wire_path,
        };
        // SAFETY: each SDK-owned object is released exactly once.
        unsafe {
            tr_result_free(result);
            tr_client_free(client);
        }
        outcome
    }

    #[test]
    fn c_abi_round_trip_and_result_ownership() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let mut keys = Vec::new();
            for attempt in 0..2 {
                let (mut socket, _) = listener.accept().unwrap();
                let mut request = [0_u8; 8192];
                let read = socket.read(&mut request).unwrap();
                let text = String::from_utf8_lossy(&request[..read]);
                assert!(text.starts_with("POST /v1/chat/completions"));
                assert!(text.contains("authorization: Bearer sk-c-test"));
                let key = text
                    .lines()
                    .find_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        name.eq_ignore_ascii_case("idempotency-key")
                            .then(|| value.trim().to_owned())
                    })
                    .expect("C ABI high-level call should mint an idempotency key");
                keys.push(key);

                if attempt == 0 {
                    let body = r#"{"error":{"message":"retry"}}"#;
                    write!(
                        socket,
                        "HTTP/1.1 503 Service Unavailable\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    )
                    .unwrap();
                } else {
                    let body = r#"{"id":"chat_c","choices":[{"index":0,"message":{"role":"assistant","content":"PONG"}}]}"#;
                    write!(
                        socket,
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    )
                    .unwrap();
                }
            }
            keys
        });

        let key = CString::new("sk-c-test").unwrap();
        let base = CString::new(format!("http://{address}/v1")).unwrap();
        let body = CString::new(
            r#"{"model":"trustedrouter/fast","messages":[{"role":"user","content":"ping"}]}"#,
        )
        .unwrap();
        // SAFETY: all pointers remain valid for the duration of each call.
        let client = unsafe { tr_client_new(key.as_ptr(), base.as_ptr(), base.as_ptr()) };
        assert!(!client.is_null());
        // SAFETY: client and request pointers are valid and singly owned.
        let result =
            unsafe { tr_chat_completions(client, body.as_ptr(), ptr::null(), ptr::null()) };
        assert_eq!(result.code, 0);
        assert_eq!(result.http_status, 200);
        // SAFETY: successful results carry a valid NUL-terminated string.
        let payload = unsafe { CStr::from_ptr(result.data) }.to_str().unwrap();
        assert!(payload.contains("PONG"));
        // SAFETY: each owned object is released once.
        unsafe {
            tr_result_free(result);
            tr_client_free(client);
        }
        let keys = server.join().unwrap();
        assert_eq!(keys.len(), 2);
        assert_eq!(keys[0], keys[1]);
        assert!(keys[0].starts_with("tr-req-"));
    }

    #[test]
    fn c_abi_contains_null_pointer_errors() {
        // SAFETY: null is explicitly accepted and converted into an error result.
        let result = unsafe {
            tr_request_json(
                ptr::null_mut(),
                0,
                c"GET".as_ptr(),
                c"/models".as_ptr(),
                ptr::null(),
                ptr::null(),
                ptr::null(),
            )
        };
        assert_ne!(result.code, 0);
        assert!(result.data.is_null());
        assert!(!result.error.is_null());
        // SAFETY: the result is released once.
        unsafe { tr_result_free(result) };
    }

    #[test]
    fn c_abi_chat_stream_rejects_truncation_malformed_json_and_api_errors() {
        let truncated = invoke_stream(
            "/chat/completions",
            "data: {\"id\":\"chunk\",\"choices\":[]}\n\n",
            Some(continue_stream_callback),
        );
        assert_eq!(truncated.code, 8);
        assert_eq!(truncated.http_status, 0);
        assert_eq!(truncated.callbacks, 1);
        assert!(truncated
            .error
            .as_deref()
            .unwrap()
            .contains("ended before [DONE]"));

        let malformed = invoke_stream(
            "/chat/completions",
            "data: {not-json}\n\ndata: [DONE]\n\n",
            Some(continue_stream_callback),
        );
        assert_eq!(malformed.code, 10);
        assert_eq!(malformed.callbacks, 0);
        assert!(malformed
            .error
            .as_deref()
            .unwrap()
            .contains("invalid SSE JSON"));

        let api_error = invoke_stream(
            "/chat/completions",
            "data: {\"error\":{\"message\":\"limited\",\"status\":429}}\n\n",
            Some(continue_stream_callback),
        );
        assert_eq!(api_error.code, 5);
        assert_eq!(api_error.http_status, 429);
        assert_eq!(api_error.callbacks, 0);
        assert!(api_error.error.as_deref().unwrap().contains("limited"));
    }

    #[test]
    fn c_abi_responses_stream_requires_a_terminal_event() {
        let truncated = invoke_stream(
            "/responses",
            "event: response.output_text.delta\ndata: {\"type\":\"response.output_text.delta\",\"delta\":\"x\"}\n\n",
            Some(continue_stream_callback),
        );
        assert_eq!(truncated.code, 8);
        assert_eq!(truncated.callbacks, 1);
        assert!(truncated
            .error
            .as_deref()
            .unwrap()
            .contains("before a terminal event"));
    }

    #[test]
    fn c_abi_known_stream_terminals_complete_successfully() {
        let chat = invoke_stream(
            "/chat/completions",
            "data: {\"id\":\"chunk\",\"choices\":[]}\n\ndata: [DONE]\n\n",
            Some(continue_stream_callback),
        );
        assert_eq!(chat.code, 0);
        assert_eq!(chat.callbacks, 2);

        let responses = invoke_stream(
            "/responses",
            "event: response.completed\ndata: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp_1\"}}\n\n",
            Some(continue_stream_callback),
        );
        assert_eq!(responses.code, 0);
        assert_eq!(responses.callbacks, 1);
    }

    #[test]
    fn c_abi_semantic_prompt_routes_cannot_bypass_validation() {
        let chat_dot_segment = invoke_stream(
            "/x/../chat/completions",
            "data: {not-json}\n\n",
            Some(continue_stream_callback),
        );
        assert_eq!(chat_dot_segment.wire_path, "/v1/chat/completions");
        assert_eq!(chat_dot_segment.code, 10);
        assert_eq!(chat_dot_segment.callbacks, 0);

        let responses_dot_segment = invoke_stream(
            "/x/../responses",
            "event: response.output_text.delta\ndata: {\"type\":\"response.output_text.delta\",\"delta\":\"x\"}\n\n",
            Some(continue_stream_callback),
        );
        assert_eq!(responses_dot_segment.wire_path, "/v1/responses");
        assert_eq!(responses_dot_segment.code, 8);
        assert_eq!(responses_dot_segment.callbacks, 1);

        for spelling in [
            "/chat/%63ompletions",
            "/chat/completion%73",
            "/chat%2fcompletions",
            "/CHAT/COMPLETIONS",
            "/chat//completions",
        ] {
            let malformed = invoke_stream(
                spelling,
                "data: {not-json}\n\n",
                Some(continue_stream_callback),
            );
            assert_eq!(malformed.code, 10, "chat route spelling {spelling}");
            assert_eq!(malformed.callbacks, 0, "chat route spelling {spelling}");
        }

        for spelling in [
            "/%72esponses",
            "/response%73",
            "/responses%2f",
            "/RESPONSES",
            "/responses//",
        ] {
            let truncated = invoke_stream(
                spelling,
                "event: response.output_text.delta\ndata: {\"type\":\"response.output_text.delta\",\"delta\":\"x\"}\n\n",
                Some(continue_stream_callback),
            );
            assert_eq!(truncated.code, 8, "Responses route spelling {spelling}");
            assert_eq!(
                truncated.callbacks, 1,
                "Responses route spelling {spelling}"
            );
        }
    }

    #[test]
    fn c_abi_callback_cancellation_is_clean_success() {
        let cancelled = invoke_stream(
            "/chat/completions",
            "data: {\"id\":\"chunk\",\"choices\":[]}\n\n",
            Some(cancel_stream_callback),
        );
        assert_eq!(cancelled.code, 0);
        assert_eq!(cancelled.http_status, 200);
        assert_eq!(cancelled.callbacks, 1);
        assert_eq!(cancelled.data.as_deref(), Some("{\"completed\":true}"));
        assert!(cancelled.error.is_none());
    }
}
