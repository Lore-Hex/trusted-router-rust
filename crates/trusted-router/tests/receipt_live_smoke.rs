//! Live production receipt verification. Run explicitly:
//!   `TRUSTEDROUTER_API_KEY=... cargo test --test receipt_live_smoke -- --ignored`
//!
//! Exercises the receipt-key attestation path against a REAL Confidential
//! Space key-binding document (`gcp-cs-jwt`) — the layer the frozen parity fixtures cannot
//! reach (their attestations are placeholders).

use base64::Engine as _;
use sha2::Digest as _;
use trusted_router::{verify_receipt, ReceiptVerificationOptions};

const BASE: &str = "https://api-us-central1.quillrouter.com";
fn expected_issuer() -> String {
    // Prod's issuer era: legacy https://api.quillrouter.com until the
    // QUILL_RECEIPT_ISS pin ships (quill-cloud-proxy#253), canonical after.
    std::env::var("TRUSTEDROUTER_EXPECTED_ISSUER")
        .unwrap_or_else(|_| "https://api.trustedrouter.com".to_owned())
}

#[tokio::test]
#[ignore = "requires TRUSTEDROUTER_API_KEY and production traffic"]
async fn streaming_receipt_verifies_with_full_attestation_chain() {
    let key = std::env::var("TRUSTEDROUTER_API_KEY").expect("TRUSTEDROUTER_API_KEY");
    let body = br#"{"model":"trustedrouter/auto","stream":true,"messages":[{"role":"user","content":"Say PONG."}],"max_tokens":8}"#;
    let client = reqwest::Client::new();
    let wire = client
        .post(format!("{BASE}/v1/chat/completions"))
        .bearer_auth(&key)
        .header("content-type", "application/json")
        .header("x-inference-receipt", "rust_live_check_1")
        .body(body.to_vec())
        .send()
        .await
        .expect("chat call")
        .bytes()
        .await
        .expect("stream body")
        .to_vec();
    let mut receipt: Option<serde_json::Value> = None;
    for event in String::from_utf8_lossy(&wire).split("\n\n") {
        if let Some(payload) = event.strip_prefix("data: ") {
            if payload == "[DONE]" {
                continue;
            }
            if let Ok(value) = serde_json::from_str::<serde_json::Value>(payload) {
                if let Some(embedded) = value.get("inference_receipt") {
                    receipt = Some(embedded.clone());
                }
            }
        }
    }
    let receipt = receipt.expect("receipt event in stream");
    let claims = verify_receipt(
        &serde_json::to_vec(&receipt).unwrap(),
        &expected_issuer(),
        ReceiptVerificationOptions {
            request_body: Some(body),
            response_stream: Some(&wire),
            expected_nonce: Some("rust_live_check_1"),
            max_age_seconds: Some(300),
            ..Default::default()
        },
    )
    .await
    .expect("live streaming receipt must verify with the full chain");
    assert!(!claims.model.selected.is_empty());
}

#[tokio::test]
#[ignore = "requires TRUSTEDROUTER_API_KEY and production traffic"]
async fn compact_receipt_verifies_with_fetched_attestation() {
    let key = std::env::var("TRUSTEDROUTER_API_KEY").expect("TRUSTEDROUTER_API_KEY");
    let body = br#"{"model":"trustedrouter/auto","messages":[{"role":"user","content":"Say PONG."}],"max_tokens":8}"#;
    let client = reqwest::Client::new();
    let response = client
        .post(format!("{BASE}/v1/chat/completions"))
        .bearer_auth(&key)
        .header("content-type", "application/json")
        .header("x-inference-receipt", "rust_live_check_2")
        .body(body.to_vec())
        .send()
        .await
        .expect("chat call");
    let compact = response
        .headers()
        .get("x-inference-receipt")
        .expect("receipt header")
        .to_str()
        .unwrap()
        .to_owned();
    let response_body = response.bytes().await.expect("body").to_vec();
    let payload = compact.split('.').nth(1).expect("compact payload");
    let claims_json: serde_json::Value = serde_json::from_slice(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(payload)
            .expect("payload b64"),
    )
    .unwrap();
    let want = claims_json["att_sha256"].as_str().expect("att_sha256");
    // /receipt-attestation serves the PER-INSTANCE document; a kept-alive
    // connection pins every retry to one instance, so use a fresh
    // connection per attempt and retry until the digest matches.
    let mut attestation = None;
    for _ in 0..12 {
        let fresh = reqwest::Client::new();
        let candidate = fresh
            .get(format!("{BASE}/receipt-attestation"))
            .header("connection", "close")
            .send()
            .await
            .expect("attestation fetch")
            .bytes()
            .await
            .expect("attestation body")
            .to_vec();
        let digest = sha2::Sha256::digest(&candidate);
        if base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest) == want {
            attestation = Some(candidate);
            break;
        }
    }
    let attestation = attestation.expect("matching per-instance attestation within 12 fetches");
    verify_receipt(
        compact.as_bytes(),
        &expected_issuer(),
        ReceiptVerificationOptions {
            request_body: Some(body),
            response_body: Some(&response_body),
            expected_nonce: Some("rust_live_check_2"),
            max_age_seconds: Some(300),
            attestation: Some(&attestation),
            ..Default::default()
        },
    )
    .await
    .expect("live compact receipt must verify with the supplied attestation");
}
