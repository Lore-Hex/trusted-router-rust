#![allow(missing_docs)]

use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};
use trusted_router::{
    verify_gateway_attestation, AttestationPolicy, AttestationVerificationOptions, ErrorKind,
    GCP_ISSUER,
};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const TEST_PRIVATE_KEY: &[u8] = include_bytes!("fixtures/attestation-private.pem");
const TEST_RSA_MODULUS: &str = "h5lUGVA4611JPHsVBcu8h38KnZ1hZRs9bnyVk8RFzMNZot9ox3EAobT64XrlK5pYjFOB-rq3ra9j-B0Mxt8Lbn3EYs-ClXO84eCb2IiVLuclcjBDmW5v1xFq2a7Jpgpj7T0Kv-9YZ9GfJSZOM_mEyVMi2SX5tZbvbrVG17j9nBNjvege-Y4g7qzzPy3Im0MwPFD6W5k8kMVZWykrWlOAdG5zLhkK5B3euk7Jle7ZsqMV-wNoiO8l52QXGWwCi0M28KKTnFJgwgusoKcTk4_zGk1601vgioLpC3WkYagP615Eqt4d81YmLIROFqKW8xZHBXcroyAmH8eJdFJ4qZXGow";

fn fixture(debug_status: &str) -> (Vec<u8>, AttestationVerificationOptions) {
    let certificate = b"same-connection-certificate".to_vec();
    let certificate_hash = hex(&Sha256::digest(&certificate));
    let expiry = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 300;
    let claims = json!({
        "iss": GCP_ISSUER,
        "aud": "quill-cloud",
        "exp": expiry,
        "dbgstat": debug_status,
        "swname": "CONFIDENTIAL_SPACE",
        "secboot": true,
        "hwmodel": "GCP_INTEL_TDX",
        "tls_cert_sha256": certificate_hash,
        "eat_nonce": ["fresh-nonce"],
        "submods": {"container": {
            "image_digest": "sha256:trusted",
            "image_reference": "registry.example/trusted:release"
        }}
    });
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some("test-key".to_owned());
    let token = encode(
        &header,
        &claims,
        &EncodingKey::from_rsa_pem(TEST_PRIVATE_KEY).unwrap(),
    )
    .unwrap()
    .into_bytes();
    let jwks = json!({"keys": [{
        "kid": "test-key", "kty": "RSA",
        "n": TEST_RSA_MODULUS,
        "e": "AQAB"
    }]});
    let options = AttestationVerificationOptions {
        policy: AttestationPolicy {
            expected_image_digest: Some("sha256:trusted".to_owned()),
            expected_image_reference: Some("registry.example/trusted:release".to_owned()),
            ..AttestationPolicy::default()
        },
        nonce_hex: Some("fresh-nonce".to_owned()),
        tls_certificate_der: Some(certificate),
        tls_exporter: None,
        jwks: Some(jwks),
        jwks_url: None,
        http_client: None,
    };
    (token, options)
}

#[tokio::test]
async fn verifies_signature_image_nonce_and_certificate() {
    let (token, options) = fixture("disabled-since-boot");
    let result = verify_gateway_attestation(&token, options).await.unwrap();
    assert_eq!(result.image_digest, "sha256:trusted");
    assert_eq!(result.nonce.as_deref(), Some("fresh-nonce"));
    assert_eq!(result.cert_sha256.len(), 64);
}

#[tokio::test]
async fn accepts_any_digest_in_published_rollout_set() {
    let (token, mut options) = fixture("disabled-since-boot");
    options.policy.expected_image_digest = Some("sha256:new".to_owned());
    options.policy.expected_image_digests =
        vec!["sha256:trusted".to_owned(), "sha256:new".to_owned()];
    options.policy.expected_image_reference = Some("registry.example/new:release".to_owned());
    options.policy.expected_image_references = vec![
        "registry.example/trusted:release".to_owned(),
        "registry.example/new:release".to_owned(),
    ];
    let result = verify_gateway_attestation(&token, options).await.unwrap();
    assert_eq!(result.image_digest, "sha256:trusted");
}

#[tokio::test]
async fn rejects_debug_workload_and_bad_nonce() {
    let (token, options) = fixture("enabled");
    let error = verify_gateway_attestation(&token, options)
        .await
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Attestation);
    assert!(error.to_string().contains("debug"));

    let (token, mut options) = fixture("disabled-since-boot");
    options.nonce_hex = Some("replayed".to_owned());
    assert!(verify_gateway_attestation(&token, options).await.is_err());
}

#[tokio::test]
async fn exporter_requires_distinct_nonce_and_exact_length() {
    let (token, mut options) = fixture("disabled-since-boot");
    options.tls_exporter = Some(vec![0; 31]);
    let error = verify_gateway_attestation(&token, options)
        .await
        .unwrap_err();
    assert!(error.to_string().contains("32"));
}

#[tokio::test]
async fn owned_jwks_client_rejects_redirects_while_supplied_policy_is_caller_owned() {
    let source = MockServer::start().await;
    let target = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/jwks"))
        .respond_with(
            ResponseTemplate::new(307).insert_header("location", format!("{}/keys", target.uri())),
        )
        .mount(&source)
        .await;

    let (token, mut options) = fixture("disabled-since-boot");
    let jwks = options.jwks.take().unwrap();
    Mock::given(method("GET"))
        .and(path("/keys"))
        .respond_with(ResponseTemplate::new(200).set_body_json(jwks))
        .mount(&target)
        .await;
    options.jwks_url = Some(format!("{}/jwks", source.uri()));

    let error = verify_gateway_attestation(&token, options.clone())
        .await
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Attestation);
    assert!(error.to_string().contains("HTTP 307"));
    assert!(target.received_requests().await.unwrap().is_empty());

    options.http_client = Some(reqwest::Client::new());
    let verified = verify_gateway_attestation(&token, options).await.unwrap();
    assert_eq!(verified.image_digest, "sha256:trusted");
    assert_eq!(target.received_requests().await.unwrap().len(), 1);
}

fn hex(value: &[u8]) -> String {
    use std::fmt::Write;
    value.iter().fold(
        String::with_capacity(value.len() * 2),
        |mut output, byte| {
            let _ = write!(output, "{byte:02x}");
            output
        },
    )
}
