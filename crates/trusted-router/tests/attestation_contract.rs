#![allow(missing_docs)]

use base64::Engine;
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use rand::rngs::OsRng;
use rsa::pkcs8::{EncodePrivateKey, LineEnding};
use rsa::traits::PublicKeyParts;
use rsa::RsaPrivateKey;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};
use trusted_router::{
    verify_gateway_attestation, AttestationPolicy, AttestationVerificationOptions, ErrorKind,
    GCP_ISSUER,
};

fn fixture(debug_status: &str) -> (Vec<u8>, AttestationVerificationOptions) {
    let private = RsaPrivateKey::new(&mut OsRng, 2048).unwrap();
    let public = private.to_public_key();
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
    let pem = private.to_pkcs8_pem(LineEnding::LF).unwrap();
    let token = encode(
        &header,
        &claims,
        &EncodingKey::from_rsa_pem(pem.as_bytes()).unwrap(),
    )
    .unwrap()
    .into_bytes();
    let jwks = json!({"keys": [{
        "kid": "test-key", "kty": "RSA",
        "n": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(public.n().to_bytes_be()),
        "e": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(public.e().to_bytes_be())
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
