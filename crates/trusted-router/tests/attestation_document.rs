//! Document-only gateway attestation and the binding every result reports.
//!
//! The fixture is the claim set the live gateway returned on 2026-10-15 (see
//! `fixtures/attestation/metadata.json`). Its shape is the reason this mode
//! exists: there is no `tls_cert_sha256` claim, and the leaf certificate hash
//! is one anonymous `eat_nonce` entry among several, so
//! `verify_gateway_attestation` cannot pass without the certificate DER, which
//! a reqwest caller never has. The tests re-sign those claims with the test
//! key and a fresh expiry, put the test's own nonce where the caller nonce
//! sat, and check that every claim check still runs while no TLS binding is
//! claimed.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::unwrap_in_result,
    clippy::as_conversions,
    reason = "Test assertions and fixture construction deliberately fail loudly"
)]
#![allow(
    missing_docs,
    reason = "Integration test helpers are not public SDK API"
)]

use base64::Engine as _;
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};
use trusted_router::{
    policy_from_trust_release, verify_gateway_attestation, verify_gateway_attestation_document,
    AttestationBinding, AttestationPolicy, AttestationVerificationOptions,
    DocumentVerificationOptions, ErrorKind, GatewayAttestation, TrustRelease, EXPORTER_LENGTH,
    GCP_ISSUER,
};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const TEST_PRIVATE_KEY: &[u8] = include_bytes!("fixtures/attestation-private.pem");
const TEST_RSA_MODULUS: &str = "h5lUGVA4611JPHsVBcu8h38KnZ1hZRs9bnyVk8RFzMNZot9ox3EAobT64XrlK5pYjFOB-rq3ra9j-B0Mxt8Lbn3EYs-ClXO84eCb2IiVLuclcjBDmW5v1xFq2a7Jpgpj7T0Kv-9YZ9GfJSZOM_mEyVMi2SX5tZbvbrVG17j9nBNjvege-Y4g7qzzPy3Im0MwPFD6W5k8kMVZWykrWlOAdG5zLhkK5B3euk7Jle7ZsqMV-wNoiO8l52QXGWwCi0M28KKTnFJgwgusoKcTk4_zGk1601vgioLpC3WkYagP615Eqt4d81YmLIROFqKW8xZHBXcroyAmH8eJdFJ4qZXGow";
const LIVE_CLAIMS: &str = include_str!("fixtures/attestation/live-gateway-claims.json");
const LIVE_LEAF_PEM: &str = include_str!("fixtures/attestation/live-gateway-leaf.pem");
const CALLER_NONCE_SLOT: usize = 3;

fn live() -> Value {
    serde_json::from_str(LIVE_CLAIMS).unwrap()
}

fn leaf_der() -> Vec<u8> {
    let body: String = LIVE_LEAF_PEM
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect();
    base64::engine::general_purpose::STANDARD
        .decode(body)
        .unwrap()
}

fn leaf_sha() -> String {
    hex(&Sha256::digest(leaf_der()))
}

fn now() -> i64 {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    )
    .unwrap()
}

fn fresh_nonce() -> String {
    hex(&rand::random::<[u8; 32]>())
}

/// The live claim set, freshly dated, answering `nonce`.
fn live_claims(nonce: &str) -> Value {
    let mut claims = live();
    let now = now();
    claims["iat"] = json!(now);
    claims["nbf"] = json!(now);
    claims["exp"] = json!(now + 3600);
    claims["eat_nonce"][CALLER_NONCE_SLOT] = json!(nonce);
    claims
}

fn sign(claims: &Value) -> Vec<u8> {
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some("test-key".to_owned());
    encode(
        &header,
        claims,
        &EncodingKey::from_rsa_pem(TEST_PRIVATE_KEY).unwrap(),
    )
    .unwrap()
    .into_bytes()
}

fn jwks_with_modulus(modulus: &str) -> Value {
    json!({"keys": [{"kid": "test-key", "kty": "RSA", "n": modulus, "e": "AQAB"}]})
}

fn jwks() -> Value {
    jwks_with_modulus(TEST_RSA_MODULUS)
}

/// What `policy_from_trust_release` builds from a release that publishes this build.
fn policy() -> AttestationPolicy {
    let claims = live();
    let release = TrustRelease {
        image_digest: claims["submods"]["container"]["image_digest"]
            .as_str()
            .unwrap()
            .to_owned(),
        image_reference: claims["submods"]["container"]["image_reference"]
            .as_str()
            .unwrap()
            .to_owned(),
        ..TrustRelease::default()
    };
    policy_from_trust_release(&release, None).unwrap()
}

fn document_options(nonce: &str) -> DocumentVerificationOptions {
    DocumentVerificationOptions {
        policy: policy(),
        nonce_hex: nonce.to_owned(),
        jwks: Some(jwks()),
        jwks_url: None,
        http_client: None,
    }
}

fn live_options(nonce: Option<&str>) -> AttestationVerificationOptions {
    AttestationVerificationOptions {
        policy: policy(),
        nonce_hex: nonce.map(str::to_owned),
        tls_certificate_der: None,
        tls_exporter: None,
        jwks: Some(jwks()),
        jwks_url: None,
        http_client: None,
    }
}

async fn document_error(token: &[u8], options: DocumentVerificationOptions) -> String {
    let error = verify_gateway_attestation_document(token, options)
        .await
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Attestation);
    error.to_string()
}

// ---- the live shape -----------------------------------------------------------

#[tokio::test]
async fn live_shaped_token_verifies_with_binding_none() {
    let nonce = fresh_nonce();
    let result =
        verify_gateway_attestation_document(&sign(&live_claims(&nonce)), document_options(&nonce))
            .await
            .unwrap();
    let live = live();
    assert_eq!(result.binding(), AttestationBinding::None);
    assert_eq!(result.nonce, nonce);
    assert_eq!(
        result.image_digest,
        live["submods"]["container"]["image_digest"]
    );
    assert_eq!(
        result.image_reference,
        live["submods"]["container"]["image_reference"]
    );
    assert_eq!(result.issuer, GCP_ISSUER);
    assert_eq!(result.audience, "quill-cloud");
    assert!(result.expires_at > now());
    assert_eq!(result.raw_claims["hwmodel"], "GCP_INTEL_TDX");
    assert!(result.cert_sha256_candidates.contains(&leaf_sha()));
    assert!(!result.cert_sha256_candidates.contains(&nonce));
    let expected: Vec<String> = live["eat_nonce"].as_array().unwrap()[..CALLER_NONCE_SLOT]
        .iter()
        .map(|value| value.as_str().unwrap().to_owned())
        .collect();
    assert_eq!(result.cert_sha256_candidates, expected);

    // Serialized results carry the binding, and no certificate as the connection's.
    let serialized = serde_json::to_value(&result).unwrap();
    assert_eq!(serialized["binding"], "none");
    assert!(serialized.get("cert_sha256").is_none());
    assert_eq!(serialized["nonce"], nonce.as_str());
}

#[tokio::test]
async fn default_verifier_still_requires_tls_evidence_for_the_live_shape() {
    let nonce = fresh_nonce();
    let token = sign(&live_claims(&nonce));
    let error = verify_gateway_attestation(&token, live_options(Some(&nonce)))
        .await
        .unwrap_err()
        .to_string();
    assert!(error.contains("does not bind a TLS certificate"), "{error}");
    assert!(
        error.contains("verify_gateway_attestation_document"),
        "{error}"
    );

    let mut options = live_options(Some(&nonce));
    options.tls_certificate_der = Some(leaf_der());
    let bound = verify_gateway_attestation(&token, options).await.unwrap();
    assert_eq!(bound.binding, AttestationBinding::TlsCert);
    assert_eq!(bound.cert_sha256, leaf_sha());
    assert_eq!(serde_json::to_value(&bound).unwrap()["binding"], "tls-cert");
}

#[tokio::test]
async fn fetches_the_jwks_when_none_is_supplied() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/jwks"))
        .respond_with(ResponseTemplate::new(200).set_body_json(jwks()))
        .expect(1)
        .mount(&server)
        .await;
    let nonce = fresh_nonce();
    let mut options = document_options(&nonce);
    options.jwks = None;
    options.jwks_url = Some(format!("{}/jwks", server.uri()));
    let result = verify_gateway_attestation_document(&sign(&live_claims(&nonce)), options)
        .await
        .unwrap();
    assert_eq!(result.binding(), AttestationBinding::None);
}

#[tokio::test]
async fn uppercase_nonce_matches_the_gateways_lowercase_echo() {
    let nonce = fresh_nonce();
    let upper = nonce.to_ascii_uppercase();
    let result =
        verify_gateway_attestation_document(&sign(&live_claims(&nonce)), document_options(&upper))
            .await
            .unwrap();
    assert_eq!(result.nonce, upper);
    assert!(!result.cert_sha256_candidates.contains(&nonce));
}

// ---- failures -------------------------------------------------------------------

#[tokio::test]
async fn a_different_nonce_is_rejected() {
    let token = sign(&live_claims(&fresh_nonce()));
    let error = document_error(&token, document_options(&fresh_nonce())).await;
    assert!(error.contains("nonce is not bound"), "{error}");
}

#[tokio::test]
async fn the_nonce_must_be_in_eat_nonce_not_only_the_legacy_claim() {
    let nonce = fresh_nonce();
    let mut claims = live_claims(&nonce);
    let eat_nonce = claims["eat_nonce"].as_array().unwrap()[..CALLER_NONCE_SLOT].to_vec();
    claims["eat_nonce"] = json!(eat_nonce);
    claims["nonces"] = json!([nonce]);
    let error = document_error(&sign(&claims), document_options(&nonce)).await;
    assert!(error.contains("nonce is not bound"), "{error}");

    claims.as_object_mut().unwrap().remove("eat_nonce");
    let error = document_error(&sign(&claims), document_options(&nonce)).await;
    assert!(error.contains("nonce is not bound"), "{error}");
}

#[tokio::test]
async fn a_workload_digest_outside_the_policy_is_rejected() {
    let nonce = fresh_nonce();
    let mut claims = live_claims(&nonce);
    claims["submods"]["container"]["image_digest"] = json!(format!("sha256:{}", "0".repeat(64)));
    let error = document_error(&sign(&claims), document_options(&nonce)).await;
    assert!(error.contains("image digest pin mismatch"), "{error}");
}

#[tokio::test]
async fn a_workload_reference_outside_the_policy_is_rejected() {
    let nonce = fresh_nonce();
    let mut claims = live_claims(&nonce);
    claims["submods"]["container"]["image_reference"] =
        json!("us-central1-docker.pkg.dev/someone/else/img:tag");
    let error = document_error(&sign(&claims), document_options(&nonce)).await;
    assert!(error.contains("image reference pin mismatch"), "{error}");
}

#[tokio::test]
async fn a_signature_from_an_unpublished_key_is_rejected() {
    // The JWKS publishes a different modulus than the key that signed.
    let mut stranger = TEST_RSA_MODULUS.to_owned();
    stranger.replace_range(10..14, "AAAA");
    let nonce = fresh_nonce();
    let mut options = document_options(&nonce);
    options.jwks = Some(jwks_with_modulus(&stranger));
    let error = document_error(&sign(&live_claims(&nonce)), options).await;
    assert!(error.contains("JWT verification failed"), "{error}");
}

#[tokio::test]
async fn claims_edited_after_signing_are_rejected() {
    let nonce = fresh_nonce();
    let signed = String::from_utf8(sign(&live_claims(&fresh_nonce()))).unwrap();
    let parts: Vec<&str> = signed.split('.').collect();
    let forged_payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(serde_json::to_vec(&live_claims(&nonce)).unwrap());
    let forged = format!("{}.{forged_payload}.{}", parts[0], parts[2]);
    let error = document_error(forged.as_bytes(), document_options(&nonce)).await;
    assert!(error.contains("JWT verification failed"), "{error}");
}

#[tokio::test]
async fn an_expired_token_is_rejected() {
    let nonce = fresh_nonce();
    let mut claims = live_claims(&nonce);
    // Beyond the verifier's 60-second clock-skew leeway.
    claims["exp"] = json!(now() - 3600);
    let error = document_error(&sign(&claims), document_options(&nonce)).await;
    assert!(error.contains("ExpiredSignature"), "{error}");
}

#[tokio::test]
async fn every_token_check_still_runs() {
    for (field, value, needle) in [
        ("iss", json!("https://evil.example"), "InvalidIssuer"),
        ("aud", json!("someone-else"), "InvalidAudience"),
        ("dbgstat", json!("enabled"), "disabled-since-boot"),
        ("swname", json!("GCE"), "not Confidential Space"),
        ("secboot", json!(false), "Secure Boot"),
        (
            "hwmodel",
            json!("GCP_SHIELDED_VM"),
            "unsupported confidential hardware",
        ),
    ] {
        let nonce = fresh_nonce();
        let mut claims = live_claims(&nonce);
        claims[field] = value;
        let error = document_error(&sign(&claims), document_options(&nonce)).await;
        assert!(error.contains(needle), "{field}: {error}");
    }
}

#[tokio::test]
async fn a_policy_pinning_no_image_is_refused() {
    let nonce = fresh_nonce();
    let mut options = document_options(&nonce);
    options.policy = AttestationPolicy::default();
    let error = document_error(&sign(&live_claims(&nonce)), options).await;
    assert!(error.contains("pins no image identity"), "{error}");
}

#[tokio::test]
async fn a_missing_or_weak_nonce_is_refused_before_any_fetch() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_json(jwks()))
        .expect(0)
        .mount(&server)
        .await;
    let token = sign(&live_claims(&fresh_nonce()));
    for nonce in [
        String::new(),
        "ab".repeat(15),                 // 15 bytes: below the 16-byte floor
        "abc".repeat(11),                // odd length
        "zz".repeat(32),                 // not hex
        format!(" {}", "ab".repeat(32)), // not trimmed for the caller
        format!("{}\n", "ab".repeat(32)),
        "ab".repeat(65), // 65 bytes: above the ceiling
    ] {
        let mut options = document_options(&nonce);
        options.jwks = None;
        options.jwks_url = Some(format!("{}/jwks", server.uri()));
        let error = document_error(&token, options).await;
        assert!(
            error.contains("fresh nonce of 16 to 64 random bytes"),
            "{nonce:?}: {error}"
        );
    }
}

// ---- certificate candidates -----------------------------------------------------

#[tokio::test]
async fn candidates_are_hash_shaped_deduplicated_and_exclude_the_nonce() {
    let nonce = fresh_nonce();
    let labelled = "AB".repeat(32);
    let mut claims = live_claims(&nonce);
    claims["tls_cert_sha256"] = json!(labelled);
    claims["eat_nonce"] = json!([
        leaf_sha(),
        nonce,
        labelled.to_ascii_lowercase(),
        leaf_sha().to_ascii_uppercase(),
        "short",
        "f".repeat(65),
    ]);
    let result = verify_gateway_attestation_document(&sign(&claims), document_options(&nonce))
        .await
        .unwrap();
    assert_eq!(
        result.cert_sha256_candidates,
        vec![labelled.to_ascii_lowercase(), leaf_sha()]
    );
    assert_eq!(result.binding(), AttestationBinding::None);
}

#[tokio::test]
async fn a_single_string_eat_nonce_is_accepted() {
    let nonce = fresh_nonce();
    let mut claims = live_claims(&nonce);
    claims["eat_nonce"] = json!(nonce);
    let result = verify_gateway_attestation_document(&sign(&claims), document_options(&nonce))
        .await
        .unwrap();
    assert!(result.cert_sha256_candidates.is_empty());
}

// ---- binding levels of the default verifier -------------------------------------

#[tokio::test]
async fn a_claimed_certificate_with_no_connection_evidence_reports_none() {
    let mut claims = live_claims(&fresh_nonce());
    claims["tls_cert_sha256"] = json!(leaf_sha());
    let token = sign(&claims);
    let claimed = verify_gateway_attestation(&token, live_options(None))
        .await
        .unwrap();
    assert_eq!(claimed.binding, AttestationBinding::None);
    assert_eq!(claimed.cert_sha256, leaf_sha());
    // A policy pin compares against a published hash, not this connection.
    let mut pinned = live_options(None);
    pinned.policy.expected_cert_sha256 = Some(leaf_sha());
    let pinned = verify_gateway_attestation(&token, pinned).await.unwrap();
    assert_eq!(pinned.binding, AttestationBinding::None);
}

#[tokio::test]
async fn a_matching_certificate_reports_tls_cert_and_a_different_one_is_rejected() {
    let nonce = fresh_nonce();
    let mut claims = live_claims(&nonce);
    claims["tls_cert_sha256"] = json!(leaf_sha());
    let token = sign(&claims);
    let mut options = live_options(Some(&nonce));
    options.tls_certificate_der = Some(leaf_der());
    let bound = verify_gateway_attestation(&token, options.clone())
        .await
        .unwrap();
    assert_eq!(bound.binding, AttestationBinding::TlsCert);
    options.tls_certificate_der = Some(vec![1, 2, 3]);
    let error = verify_gateway_attestation(&token, options)
        .await
        .unwrap_err()
        .to_string();
    assert!(error.contains("TLS certificate does not match"), "{error}");
}

#[tokio::test]
async fn a_committed_tls_exporter_reports_tls_exporter() {
    let nonce = fresh_nonce();
    let exporter = rand::random::<[u8; EXPORTER_LENGTH]>().to_vec();
    let mut claims = live_claims(&nonce);
    claims["eat_nonce"][2] = json!(hex(&exporter));
    let mut options = live_options(Some(&nonce));
    options.tls_certificate_der = Some(leaf_der());
    options.tls_exporter = Some(exporter);
    let result = verify_gateway_attestation(&sign(&claims), options)
        .await
        .unwrap();
    assert_eq!(result.binding, AttestationBinding::TlsExporter);
    assert_eq!(result.cert_sha256, leaf_sha());
    assert_eq!(
        serde_json::to_value(&result).unwrap()["binding"],
        "tls-exporter"
    );
}

#[test]
fn results_serialized_before_bindings_existed_deserialize_as_none() {
    let legacy = json!({
        "cert_sha256": "a".repeat(64),
        "image_digest": "sha256:trusted",
        "image_reference": "registry.example/trusted:release",
        "nonce": null,
        "expires_at": 0,
        "issuer": GCP_ISSUER,
        "audience": "quill-cloud",
        "raw_claims": {}
    });
    let parsed: GatewayAttestation = serde_json::from_value(legacy).unwrap();
    assert_eq!(parsed.binding, AttestationBinding::None);
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
