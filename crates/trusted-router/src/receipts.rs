//! Offline verification for signed inference receipts (wire format v1).

use crate::attestation::{
    policy_from_trust_release, verify_receipt_key_attestation, AttestationVerificationOptions,
    TrustRelease,
};
use crate::constants::DEFAULT_TRUST_RELEASE_URL;
use crate::telemetry::wire::sdk_user_agent;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use bytes::Bytes;
use constant_time_eq::constant_time_eq;
use ed25519_dalek::{Signature, VerifyingKey};
use futures_core::Stream;
use serde::de::{self, Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Number, Value};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::{SystemTime, UNIX_EPOCH};

const RECEIPT_TYPE: &str = "inference-receipt+jws";
const KEY_COMMITMENT_DOMAIN: &[u8] = b"inference-receipt-key-v1\0";

/// Result type returned by receipt verification.
pub type ReceiptResult<T> = std::result::Result<T, ReceiptVerificationError>;

/// Common, typed error taxonomy for all fail-closed receipt checks.
#[derive(Debug, thiserror::Error)]
pub enum ReceiptVerificationError {
    /// The compact or flattened JWS structure is malformed.
    #[error("receipt structure verification failed: {0}")]
    Structure(String),
    /// The protected JWS header is invalid or unsupported.
    #[error("receipt header verification failed: {0}")]
    Header(String),
    /// The Ed25519 signature is invalid or cannot be checked.
    #[error("receipt signature verification failed: {0}")]
    Signature(String),
    /// A required receipt claim is missing, malformed, or unsupported.
    #[error("receipt claims verification failed: {0}")]
    Claims(String),
    /// Required caller traffic for a receipt digest binding is absent.
    #[error(transparent)]
    MissingBinding(#[from] MissingBindingError),
    /// The receipt issuer is invalid or does not match the caller's pin.
    #[error(transparent)]
    Issuer(#[from] ReceiptIssuerError),
    /// The issue time or requested age bound is invalid.
    #[error("receipt time verification failed: {0}")]
    Time(String),
    /// The receipt does not echo the expected nonce.
    #[error("receipt nonce verification failed: {0}")]
    Nonce(String),
    /// The upstream verification window or tier is invalid.
    #[error("receipt upstream verification failed: {0}")]
    Upstream(String),
    /// A request or response byte digest check failed.
    #[error("receipt hash verification failed: {0}")]
    Hash(String),
    /// Receipt-key attestation evidence did not verify.
    #[error("receipt attestation verification failed: {0}")]
    Attestation(String),
    /// Required attestation evidence is absent.
    #[error(transparent)]
    MissingAttestation(#[from] MissingAttestationError),
    /// The attestation kind cannot be verified by this SDK.
    #[error(transparent)]
    UnsupportedAttestation(#[from] UnsupportedAttestationError),
}

/// Required receipt attestation evidence is absent.
#[derive(Debug, thiserror::Error)]
#[error("receipt attestation verification failed: {0}")]
pub struct MissingAttestationError(pub String);

/// Required caller traffic for a receipt digest binding is absent.
#[derive(Debug, thiserror::Error)]
#[error("receipt binding verification failed: {0}")]
pub struct MissingBindingError(pub String);

/// The receipt issuer is invalid or does not match the caller's pin.
#[derive(Debug, thiserror::Error)]
#[error("receipt issuer verification failed: {0}")]
pub struct ReceiptIssuerError(pub String);

/// The receipt uses an attestation kind this SDK cannot verify.
#[derive(Debug, thiserror::Error)]
#[error("receipt attestation verification failed: {0}")]
pub struct UnsupportedAttestationError(pub String);

/// Inputs to [`verify_receipt`].
#[derive(Debug, Clone)]
pub struct ReceiptVerificationOptions<'a> {
    /// Exact request body bytes, when available.
    pub request_body: Option<&'a [u8]>,
    /// Exact non-streaming response body bytes, when available.
    pub response_body: Option<&'a [u8]>,
    /// Exact captured SSE wire bytes, when available.
    pub response_stream: Option<&'a [u8]>,
    /// Nonce that the receipt must echo.
    pub expected_nonce: Option<&'a str>,
    /// Maximum permitted receipt age in seconds.
    pub max_age_seconds: Option<u64>,
    /// Unix time in seconds used for deterministic verification.
    pub now: Option<i64>,
    /// Exact GCP attestation-document bytes for a compact receipt.
    ///
    /// The document must hash to the receipt's `att_sha256` claim. For a
    /// flattened receipt, supplied bytes must exactly match its embedded
    /// document. `/receipt-attestation` serves per-instance evidence, so retry
    /// that fetch until its SHA-256 matches `att_sha256`.
    pub attestation: Option<&'a [u8]>,
    /// Whether missing attestation evidence is an error.
    pub require_attestation: bool,
    /// Whether both request and response traffic bindings are required.
    ///
    /// Leave this enabled unless intentionally performing signature-only or
    /// partial-binding inspection.
    pub require_bindings: bool,
}

impl Default for ReceiptVerificationOptions<'_> {
    fn default() -> Self {
        Self {
            request_body: None,
            response_body: None,
            response_stream: None,
            expected_nonce: None,
            max_age_seconds: None,
            now: None,
            attestation: None,
            require_attestation: true,
            require_bindings: true,
        }
    }
}

/// A verified request or response hash record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceiptHashClaims {
    /// Digest algorithm. Wire format v1 requires `sha256`.
    pub alg: String,
    /// Base64url-unpadded digest.
    pub hash: String,
    /// Hash domain.
    pub of: String,
    /// Number of hashed SSE events, when carried.
    pub events: Option<u64>,
}

/// Model routing claims from a verified receipt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceiptModelClaims {
    /// Model name supplied by the caller.
    pub requested: String,
    /// Model selected after alias resolution.
    pub selected: String,
    /// Selected provider.
    pub provider: String,
    /// Selected provider endpoint.
    pub endpoint: String,
}

/// Upstream transport or TEE verification claims.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceiptUpstreamClaims {
    /// Upstream verification tier.
    pub tier: String,
    /// TEE verification policy, when applicable.
    pub policy: Option<String>,
    /// Time the upstream evidence was verified.
    pub verified_at: Option<i64>,
    /// Exclusive expiry of the upstream verification.
    pub verification_expires_at: Option<i64>,
    /// TLS leaf fingerprint, when per-request attribution was possible.
    pub cert_sha256: Option<String>,
}

/// Whether attestation evidence was verified by this SDK.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReceiptAttestationStatus {
    /// Receipt-key evidence chained through the SDK's attestation verifier.
    Verified,
    /// The caller explicitly accepted signature-and-hashes-only verification.
    UnverifiedByThisSdk,
}

/// Fully verified wire-format-v1 receipt claims.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceiptClaims {
    /// Receipt format version.
    pub rv: i64,
    /// Issuer origin as carried in the verified receipt.
    pub iss: String,
    /// Unix issue time.
    pub iat: i64,
    /// Response identifier.
    pub jti: String,
    /// Optional generation identifier.
    pub gen: Option<String>,
    /// Optional echoed request nonce.
    pub nonce: Option<String>,
    /// Inference route.
    pub route: String,
    /// Request digest claims.
    pub req: ReceiptHashClaims,
    /// Response digest claims.
    pub resp: ReceiptHashClaims,
    /// Model routing claims.
    pub model: ReceiptModelClaims,
    /// Upstream verification claims.
    pub upstream: ReceiptUpstreamClaims,
    /// Compact-receipt attestation-document pin.
    pub att_sha256: Option<String>,
    /// Result of this SDK's attestation verification.
    pub attestation_status: ReceiptAttestationStatus,
}

impl ReceiptClaims {
    /// Alias for [`Self::attestation_status`].
    pub fn attestation(&self) -> ReceiptAttestationStatus {
        self.attestation_status
    }
}

#[derive(Debug)]
struct JwsEnvelope {
    protected: String,
    payload: String,
    signature: String,
    flattened: bool,
    flattened_value: Option<Value>,
}

#[derive(Debug)]
struct ParsedHeader {
    value: Map<String, Value>,
    public_key: [u8; 32],
}

#[derive(Debug)]
struct SseEvent<'a> {
    name: &'a [u8],
    payload: &'a [u8],
    done: bool,
}

/// Verifies a compact or flattened inference receipt and returns typed claims.
///
/// `expected_issuer` is required and pins the receipt to an HTTPS origin after
/// normalizing scheme and host case, a default port, and one trailing slash.
/// Request bytes and exactly one response representation are required by
/// default so the signed digests are bound to the caller's traffic. Set
/// [`ReceiptVerificationOptions::require_bindings`] to `false` explicitly to
/// permit signature-only or partial-binding inspection.
///
/// Compact receipts omit their attestation document. Supply its exact bytes in
/// [`ReceiptVerificationOptions::attestation`] to check the pinned digest and
/// receipt-key binding, or set
/// [`ReceiptVerificationOptions::require_attestation`] to `false` explicitly
/// to verify only the signature, claims, and supplied byte hashes. The
/// `/receipt-attestation` endpoint serves the per-instance document; callers
/// behind a load balancer should retry until SHA-256 matches `att_sha256`.
///
/// Flattened receipts always verify embedded evidence. If `attestation` is
/// supplied for one, it must exactly match the embedded document.
pub async fn verify_receipt(
    receipt: impl AsRef<[u8]>,
    expected_issuer: &str,
    options: ReceiptVerificationOptions<'_>,
) -> ReceiptResult<ReceiptClaims> {
    verify_receipt_with(
        receipt.as_ref(),
        expected_issuer,
        options,
        verify_gcp_attestation,
    )
    .await
}

#[allow(clippy::too_many_lines)]
async fn verify_receipt_with<F, Fut>(
    receipt: &[u8],
    expected_issuer: &str,
    options: ReceiptVerificationOptions<'_>,
    verify_gcp: F,
) -> ReceiptResult<ReceiptClaims>
where
    F: FnOnce(Vec<u8>, [u8; 32]) -> Fut,
    Fut: Future<Output = ReceiptResult<()>>,
{
    // Checks deliberately remain in the contract's fail-closed order.
    require_traffic_bindings(&options)?;
    let canonical_expected_issuer = canonical_https_origin(expected_issuer, "expected_issuer")?;
    let envelope = parse_envelope(receipt)?;
    let header = parse_header(&envelope)?;
    let payload_bytes = verify_signature(&envelope, &header.public_key)?;
    let payload = load_json(&payload_bytes, "receipt claims")?;
    let claims = payload.as_object().ok_or_else(|| {
        ReceiptVerificationError::Claims(
            "rv claim check failed: receipt claims must be a JSON object".to_owned(),
        )
    })?;

    let rv = claims.get("rv").and_then(Value::as_i64);
    if rv != Some(1) {
        return Err(ReceiptVerificationError::Claims(format!(
            "rv claim check failed: expected integer 1, got {}",
            display_value(claims.get("rv"))
        )));
    }
    let iss = required_string(claims, "iss", "claims")?;
    let canonical_issuer = canonical_https_origin(&iss, "iss claim")?;
    if !safe_equal(
        canonical_issuer.as_bytes(),
        canonical_expected_issuer.as_bytes(),
    ) {
        return Err(ReceiptIssuerError(format!(
            "iss claim check failed: expected {canonical_expected_issuer:?}, got {canonical_issuer:?}"
        ))
        .into());
    }
    let iat = integer(
        claims.get("iat"),
        "iat claim",
        ReceiptVerificationError::Time,
    )?;
    let now = match options.now {
        Some(value) => value,
        None => i64::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|error| ReceiptVerificationError::Time(error.to_string()))?
                .as_secs(),
        )
        .map_err(|_| {
            ReceiptVerificationError::Time("current Unix time does not fit in i64".to_owned())
        })?,
    };
    if iat > now.saturating_add(60) {
        return Err(ReceiptVerificationError::Time(format!(
            "iat future-skew check failed: iat={iat} is more than 60 seconds after now={now}"
        )));
    }
    if let Some(max_age) = options.max_age_seconds {
        let age = now
            .checked_sub(iat)
            .and_then(|value| u64::try_from(value).ok());
        if age.is_some_and(|value| value > max_age) {
            return Err(ReceiptVerificationError::Time(format!(
                "iat max-age check failed: receipt age {}s exceeds {max_age}s",
                age.unwrap_or_default()
            )));
        }
    }

    let jti = required_string(claims, "jti", "claims")?;
    let gen = optional_string(claims, "gen", "claims")?;
    let route = required_string(claims, "route", "claims")?;
    if !matches!(route.as_str(), "chat.completions" | "responses") {
        return Err(ReceiptVerificationError::Claims(format!(
            "route claim check failed: unsupported route {route:?}"
        )));
    }
    let model_raw = required_object(claims, "model", ReceiptVerificationError::Claims)?;
    let model = ReceiptModelClaims {
        requested: required_string(model_raw, "requested", "model")?,
        selected: required_string(model_raw, "selected", "model")?,
        provider: required_string(model_raw, "provider", "model")?,
        endpoint: required_string(model_raw, "endpoint", "model")?,
    };
    let att_sha256 = optional_string(claims, "att_sha256", "claims")?;
    if let Some(encoded) = att_sha256.as_deref() {
        let decoded = decode_b64(encoded, "att_sha256 claim")
            .map_err(|error| ReceiptVerificationError::Claims(error.to_string()))?;
        if decoded.len() != 32 {
            return Err(ReceiptVerificationError::Claims(
                "att_sha256 claim check failed: SHA-256 digest must be 32 bytes".to_owned(),
            ));
        }
    }
    if !envelope.flattened && att_sha256.is_none() {
        return Err(ReceiptVerificationError::Claims(
            "att_sha256 claim check failed: compact receipts must pin an attestation document"
                .to_owned(),
        ));
    }

    let nonce = optional_nonce(claims)?;
    if let Some(expected) = options.expected_nonce {
        if nonce
            .as_deref()
            .is_none_or(|actual| !safe_equal(actual.as_bytes(), expected.as_bytes()))
        {
            return Err(ReceiptVerificationError::Nonce(format!(
                "nonce match check failed: expected {expected:?}, got {nonce:?}"
            )));
        }
    }

    let upstream_raw = required_object(claims, "upstream", ReceiptVerificationError::Upstream)?;
    let tier = upstream_raw.get("tier").and_then(Value::as_str);
    let (verified_at, verification_expires_at) = match tier {
        Some("tee-verified") => {
            let verified_at = integer(
                upstream_raw.get("verified_at"),
                "upstream.verified_at",
                ReceiptVerificationError::Upstream,
            )?;
            let expires_at = integer(
                upstream_raw.get("verification_expires_at"),
                "upstream.verification_expires_at",
                ReceiptVerificationError::Upstream,
            )?;
            if !(verified_at <= iat && iat < expires_at) {
                return Err(ReceiptVerificationError::Upstream(
                    "tee-verified window check failed: expected verified_at <= iat < verification_expires_at"
                        .to_owned(),
                ));
            }
            (Some(verified_at), Some(expires_at))
        }
        Some("tls-webpki") => (None, None),
        _ => {
            return Err(ReceiptVerificationError::Upstream(format!(
                "upstream.tier check failed: unsupported tier {}",
                display_value(upstream_raw.get("tier"))
            )));
        }
    };
    let policy = optional_string(upstream_raw, "policy", "upstream")?;
    if tier == Some("tee-verified") && policy.is_none() {
        return Err(ReceiptVerificationError::Upstream(
            "upstream.policy check failed: tee-verified receipts require a policy".to_owned(),
        ));
    }
    let upstream = ReceiptUpstreamClaims {
        tier: tier.unwrap_or_default().to_owned(),
        policy,
        verified_at,
        verification_expires_at,
        cert_sha256: optional_string(upstream_raw, "cert_sha256", "upstream")?,
    };

    let req = digest_claim(
        required_object(claims, "req", ReceiptVerificationError::Hash)?,
        "req",
        false,
    )?;
    if let Some(body) = options.request_body {
        let actual = Sha256::digest(body);
        let expected = hash_bytes(&req.hash, "req.hash")?;
        if !safe_equal(&actual, &expected) {
            return Err(ReceiptVerificationError::Hash(
                "request body hash check failed: req.hash does not match".to_owned(),
            ));
        }
    }

    let resp = digest_claim(
        required_object(claims, "resp", ReceiptVerificationError::Hash)?,
        "resp",
        true,
    )?;
    if options.response_body.is_some() && options.response_stream.is_some() {
        return Err(ReceiptVerificationError::Hash(
            "response hash check failed: provide response_body or response_stream, not both"
                .to_owned(),
        ));
    }
    let expected_response = hash_bytes(&resp.hash, "resp.hash")?;
    if let Some(body) = options.response_body {
        if resp.of != "body" {
            return Err(ReceiptVerificationError::Hash(format!(
                "response body hash check failed: resp.of is {:?}, expected 'body'",
                resp.of
            )));
        }
        if !safe_equal(&Sha256::digest(body), &expected_response) {
            return Err(ReceiptVerificationError::Hash(
                "response body hash check failed: resp.hash does not match".to_owned(),
            ));
        }
    } else if let Some(stream) = options.response_stream {
        if !matches!(resp.of.as_str(), "sse-data-v1" | "sse-events-v1") {
            return Err(ReceiptVerificationError::Hash(format!(
                "response stream hash check failed: resp.of is {:?}, expected an SSE domain",
                resp.of
            )));
        }
        let (actual, events) = stream_digest(stream, &resp.of, envelope.flattened_value.as_ref())?;
        if !safe_equal(&actual, &expected_response) {
            return Err(ReceiptVerificationError::Hash(
                "response stream hash check failed: resp.hash does not match".to_owned(),
            ));
        }
        if resp.events.is_some_and(|expected| expected != events) {
            return Err(ReceiptVerificationError::Hash(format!(
                "response stream events check failed: counted {events}, receipt claims {}",
                resp.events.unwrap_or_default()
            )));
        }
    }

    let attestation_status = attestation_status(
        &envelope,
        &header,
        options.attestation,
        att_sha256.as_deref(),
        options.require_attestation,
        |attestation| verify_gcp(attestation, key_commitment(&header.public_key)),
    )
    .await?;

    Ok(ReceiptClaims {
        rv: rv.unwrap_or_default(),
        iss,
        iat,
        jti,
        gen,
        nonce,
        route,
        req,
        resp,
        model,
        upstream,
        att_sha256,
        attestation_status,
    })
}

fn parse_envelope(receipt: &[u8]) -> ReceiptResult<JwsEnvelope> {
    if !receipt.is_ascii() {
        return Err(ReceiptVerificationError::Structure(
            "JWS structure check failed: receipt bytes must be ASCII".to_owned(),
        ));
    }
    let text = std::str::from_utf8(receipt)
        .expect("ASCII was checked")
        .trim();
    if text.starts_with('{') {
        let value = load_json(text.as_bytes(), "JWS structure")?;
        return flattened_envelope(value);
    }
    let parts = text.split('.').collect::<Vec<_>>();
    if parts.len() != 3 || parts.iter().any(|part| part.is_empty()) {
        return Err(ReceiptVerificationError::Structure(format!(
            "JWS structure check failed: compact JWS must have 3 non-empty segments, got {}",
            parts.len()
        )));
    }
    Ok(JwsEnvelope {
        protected: parts[0].to_owned(),
        payload: parts[1].to_owned(),
        signature: parts[2].to_owned(),
        flattened: false,
        flattened_value: None,
    })
}

fn flattened_envelope(value: Value) -> ReceiptResult<JwsEnvelope> {
    let object = value.as_object().ok_or_else(|| {
        ReceiptVerificationError::Structure(
            "JWS structure check failed: flattened JWS must be a JSON object".to_owned(),
        )
    })?;
    if object.contains_key("header") {
        return Err(ReceiptVerificationError::Structure(
            "JWS structure check failed: unprotected flattened headers are not allowed".to_owned(),
        ));
    }
    let field = |name: &str| {
        object
            .get(name)
            .and_then(Value::as_str)
            .filter(|v| !v.is_empty())
    };
    let (Some(protected), Some(payload), Some(signature)) =
        (field("protected"), field("payload"), field("signature"))
    else {
        return Err(ReceiptVerificationError::Structure(
            "JWS structure check failed: flattened JWS requires non-empty string protected, payload, and signature members"
                .to_owned(),
        ));
    };
    let envelope = JwsEnvelope {
        protected: protected.to_owned(),
        payload: payload.to_owned(),
        signature: signature.to_owned(),
        flattened: true,
        flattened_value: Some(value),
    };
    Ok(envelope)
}

fn parse_header(envelope: &JwsEnvelope) -> ReceiptResult<ParsedHeader> {
    let raw = decode_b64(&envelope.protected, "protected header")?;
    let value = load_json(&raw, "protected header")?;
    let header = value.as_object().ok_or_else(|| {
        ReceiptVerificationError::Header(
            "protected header check failed: header must be a JSON object".to_owned(),
        )
    })?;
    if header.get("alg").and_then(Value::as_str) != Some("EdDSA") {
        return Err(ReceiptVerificationError::Header(format!(
            "protected header alg check failed: expected 'EdDSA', got {}",
            display_value(header.get("alg"))
        )));
    }
    if header.get("typ").and_then(Value::as_str) != Some(RECEIPT_TYPE) {
        return Err(ReceiptVerificationError::Header(format!(
            "protected header typ check failed: expected {RECEIPT_TYPE:?}, got {}",
            display_value(header.get("typ"))
        )));
    }
    let jwk = header
        .get("jwk")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            ReceiptVerificationError::Header(
                "protected header jwk check failed: jwk must be an object".to_owned(),
            )
        })?;
    if jwk.get("kty").and_then(Value::as_str) != Some("OKP")
        || jwk.get("crv").and_then(Value::as_str) != Some("Ed25519")
        || jwk.contains_key("d")
    {
        return Err(ReceiptVerificationError::Header(
            "protected header jwk check failed: expected a public OKP/Ed25519 JWK".to_owned(),
        ));
    }
    let x = jwk.get("x").and_then(Value::as_str).ok_or_else(|| {
        ReceiptVerificationError::Header(
            "protected header jwk.x check failed: x must be a string".to_owned(),
        )
    })?;
    let decoded = decode_b64(x, "protected header jwk.x")
        .map_err(|error| ReceiptVerificationError::Header(error.to_string()))?;
    let public_key: [u8; 32] = decoded.try_into().map_err(|value: Vec<u8>| {
        ReceiptVerificationError::Header(format!(
            "protected header jwk.x check failed: Ed25519 public key is {} bytes, expected 32",
            value.len()
        ))
    })?;
    let expected_kid = URL_SAFE_NO_PAD.encode(Sha256::digest(public_key));
    let kid = header.get("kid").and_then(Value::as_str);
    if kid.is_none_or(|value| !safe_equal(value.as_bytes(), expected_kid.as_bytes())) {
        return Err(ReceiptVerificationError::Header(
            "protected header kid check failed: kid does not equal b64url(sha256(jwk.x))"
                .to_owned(),
        ));
    }
    Ok(ParsedHeader {
        value: header.clone(),
        public_key,
    })
}

fn verify_signature(envelope: &JwsEnvelope, public_key: &[u8; 32]) -> ReceiptResult<Vec<u8>> {
    let payload = decode_b64(&envelope.payload, "JWS payload")?;
    let signature_bytes = decode_b64(&envelope.signature, "JWS signature")
        .map_err(|error| ReceiptVerificationError::Signature(error.to_string()))?;
    let signature = Signature::from_slice(&signature_bytes).map_err(|_| {
        ReceiptVerificationError::Signature(
            "Ed25519 signature check failed: signature must be 64 bytes".to_owned(),
        )
    })?;
    let key = VerifyingKey::from_bytes(public_key).map_err(|error| {
        ReceiptVerificationError::Signature(format!(
            "Ed25519 signature check failed: invalid public key: {error}"
        ))
    })?;
    let signing_input = format!("{}.{}", envelope.protected, envelope.payload);
    key.verify_strict(signing_input.as_bytes(), &signature)
        .map_err(|_| {
            ReceiptVerificationError::Signature("Ed25519 signature check failed".to_owned())
        })?;
    Ok(payload)
}

fn canonical_https_origin(value: &str, check: &str) -> ReceiptResult<String> {
    if value.is_empty() {
        return Err(ReceiptIssuerError(format!(
            "{check} check failed: required HTTPS origin is missing"
        ))
        .into());
    }
    let parsed = url::Url::parse(value).map_err(|_| {
        ReceiptVerificationError::from(ReceiptIssuerError(format!(
            "{check} check failed: invalid HTTPS origin"
        )))
    })?;
    if parsed.scheme() != "https" {
        return Err(ReceiptIssuerError(format!(
            "{check} check failed: issuer origin must use https"
        ))
        .into());
    }
    if parsed.host().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.path() != "/"
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return Err(ReceiptIssuerError(format!(
            "{check} check failed: expected an origin with no path, query, or fragment"
        ))
        .into());
    }

    let host = match parsed.host().expect("host presence was checked") {
        url::Host::Domain(host) => host.to_owned(),
        url::Host::Ipv4(host) => host.to_string(),
        url::Host::Ipv6(host) => format!("[{host}]"),
    };
    let canonical = parsed.port().map_or_else(
        || format!("https://{host}"),
        |port| format!("https://{host}:{port}"),
    );

    // The URL parser deliberately normalizes more than this contract allows.
    // Accept only scheme/host case folding, one trailing slash, and an
    // explicit default HTTPS port in addition to the canonical spelling.
    let normalized_input = value
        .strip_suffix('/')
        .unwrap_or(value)
        .to_ascii_lowercase();
    let canonical_input = canonical.to_ascii_lowercase();
    let explicit_default_port = format!("{canonical_input}:443");
    if normalized_input != canonical_input
        && (parsed.port().is_some() || normalized_input != explicit_default_port)
    {
        return Err(
            ReceiptIssuerError(format!("{check} check failed: invalid HTTPS origin")).into(),
        );
    }
    Ok(canonical)
}

fn require_traffic_bindings(options: &ReceiptVerificationOptions<'_>) -> ReceiptResult<()> {
    if !options.require_bindings {
        return Ok(());
    }
    let missing_request = options.request_body.is_none();
    let missing_response = options.response_body.is_none() && options.response_stream.is_none();
    if missing_request && missing_response {
        return Err(MissingBindingError(
            "receipt binding check failed: missing request_body and response_body or response_stream"
                .to_owned(),
        )
        .into());
    }
    if missing_request {
        return Err(MissingBindingError(
            "receipt binding check failed: missing request_body".to_owned(),
        )
        .into());
    }
    if missing_response {
        return Err(MissingBindingError(
            "receipt binding check failed: missing response_body or response_stream".to_owned(),
        )
        .into());
    }
    Ok(())
}

async fn attestation_status<F, Fut>(
    envelope: &JwsEnvelope,
    header: &ParsedHeader,
    supplied_attestation: Option<&[u8]>,
    att_sha256: Option<&str>,
    require_attestation: bool,
    verify_gcp: F,
) -> ReceiptResult<ReceiptAttestationStatus>
where
    F: FnOnce(Vec<u8>) -> Fut,
    Fut: Future<Output = ReceiptResult<()>>,
{
    if !envelope.flattened {
        let Some(attestation) = supplied_attestation else {
            if !require_attestation {
                return Ok(ReceiptAttestationStatus::UnverifiedByThisSdk);
            }
            return Err(MissingAttestationError(
                "attestation check failed: compact receipts omit attestation evidence; obtain the pinned document or explicitly set require_attestation to false"
                    .to_owned(),
            )
            .into());
        };
        let encoded_digest = att_sha256.ok_or_else(|| {
            ReceiptVerificationError::from(MissingAttestationError(
                "attestation check failed: compact receipt has no att_sha256 claim".to_owned(),
            ))
        })?;
        let expected_digest = decode_b64(encoded_digest, "att_sha256 claim")?;
        let actual_digest = Sha256::digest(attestation);
        if !safe_equal(&actual_digest, &expected_digest) {
            return Err(ReceiptVerificationError::Attestation(
                "att_sha256 check failed: supplied attestation does not match the compact receipt"
                    .to_owned(),
            ));
        }
        verify_gcp(attestation.to_vec()).await?;
        return Ok(ReceiptAttestationStatus::Verified);
    }
    let kind = header.value.get("att_kind");
    match kind.and_then(Value::as_str) {
        Some("aws-nitro-cose" | "azure-maa-jwt") => {
            return Err(UnsupportedAttestationError(format!(
                "attestation kind check failed: {} is not supported by this SDK",
                display_value(kind)
            ))
            .into());
        }
        Some("gcp-cs-jwt") => {}
        Some(_) => {
            return Err(UnsupportedAttestationError(format!(
                "attestation kind check failed: unsupported att_kind {}",
                display_value(kind)
            ))
            .into());
        }
        None => {
            return Err(MissingAttestationError(
                "attestation check failed: flattened receipt has no att_kind".to_owned(),
            )
            .into());
        }
    }
    let embedded_attestation = header
        .value
        .get("att")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            ReceiptVerificationError::from(MissingAttestationError(
                "attestation check failed: flattened receipt has no embedded att".to_owned(),
            ))
        })?;
    if supplied_attestation
        .is_some_and(|supplied| !safe_equal(supplied, embedded_attestation.as_bytes()))
    {
        return Err(ReceiptVerificationError::Attestation(
            "attestation check failed: supplied attestation does not match the flattened receipt's embedded attestation"
                .to_owned(),
        ));
    }
    verify_gcp(embedded_attestation.as_bytes().to_vec()).await?;
    Ok(ReceiptAttestationStatus::Verified)
}

async fn verify_gcp_attestation(attestation: Vec<u8>, commitment: [u8; 32]) -> ReceiptResult<()> {
    let client = reqwest::Client::builder()
        .user_agent(sdk_user_agent())
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|error| ReceiptVerificationError::Attestation(error.to_string()))?;
    let [trust_release_url, jwks_url] = receipt_verification_material_urls();
    let response = client
        .get(trust_release_url)
        .send()
        .await
        .map_err(|error| {
            ReceiptVerificationError::Attestation(format!("trust release fetch failed: {error}"))
        })?;
    if !response.status().is_success() {
        return Err(ReceiptVerificationError::Attestation(format!(
            "trust release fetch returned HTTP {}",
            response.status()
        )));
    }
    let release = response.json::<TrustRelease>().await.map_err(|error| {
        ReceiptVerificationError::Attestation(format!("invalid trust release JSON: {error}"))
    })?;
    let policy = policy_from_trust_release(&release, None)
        .map_err(|error| ReceiptVerificationError::Attestation(error.to_string()))?;
    verify_receipt_key_attestation(
        &attestation,
        AttestationVerificationOptions {
            policy,
            nonce_hex: Some(hex(&commitment)),
            tls_certificate_der: None,
            tls_exporter: None,
            jwks: None,
            jwks_url: Some(jwks_url.to_owned()),
            http_client: Some(client),
        },
    )
    .await
    .map_err(|error| {
        ReceiptVerificationError::Attestation(format!("GCP attestation check failed: {error}"))
    })?;
    Ok(())
}

fn receipt_verification_material_urls() -> [&'static str; 2] {
    [DEFAULT_TRUST_RELEASE_URL, crate::attestation::GCP_JWKS_URL]
}

fn digest_claim(
    record: &Map<String, Value>,
    name: &str,
    response: bool,
) -> ReceiptResult<ReceiptHashClaims> {
    if record.get("alg").and_then(Value::as_str) != Some("sha256") {
        return Err(ReceiptVerificationError::Hash(format!(
            "{name}.alg check failed: expected 'sha256', got {}",
            display_value(record.get("alg"))
        )));
    }
    let encoded = record.get("hash").and_then(Value::as_str).ok_or_else(|| {
        ReceiptVerificationError::Hash(format!(
            "{name}.hash check failed: required string is missing"
        ))
    })?;
    let digest = hash_bytes(encoded, &format!("{name}.hash"))?;
    if digest.len() != 32 {
        return Err(ReceiptVerificationError::Hash(format!(
            "{name}.hash check failed: SHA-256 digest must be 32 bytes"
        )));
    }
    let of = record.get("of").and_then(Value::as_str).unwrap_or_default();
    let allowed = of == "body" || (response && matches!(of, "sse-data-v1" | "sse-events-v1"));
    if !allowed {
        return Err(ReceiptVerificationError::Hash(format!(
            "{name}.of check failed: unsupported hash domain {}",
            display_value(record.get("of"))
        )));
    }
    let events = match record.get("events") {
        None | Some(Value::Null) if of == "body" => None,
        Some(value) if response && of != "body" => Some(value.as_u64().ok_or_else(|| {
            ReceiptVerificationError::Hash(format!(
                "{name}.events check failed: value must be a non-negative integer"
            ))
        })?),
        None if response && of != "body" => None,
        _ => {
            return Err(ReceiptVerificationError::Hash(format!(
                "{name}.events check failed: body receipts must omit events"
            )));
        }
    };
    Ok(ReceiptHashClaims {
        alg: "sha256".to_owned(),
        hash: encoded.to_owned(),
        of: of.to_owned(),
        events,
    })
}

fn stream_digest(
    stream: &[u8],
    domain: &str,
    expected_receipt: Option<&Value>,
) -> ReceiptResult<(Vec<u8>, u64)> {
    let mut digest = Sha256::new();
    let mut events = 0_u64;
    let mut offset = 0;
    let mut saw_done = false;
    let mut saw_receipt = false;
    while offset < stream.len() {
        let (raw, next) = next_sse_event(stream, offset).ok_or_else(|| {
            ReceiptVerificationError::Hash(
                "response stream framing check failed: stream has an incomplete SSE tail"
                    .to_owned(),
            )
        })?;
        offset = next;
        let event = decode_sse_event(raw)?;
        if saw_done {
            return Err(ReceiptVerificationError::Hash(
                "response stream receipt position check failed: data event follows [DONE]"
                    .to_owned(),
            ));
        }
        if event.done {
            saw_done = true;
            continue;
        }
        if let Some(embedded) = embedded_receipt(event.payload)? {
            if saw_receipt {
                return Err(ReceiptVerificationError::Hash(
                    "response stream receipt position check failed: multiple receipt events"
                        .to_owned(),
                ));
            }
            if expected_receipt.is_none_or(|expected| expected != &embedded) {
                return Err(ReceiptVerificationError::Hash(
                    "response stream receipt position check failed: embedded receipt does not match the verified flattened JWS"
                        .to_owned(),
                ));
            }
            saw_receipt = true;
            continue;
        }
        if saw_receipt {
            return Err(ReceiptVerificationError::Hash(
                "response stream receipt position check failed: receipt is not the last data event before [DONE]"
                    .to_owned(),
            ));
        }
        match domain {
            "sse-data-v1" => {
                if !event.name.is_empty() {
                    return Err(ReceiptVerificationError::Hash(
                        "response stream hash check failed: sse-data-v1 events must be unnamed"
                            .to_owned(),
                    ));
                }
            }
            "sse-events-v1" => {
                digest.update(event.name);
                digest.update(b"\n");
            }
            _ => {
                return Err(ReceiptVerificationError::Hash(format!(
                    "response stream hash check failed: unsupported domain {domain:?}"
                )));
            }
        }
        digest.update(event.payload);
        digest.update(b"\n");
        events += 1;
    }
    if !saw_receipt {
        return Err(ReceiptVerificationError::Hash(
            "response stream receipt position check failed: receipt event is missing".to_owned(),
        ));
    }
    if !saw_done {
        return Err(ReceiptVerificationError::Hash(
            "response stream receipt position check failed: receipt is not followed by [DONE]"
                .to_owned(),
        ));
    }
    Ok((digest.finalize().to_vec(), events))
}

fn next_sse_event(stream: &[u8], offset: usize) -> Option<(&[u8], usize)> {
    let lf = find_subslice(&stream[offset..], b"\n\n").map(|index| offset + index + 2);
    let crlf = find_subslice(&stream[offset..], b"\r\n\r\n").map(|index| offset + index + 4);
    let end = match (lf, crlf) {
        (Some(left), Some(right)) => left.min(right),
        (Some(end), None) | (None, Some(end)) => end,
        (None, None) => return None,
    };
    Some((&stream[offset..end], end))
}

fn decode_sse_event(raw: &[u8]) -> ReceiptResult<SseEvent<'_>> {
    let body = raw
        .strip_suffix(b"\r\n\r\n")
        .or_else(|| raw.strip_suffix(b"\n\n"))
        .ok_or_else(|| {
            ReceiptVerificationError::Hash(
                "response stream framing check failed: incomplete SSE event".to_owned(),
            )
        })?;
    let mut name = None;
    let mut payload = None;
    for raw_line in body.split(|byte| *byte == b'\n') {
        let line = raw_line.strip_suffix(b"\r").unwrap_or(raw_line);
        if let Some(value) = line.strip_prefix(b"data:") {
            if payload.is_some() {
                return Err(ReceiptVerificationError::Hash(
                    "response stream framing check failed: SSE event has multiple data fields"
                        .to_owned(),
                ));
            }
            payload = Some(value.strip_prefix(b" ").unwrap_or(value));
        } else if let Some(value) = line.strip_prefix(b"event:") {
            if name.is_some() {
                return Err(ReceiptVerificationError::Hash(
                    "response stream framing check failed: SSE event has multiple event fields"
                        .to_owned(),
                ));
            }
            name = Some(value.strip_prefix(b" ").unwrap_or(value));
        } else {
            return Err(ReceiptVerificationError::Hash(
                "response stream framing check failed: SSE event contains an unsupported field"
                    .to_owned(),
            ));
        }
    }
    let payload = payload.ok_or_else(|| {
        ReceiptVerificationError::Hash(
            "response stream framing check failed: SSE event has no data field".to_owned(),
        )
    })?;
    Ok(SseEvent {
        name: name.unwrap_or_default(),
        payload,
        done: payload == b"[DONE]",
    })
}

fn embedded_receipt(payload: &[u8]) -> ReceiptResult<Option<Value>> {
    let Ok(value) = load_json(payload, "response stream event JSON") else {
        return Ok(None);
    };
    let Some(object) = value.as_object() else {
        return Ok(None);
    };
    let Some(receipt) = object.get("inference_receipt") else {
        return Ok(None);
    };
    if !receipt.is_object() {
        return Err(ReceiptVerificationError::Hash(
            "response stream receipt position check failed: inference_receipt must be a flattened JWS object"
                .to_owned(),
        ));
    }
    Ok(Some(receipt.clone()))
}

/// Wraps a raw byte stream, preserving every chunk and discovering its receipt.
#[derive(Debug)]
pub struct ReceiptCapture<S> {
    source: Pin<Box<S>>,
    wire: Vec<u8>,
    receipt: Option<Value>,
}

impl<S> ReceiptCapture<S> {
    /// Creates an exact-wire receipt capture around a byte stream.
    pub fn new(source: S) -> Self {
        Self {
            source: Box::pin(source),
            wire: Vec::new(),
            receipt: None,
        }
    }

    /// Returns the flattened receipt once a complete receipt event was captured.
    pub fn receipt(&self) -> Option<&Value> {
        self.receipt.as_ref()
    }

    /// Returns all captured wire bytes without normalization.
    pub fn captured_bytes(&self) -> &[u8] {
        &self.wire
    }

    /// Verifies the discovered receipt against the exact captured stream.
    pub async fn verify<'a>(
        &'a self,
        expected_issuer: &str,
        options: ReceiptVerificationOptions<'a>,
    ) -> ReceiptResult<ReceiptClaims> {
        self.verify_with(expected_issuer, options, verify_gcp_attestation)
            .await
    }

    async fn verify_with<'a, F, Fut>(
        &'a self,
        expected_issuer: &str,
        mut options: ReceiptVerificationOptions<'a>,
        verify_gcp: F,
    ) -> ReceiptResult<ReceiptClaims>
    where
        F: FnOnce(Vec<u8>, [u8; 32]) -> Fut,
        Fut: Future<Output = ReceiptResult<()>>,
    {
        let receipt = self.receipt.as_ref().ok_or_else(|| {
            ReceiptVerificationError::Structure(
                "receipt capture check failed: no flattened receipt event has been captured"
                    .to_owned(),
            )
        })?;
        if options.response_stream.is_some() {
            return Err(ReceiptVerificationError::Structure(
                "ReceiptCapture::verify supplies response_stream from captured bytes".to_owned(),
            ));
        }
        options.response_stream = Some(&self.wire);
        let encoded = serde_json::to_vec(receipt).map_err(|error| {
            ReceiptVerificationError::Structure(format!(
                "receipt capture serialization failed: {error}"
            ))
        })?;
        verify_receipt_with(&encoded, expected_issuer, options, verify_gcp).await
    }

    fn refresh_receipt(&mut self) {
        let mut offset = 0;
        while offset < self.wire.len() {
            let Some((raw, next)) = next_sse_event(&self.wire, offset) else {
                return;
            };
            offset = next;
            if let Ok(event) = decode_sse_event(raw) {
                if let Ok(Some(receipt)) = embedded_receipt(event.payload) {
                    self.receipt = Some(receipt);
                }
            }
        }
    }
}

impl<S, E> Stream for ReceiptCapture<S>
where
    S: Stream<Item = std::result::Result<Bytes, E>>,
{
    type Item = std::result::Result<Bytes, E>;

    fn poll_next(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match self.source.as_mut().poll_next(context) {
            Poll::Ready(Some(Ok(chunk))) => {
                self.wire.extend_from_slice(&chunk);
                self.refresh_receipt();
                Poll::Ready(Some(Ok(chunk)))
            }
            Poll::Ready(Some(Err(error))) => Poll::Ready(Some(Err(error))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}

fn load_json(data: &[u8], check: &str) -> ReceiptResult<Value> {
    let mut deserializer = serde_json::Deserializer::from_slice(data);
    let value = StrictValue::deserialize(&mut deserializer)
        .map(|value| value.0)
        .map_err(|error| {
            ReceiptVerificationError::Structure(format!(
                "{check} check failed: invalid JSON: {error}"
            ))
        })?;
    deserializer.end().map_err(|error| {
        ReceiptVerificationError::Structure(format!("{check} check failed: invalid JSON: {error}"))
    })?;
    Ok(value)
}

struct StrictValue(Value);

impl<'de> Deserialize<'de> for StrictValue {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(StrictValueVisitor)
    }
}

struct StrictValueVisitor;

impl<'de> Visitor<'de> for StrictValueVisitor {
    type Value = StrictValue;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("valid JSON without duplicate object members")
    }

    fn visit_bool<E>(self, value: bool) -> std::result::Result<Self::Value, E> {
        Ok(StrictValue(Value::Bool(value)))
    }

    fn visit_i64<E>(self, value: i64) -> std::result::Result<Self::Value, E> {
        Ok(StrictValue(Value::Number(Number::from(value))))
    }

    fn visit_u64<E>(self, value: u64) -> std::result::Result<Self::Value, E> {
        Ok(StrictValue(Value::Number(Number::from(value))))
    }

    fn visit_f64<E>(self, value: f64) -> std::result::Result<Self::Value, E>
    where
        E: de::Error,
    {
        Number::from_f64(value)
            .map(Value::Number)
            .map(StrictValue)
            .ok_or_else(|| E::custom("non-finite JSON number"))
    }

    fn visit_str<E>(self, value: &str) -> std::result::Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(StrictValue(Value::String(value.to_owned())))
    }

    fn visit_string<E>(self, value: String) -> std::result::Result<Self::Value, E> {
        Ok(StrictValue(Value::String(value)))
    }

    fn visit_none<E>(self) -> std::result::Result<Self::Value, E> {
        Ok(StrictValue(Value::Null))
    }

    fn visit_unit<E>(self) -> std::result::Result<Self::Value, E> {
        Ok(StrictValue(Value::Null))
    }

    fn visit_seq<A>(self, mut sequence: A) -> std::result::Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element::<StrictValue>()? {
            values.push(value.0);
        }
        Ok(StrictValue(Value::Array(values)))
    }

    fn visit_map<A>(self, mut object: A) -> std::result::Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut seen = HashSet::new();
        let mut values = Map::new();
        while let Some(key) = object.next_key::<String>()? {
            if !seen.insert(key.clone()) {
                return Err(de::Error::custom(format!("duplicate JSON member {key:?}")));
            }
            let value = object.next_value::<StrictValue>()?;
            values.insert(key, value.0);
        }
        Ok(StrictValue(Value::Object(values)))
    }
}

fn decode_b64(value: &str, check: &str) -> ReceiptResult<Vec<u8>> {
    if value.is_empty()
        || value.len() % 4 == 1
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        return Err(ReceiptVerificationError::Structure(format!(
            "{check} check failed: invalid base64url encoding"
        )));
    }
    URL_SAFE_NO_PAD.decode(value).map_err(|_| {
        ReceiptVerificationError::Structure(format!(
            "{check} check failed: invalid base64url encoding"
        ))
    })
}

fn hash_bytes(value: &str, check: &str) -> ReceiptResult<Vec<u8>> {
    decode_b64(value, check).map_err(|error| ReceiptVerificationError::Hash(error.to_string()))
}

fn required_object<'a>(
    object: &'a Map<String, Value>,
    name: &str,
    error: fn(String) -> ReceiptVerificationError,
) -> ReceiptResult<&'a Map<String, Value>> {
    object.get(name).and_then(Value::as_object).ok_or_else(|| {
        error(format!(
            "{name} claim check failed: required object is missing or invalid"
        ))
    })
}

fn required_string(object: &Map<String, Value>, name: &str, family: &str) -> ReceiptResult<String> {
    object
        .get(name)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| {
            ReceiptVerificationError::Claims(format!(
                "{family} {name} check failed: required string is missing or empty"
            ))
        })
}

fn optional_string(
    object: &Map<String, Value>,
    name: &str,
    family: &str,
) -> ReceiptResult<Option<String>> {
    match object.get(name) {
        None => Ok(None),
        Some(Value::String(value)) if !value.is_empty() => Ok(Some(value.clone())),
        _ => Err(ReceiptVerificationError::Claims(format!(
            "{family} {name} check failed: value must be a non-empty string"
        ))),
    }
}

fn optional_nonce(object: &Map<String, Value>) -> ReceiptResult<Option<String>> {
    match object.get("nonce") {
        None => Ok(None),
        Some(Value::String(value))
            if (1..=88).contains(&value.len())
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-')) =>
        {
            Ok(Some(value.clone()))
        }
        _ => Err(ReceiptVerificationError::Nonce(
            "nonce claim check failed: nonce must contain 1-88 base64url characters".to_owned(),
        )),
    }
}

fn integer(
    value: Option<&Value>,
    check: &str,
    error: fn(String) -> ReceiptVerificationError,
) -> ReceiptResult<i64> {
    value
        .and_then(Value::as_i64)
        .ok_or_else(|| error(format!("{check} check failed: expected an integer")))
}

fn display_value(value: Option<&Value>) -> String {
    value.map_or_else(|| "missing".to_owned(), Value::to_string)
}

fn safe_equal(left: &[u8], right: &[u8]) -> bool {
    left.len() == right.len() && constant_time_eq(left, right)
}

fn key_commitment(public_key: &[u8; 32]) -> [u8; 32] {
    Sha256::digest([KEY_COMMITMENT_DOMAIN, public_key].concat()).into()
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
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

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use futures_util::{stream, StreamExt};
    use serde_json::json;
    use std::fs;
    use std::path::PathBuf;
    use std::sync::{Arc, Mutex};

    const NOW: i64 = 1_756_223_999;
    const EXPECTED_ISSUER: &str = "https://api.trustedrouter.com";

    fn digest(value: &[u8]) -> String {
        URL_SAFE_NO_PAD.encode(Sha256::digest(value))
    }

    fn claims(response_of: &str, response_hash: Option<String>) -> Value {
        let mut response = json!({
            "alg": "sha256",
            "hash": response_hash.unwrap_or_else(|| digest(b"response")),
            "of": response_of,
        });
        if response_of != "body" {
            response["events"] = json!(1);
        }
        json!({
            "rv": 1,
            "iss": "https://api.trustedrouter.com",
            "iat": NOW,
            "jti": "chatcmpl-test",
            "gen": "gen-test",
            "nonce": "nonce_test",
            "route": "chat.completions",
            "req": {"alg": "sha256", "hash": digest(b"request"), "of": "body"},
            "resp": response,
            "model": {
                "requested": "requested",
                "selected": "selected",
                "provider": "provider",
                "endpoint": "endpoint",
            },
            "upstream": {
                "tier": "tee-verified",
                "policy": "chutes-tdx-nvidia-e2e-v1",
                "verified_at": NOW - 60,
                "verification_expires_at": NOW + 240,
            },
            "att_sha256": digest(b"attestation"),
        })
    }

    fn key(byte: u8) -> SigningKey {
        SigningKey::from_bytes(&[byte; 32])
    }

    fn sign(
        claims: &Value,
        flattened: bool,
        header_updates: Option<Map<String, Value>>,
        signing_key: Option<&SigningKey>,
    ) -> Vec<u8> {
        sign_payload(
            serde_json::to_vec(claims).unwrap(),
            flattened,
            header_updates,
            signing_key,
        )
    }

    fn sign_payload(
        payload_bytes: Vec<u8>,
        flattened: bool,
        header_updates: Option<Map<String, Value>>,
        signing_key: Option<&SigningKey>,
    ) -> Vec<u8> {
        let receipt_key = key(7);
        let public_key = receipt_key.verifying_key().to_bytes();
        let mut header = json!({
            "alg": "EdDSA",
            "typ": RECEIPT_TYPE,
            "kid": digest(&public_key),
            "jwk": {"kty": "OKP", "crv": "Ed25519", "x": URL_SAFE_NO_PAD.encode(public_key)},
        });
        if flattened {
            header["att"] = json!("fake.jwt.token");
            header["att_kind"] = json!("gcp-cs-jwt");
        }
        if let Some(updates) = header_updates {
            header.as_object_mut().unwrap().extend(updates);
        }
        let protected = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
        let payload = URL_SAFE_NO_PAD.encode(payload_bytes);
        let signing_input = format!("{protected}.{payload}");
        let signature = (signing_key.unwrap_or(&receipt_key))
            .sign(signing_input.as_bytes())
            .to_bytes();
        if flattened {
            serde_json::to_vec(&json!({
                "protected": protected,
                "payload": payload,
                "signature": URL_SAFE_NO_PAD.encode(signature),
            }))
            .unwrap()
        } else {
            format!(
                "{protected}.{payload}.{}",
                URL_SAFE_NO_PAD.encode(signature)
            )
            .into_bytes()
        }
    }

    fn receipt_event(receipt: &[u8]) -> Vec<u8> {
        let receipt: Value = serde_json::from_slice(receipt).unwrap();
        let payload = serde_json::to_vec(&json!({
            "id": "chatcmpl-test",
            "object": "chat.completion.chunk",
            "choices": [],
            "inference_receipt": receipt,
        }))
        .unwrap();
        [b"data: ".as_slice(), &payload, b"\n\n"].concat()
    }

    fn stream_receipt(events: u64) -> (Vec<u8>, Vec<u8>) {
        let payload = br#"{"choices":[{"delta":{"content":"hello"}}]}"#;
        let mut stream_claims = claims(
            "sse-data-v1",
            Some(digest(&[payload.as_slice(), b"\n"].concat())),
        );
        stream_claims.as_object_mut().unwrap().remove("att_sha256");
        stream_claims["resp"]["events"] = json!(events);
        let receipt = sign(&stream_claims, true, None, None);
        let wire = [
            b"data: ".as_slice(),
            payload,
            b"\n\n",
            &receipt_event(&receipt),
            b"data: [DONE]\n\n",
        ]
        .concat();
        (receipt, wire)
    }

    fn options() -> ReceiptVerificationOptions<'static> {
        ReceiptVerificationOptions {
            now: Some(NOW),
            require_attestation: false,
            require_bindings: false,
            ..ReceiptVerificationOptions::default()
        }
    }

    async fn verify_without_evidence(
        receipt: &[u8],
        options: ReceiptVerificationOptions<'_>,
    ) -> ReceiptResult<ReceiptClaims> {
        verify_without_evidence_at(receipt, EXPECTED_ISSUER, options).await
    }

    async fn verify_without_evidence_at(
        receipt: &[u8],
        expected_issuer: &str,
        options: ReceiptVerificationOptions<'_>,
    ) -> ReceiptResult<ReceiptClaims> {
        verify_receipt_with(
            receipt,
            expected_issuer,
            options,
            |_attestation, _commitment| async { Ok(()) },
        )
        .await
    }

    #[tokio::test]
    async fn frozen_parity_fixtures_verify_unmodified() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/receipts");
        for name in ["compact-body", "chat-stream", "responses-stream"] {
            let directory = root.join(name);
            let receipt = fs::read(directory.join("receipt.jws")).unwrap();
            let request = fs::read(directory.join("request.body")).unwrap();
            let metadata: Value =
                serde_json::from_slice(&fs::read(directory.join("metadata.json")).unwrap())
                    .unwrap();
            let response_body = fs::read(directory.join("response.body")).ok();
            let response_stream = fs::read(directory.join("response.sse")).ok();
            let fixture_options = ReceiptVerificationOptions {
                request_body: Some(&request),
                response_body: response_body.as_deref(),
                response_stream: response_stream.as_deref(),
                expected_nonce: metadata.get("expected_nonce").and_then(Value::as_str),
                now: metadata.get("now").and_then(Value::as_i64),
                require_attestation: metadata
                    .get("require_attestation")
                    .and_then(Value::as_bool)
                    .unwrap(),
                ..ReceiptVerificationOptions::default()
            };
            let verified = verify_without_evidence_at(&receipt, EXPECTED_ISSUER, fixture_options)
                .await
                .unwrap_or_else(|error| panic!("fixture {name} failed: {error}"));
            assert_eq!(verified.rv, 1);
        }
    }

    #[tokio::test]
    async fn verifies_compact_receipt_bodies_with_explicit_escape() {
        let receipt = sign(&claims("body", None), false, None, None);
        let verified = verify_without_evidence(
            &receipt,
            ReceiptVerificationOptions {
                request_body: Some(b"request"),
                response_body: Some(b"response"),
                expected_nonce: Some("nonce_test"),
                max_age_seconds: Some(10),
                ..options()
            },
        )
        .await
        .unwrap();
        assert_eq!(verified.model.provider, "provider");
        assert_eq!(
            verified.attestation_status,
            ReceiptAttestationStatus::UnverifiedByThisSdk
        );
    }

    #[tokio::test]
    async fn bindings_are_required_by_default_and_can_be_explicitly_disabled() {
        let receipt = sign(&claims("body", None), false, None, None);
        let error = verify_without_evidence(
            &receipt,
            ReceiptVerificationOptions {
                now: Some(NOW),
                require_attestation: false,
                ..ReceiptVerificationOptions::default()
            },
        )
        .await
        .unwrap_err();
        assert!(matches!(
            error,
            ReceiptVerificationError::MissingBinding(MissingBindingError(message))
                if message.contains("missing request_body and response_body or response_stream")
        ));

        let verified = verify_without_evidence(&receipt, options()).await.unwrap();
        assert_eq!(verified.iss, EXPECTED_ISSUER);
    }

    #[tokio::test]
    async fn partial_bindings_fail_closed_by_default() {
        let receipt = sign(&claims("body", None), false, None, None);
        let base = ReceiptVerificationOptions {
            now: Some(NOW),
            require_attestation: false,
            ..ReceiptVerificationOptions::default()
        };
        let error = verify_without_evidence(
            &receipt,
            ReceiptVerificationOptions {
                request_body: Some(b"request"),
                ..base.clone()
            },
        )
        .await
        .unwrap_err();
        assert!(matches!(
            error,
            ReceiptVerificationError::MissingBinding(MissingBindingError(message))
                if message.contains("missing response_body or response_stream")
        ));

        let error = verify_without_evidence(
            &receipt,
            ReceiptVerificationOptions {
                response_body: Some(b"response"),
                ..base
            },
        )
        .await
        .unwrap_err();
        assert!(matches!(
            error,
            ReceiptVerificationError::MissingBinding(MissingBindingError(message))
                if message.contains("missing request_body")
        ));
    }

    #[tokio::test]
    async fn expected_issuer_exact_match_passes_and_mismatch_is_typed() {
        let receipt = sign(&claims("body", None), false, None, None);
        let verified = verify_without_evidence(&receipt, options()).await.unwrap();
        assert_eq!(verified.iss, EXPECTED_ISSUER);

        let error = verify_without_evidence_at(&receipt, "https://other.example", options())
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            ReceiptVerificationError::Issuer(ReceiptIssuerError(message))
                if message.contains("iss claim check failed: expected")
        ));
    }

    #[tokio::test]
    async fn issuer_origin_normalization_accepts_case_slash_and_default_port() {
        for (receipt_issuer, expected_issuer) in [
            (
                "https://API.TrustedRouter.COM/",
                "HTTPS://api.trustedrouter.com",
            ),
            (
                "https://API.TrustedRouter.COM:443/",
                "https://api.trustedrouter.com",
            ),
            (
                "https://API.TrustedRouter.COM:8443/",
                "https://api.trustedrouter.com:8443",
            ),
        ] {
            let mut receipt_claims = claims("body", None);
            receipt_claims["iss"] = json!(receipt_issuer);
            let receipt = sign(&receipt_claims, false, None, None);
            let verified = verify_without_evidence_at(&receipt, expected_issuer, options())
                .await
                .unwrap();
            assert_eq!(verified.iss, receipt_issuer);
        }
    }

    #[tokio::test]
    async fn issuer_port_must_match_exactly_after_normalization() {
        let mut receipt_claims = claims("body", None);
        receipt_claims["iss"] = json!("https://api.trustedrouter.com:8443");
        let receipt = sign(&receipt_claims, false, None, None);
        assert!(matches!(
            verify_without_evidence(&receipt, options()).await,
            Err(ReceiptVerificationError::Issuer(ReceiptIssuerError(message)))
                if message.contains("iss claim check failed: expected")
        ));
    }

    #[tokio::test]
    async fn http_receipt_issuer_is_rejected() {
        let mut receipt_claims = claims("body", None);
        receipt_claims["iss"] = json!("http://api.trustedrouter.com");
        let receipt = sign(&receipt_claims, false, None, None);
        assert!(matches!(
            verify_without_evidence(&receipt, options()).await,
            Err(ReceiptVerificationError::Issuer(ReceiptIssuerError(message)))
                if message.contains("must use https")
        ));

        let receipt = sign(&claims("body", None), false, None, None);
        assert!(matches!(
            verify_without_evidence_at(
                &receipt,
                "http://api.trustedrouter.com",
                options()
            )
            .await,
            Err(ReceiptVerificationError::Issuer(ReceiptIssuerError(message)))
                if message.contains("must use https")
        ));
    }

    #[tokio::test]
    async fn receipt_issuer_is_never_used_to_fetch_verification_material() {
        let hostile_issuer = "https://evil.example";
        let mut receipt_claims = claims("body", None);
        receipt_claims["iss"] = json!(hostile_issuer);
        receipt_claims.as_object_mut().unwrap().remove("att_sha256");
        let receipt = sign(&receipt_claims, true, None, None);
        let requested_urls = Arc::new(Mutex::new(Vec::new()));
        let recorded_requests = Arc::clone(&requested_urls);
        let verified = verify_receipt_with(
            &receipt,
            hostile_issuer,
            options(),
            move |attestation, commitment| async move {
                assert_eq!(attestation, b"fake.jwt.token");
                assert_eq!(
                    commitment,
                    key_commitment(&key(7).verifying_key().to_bytes())
                );
                for url in receipt_verification_material_urls() {
                    // This recorder stands in at the HTTP GET boundary used by
                    // the production verifier and observes every selected URL.
                    recorded_requests.lock().unwrap().push(url.to_owned());
                }
                Ok(())
            },
        )
        .await
        .unwrap();

        assert_eq!(verified.iss, hostile_issuer);
        let requests = requested_urls.lock().unwrap();
        let expected_urls = receipt_verification_material_urls();
        assert_eq!(requests.as_slice(), expected_urls);
        assert!(requests
            .iter()
            .all(|url| url::Url::parse(url).unwrap().host_str() != Some("evil.example")));
    }

    #[tokio::test]
    async fn tampered_payload_wrong_key_and_stale_claim_fail_signature() {
        let receipt = sign(&claims("body", None), false, None, None);
        let text = std::str::from_utf8(&receipt).unwrap();
        let parts = text.split('.').collect::<Vec<_>>();
        let mut payload = URL_SAFE_NO_PAD.decode(parts[1]).unwrap();
        let index = payload.len() - 2;
        payload[index] ^= 1;
        let flipped = format!(
            "{}.{}.{}",
            parts[0],
            URL_SAFE_NO_PAD.encode(payload),
            parts[2]
        );
        assert!(matches!(
            verify_without_evidence(flipped.as_bytes(), options()).await,
            Err(ReceiptVerificationError::Signature(_))
        ));

        let wrong_key_receipt = sign(&claims("body", None), false, None, Some(&key(8)));
        assert!(matches!(
            verify_without_evidence(&wrong_key_receipt, options()).await,
            Err(ReceiptVerificationError::Signature(_))
        ));

        let mut edited: Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1]).unwrap()).unwrap();
        edited["model"]["selected"] = json!("tampered");
        let stale = format!(
            "{}.{}.{}",
            parts[0],
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&edited).unwrap()),
            parts[2]
        );
        assert!(matches!(
            verify_without_evidence(stale.as_bytes(), options()).await,
            Err(ReceiptVerificationError::Signature(_))
        ));
    }

    #[tokio::test]
    async fn wrong_kid_fails_before_signature() {
        let mut updates = Map::new();
        updates.insert("kid".to_owned(), json!(digest(b"wrong")));
        let receipt = sign(&claims("body", None), false, Some(updates), None);
        assert!(matches!(
            verify_without_evidence(&receipt, options()).await,
            Err(ReceiptVerificationError::Header(message)) if message.contains("kid")
        ));
    }

    #[tokio::test]
    async fn stream_byte_flip_receipt_position_and_event_count_fail() {
        let (receipt, stream) = stream_receipt(1);
        let flipped = String::from_utf8(stream.clone())
            .unwrap()
            .replace("hello", "jello")
            .into_bytes();
        assert!(matches!(
            verify_without_evidence(
                &receipt,
                ReceiptVerificationOptions {
                    response_stream: Some(&flipped),
                    ..options()
                }
            )
            .await,
            Err(ReceiptVerificationError::Hash(message)) if message.contains("stream hash")
        ));

        let not_last = String::from_utf8(stream.clone())
            .unwrap()
            .replace("data: [DONE]", "data: {\"choices\":[]}\n\ndata: [DONE]")
            .into_bytes();
        assert!(matches!(
            verify_without_evidence(
                &receipt,
                ReceiptVerificationOptions {
                    response_stream: Some(&not_last),
                    ..options()
                }
            )
            .await,
            Err(ReceiptVerificationError::Hash(message)) if message.contains("not the last")
        ));

        let (wrong_count_receipt, wrong_count_stream) = stream_receipt(2);
        assert!(matches!(
            verify_without_evidence(
                &wrong_count_receipt,
                ReceiptVerificationOptions {
                    response_stream: Some(&wrong_count_stream),
                    ..options()
                }
            )
            .await,
            Err(ReceiptVerificationError::Hash(message)) if message.contains("events check")
        ));
    }

    #[tokio::test]
    async fn future_expired_window_and_nonce_mismatch_have_typed_errors() {
        let mut future = claims("body", None);
        future["iat"] = json!(NOW + 61);
        assert!(matches!(
            verify_without_evidence(&sign(&future, false, None, None), options()).await,
            Err(ReceiptVerificationError::Time(_))
        ));

        let mut expired = claims("body", None);
        expired["upstream"]["verification_expires_at"] = json!(NOW);
        assert!(matches!(
            verify_without_evidence(&sign(&expired, false, None, None), options()).await,
            Err(ReceiptVerificationError::Upstream(_))
        ));

        assert!(matches!(
            verify_without_evidence(
                &sign(&claims("body", None), false, None, None),
                ReceiptVerificationOptions {
                    expected_nonce: Some("different"),
                    ..options()
                }
            )
            .await,
            Err(ReceiptVerificationError::Nonce(_))
        ));
    }

    #[tokio::test]
    async fn unsupported_and_missing_attestation_fail_closed() {
        for kind in ["aws-nitro-cose", "azure-maa-jwt"] {
            let mut receipt_claims = claims("body", None);
            receipt_claims.as_object_mut().unwrap().remove("att_sha256");
            let mut updates = Map::new();
            updates.insert("att_kind".to_owned(), json!(kind));
            let receipt = sign(&receipt_claims, true, Some(updates), None);
            assert!(matches!(
                verify_without_evidence(&receipt, options()).await,
                Err(ReceiptVerificationError::UnsupportedAttestation(_))
            ));
        }

        let compact = sign(&claims("body", None), false, None, None);
        assert!(matches!(
            verify_without_evidence(
                &compact,
                ReceiptVerificationOptions {
                    now: Some(NOW),
                    require_bindings: false,
                    ..ReceiptVerificationOptions::default()
                }
            )
            .await,
            Err(ReceiptVerificationError::MissingAttestation(_))
        ));

        let mut flattened_claims = claims("body", None);
        flattened_claims
            .as_object_mut()
            .unwrap()
            .remove("att_sha256");
        let mut updates = Map::new();
        updates.insert("att".to_owned(), Value::Null);
        updates.insert("att_kind".to_owned(), Value::Null);
        let flattened = sign(&flattened_claims, true, Some(updates), None);
        assert!(matches!(
            verify_without_evidence(&flattened, options()).await,
            Err(ReceiptVerificationError::MissingAttestation(_))
        ));
    }

    #[tokio::test]
    async fn compact_receipt_verifies_a_supplied_pinned_attestation() {
        let document = b"fake.jwt.token";
        let mut receipt_claims = claims("body", None);
        receipt_claims["att_sha256"] = json!(digest(document));
        let receipt = sign(&receipt_claims, false, None, None);

        let verified = verify_receipt_with(
            &receipt,
            EXPECTED_ISSUER,
            ReceiptVerificationOptions {
                now: Some(NOW),
                attestation: Some(document),
                require_bindings: false,
                ..ReceiptVerificationOptions::default()
            },
            |attestation, commitment| async move {
                assert_eq!(attestation, document);
                assert_eq!(
                    commitment,
                    key_commitment(&key(7).verifying_key().to_bytes())
                );
                Ok(())
            },
        )
        .await
        .unwrap();
        assert_eq!(
            verified.attestation_status,
            ReceiptAttestationStatus::Verified
        );

        let mut changed = document.to_vec();
        *changed.last_mut().unwrap() ^= 1;
        let error = verify_without_evidence(
            &receipt,
            ReceiptVerificationOptions {
                now: Some(NOW),
                attestation: Some(&changed),
                require_bindings: false,
                ..ReceiptVerificationOptions::default()
            },
        )
        .await
        .unwrap_err();
        assert!(matches!(
            error,
            ReceiptVerificationError::Attestation(message)
                if message.contains("att_sha256 check failed")
        ));
    }

    #[tokio::test]
    async fn flattened_receipt_rejects_a_mismatched_supplied_attestation() {
        let mut receipt_claims = claims("body", None);
        receipt_claims.as_object_mut().unwrap().remove("att_sha256");
        let receipt = sign(&receipt_claims, true, None, None);
        let error = verify_without_evidence(
            &receipt,
            ReceiptVerificationOptions {
                now: Some(NOW),
                attestation: Some(b"different.jwt.token"),
                require_attestation: false,
                require_bindings: false,
                ..ReceiptVerificationOptions::default()
            },
        )
        .await
        .unwrap_err();
        assert!(matches!(
            error,
            ReceiptVerificationError::Attestation(message)
                if message.contains("does not match") && message.contains("embedded")
        ));
    }

    #[tokio::test]
    async fn duplicate_json_members_are_rejected_at_nested_depth() {
        let payload = format!(
            concat!(
                "{{\"rv\":1,\"iss\":\"https://api.trustedrouter.com\",",
                "\"iat\":{},\"jti\":\"id\",\"route\":\"chat.completions\",",
                "\"req\":{{\"alg\":\"sha256\",\"hash\":\"{}\",\"of\":\"body\"}},",
                "\"resp\":{{\"alg\":\"sha256\",\"hash\":\"{}\",\"of\":\"body\"}},",
                "\"model\":{{\"requested\":\"r\",\"selected\":\"s\",",
                "\"provider\":\"p\",\"provider\":\"duplicate\",\"endpoint\":\"e\"}},",
                "\"upstream\":{{\"tier\":\"tls-webpki\"}},\"att_sha256\":\"{}\"}}"
            ),
            NOW,
            digest(b"request"),
            digest(b"response"),
            digest(b"attestation"),
        );
        let receipt = sign_payload(payload.into_bytes(), false, None, None);
        assert!(matches!(
            verify_without_evidence(&receipt, options()).await,
            Err(ReceiptVerificationError::Structure(message)) if message.contains("duplicate JSON member")
        ));
    }

    #[tokio::test]
    async fn multiline_data_and_unknown_sse_fields_fail() {
        let (receipt, stream) = stream_receipt(1);
        let text = String::from_utf8(stream).unwrap();
        for tampered in [
            text.replace("data: {\"choices\"", "data: first\ndata: {\"choices\""),
            text.replace("data: {\"choices\"", "id: 1\ndata: {\"choices\""),
        ] {
            assert!(matches!(
                verify_without_evidence(
                    &receipt,
                    ReceiptVerificationOptions {
                        response_stream: Some(tampered.as_bytes()),
                        ..options()
                    }
                )
                .await,
                Err(ReceiptVerificationError::Hash(_))
            ));
        }
    }

    #[tokio::test]
    async fn capture_preserves_split_chunks_discovers_and_verifies() {
        let (receipt, wire) = stream_receipt(1);
        let chunks = vec![
            Ok::<_, ()>(Bytes::copy_from_slice(&wire[..17])),
            Ok(Bytes::copy_from_slice(&wire[17..83])),
            Ok(Bytes::copy_from_slice(&wire[83..])),
        ];
        let mut capture = ReceiptCapture::new(stream::iter(chunks));
        let mut consumed = Vec::new();
        while let Some(chunk) = capture.next().await {
            consumed.extend_from_slice(&chunk.unwrap());
        }
        assert_eq!(consumed, wire);
        assert_eq!(capture.captured_bytes(), wire);
        assert_eq!(
            capture.receipt(),
            Some(&serde_json::from_slice::<Value>(&receipt).unwrap())
        );
        let verified = capture
            .verify_with(
                EXPECTED_ISSUER,
                options(),
                |_attestation, _commitment| async { Ok(()) },
            )
            .await
            .unwrap();
        assert_eq!(verified.jti, "chatcmpl-test");
    }

    #[tokio::test]
    async fn gcp_verifier_receives_domain_separated_key_commitment_input() {
        let mut receipt_claims = claims("body", None);
        receipt_claims.as_object_mut().unwrap().remove("att_sha256");
        let receipt = sign(&receipt_claims, true, None, None);
        let expected_commitment = key_commitment(&key(7).verifying_key().to_bytes());
        let verified = verify_receipt_with(
            &receipt,
            EXPECTED_ISSUER,
            options(),
            move |attestation, commitment| async move {
                assert_eq!(attestation, b"fake.jwt.token");
                assert_eq!(commitment, expected_commitment);
                Ok(())
            },
        )
        .await
        .unwrap();
        assert_eq!(
            verified.attestation_status,
            ReceiptAttestationStatus::Verified
        );
    }
}
