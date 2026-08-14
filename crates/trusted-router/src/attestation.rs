//! Google Confidential Space attestation verification.

use crate::{Error, Result};
use constant_time_eq::constant_time_eq;
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

/// Issuer used by Google Confidential Space attestation JWTs.
pub const GCP_ISSUER: &str = "https://confidentialcomputing.googleapis.com";
/// Public Google JWKS for Confidential Space workload attestations.
pub const GCP_JWKS_URL: &str = "https://www.googleapis.com/service_accounts/v1/metadata/jwk/signer@confidentialspace-sign.iam.gserviceaccount.com";
/// RFC 9266 channel-binding label committed by the gateway.
pub const EXPORTER_LABEL: &str = "EXPORTER-Channel-Binding";
/// Required TLS exporter length.
pub const EXPORTER_LENGTH: usize = 32;

/// Pinned workload values that a gateway attestation must match.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationPolicy {
    /// Required JWT audience.
    pub audience: String,
    /// Optional TLS leaf certificate SHA-256 pin.
    pub expected_cert_sha256: Option<String>,
    /// Optional container digest pin.
    pub expected_image_digest: Option<String>,
    /// Published transition set accepted during staged rollouts.
    #[serde(default)]
    pub expected_image_digests: Vec<String>,
    /// Optional container reference pin.
    pub expected_image_reference: Option<String>,
    /// Published image-reference transition set accepted during staged rollouts.
    #[serde(default)]
    pub expected_image_references: Vec<String>,
    /// Development-only escape hatch. Production callers should leave this false.
    #[serde(default)]
    pub allow_debug: bool,
}

impl AttestationPolicy {
    /// Whether this policy constrains *which* workload image is acceptable.
    ///
    /// Both image checks go through [`require_one_of`], which is a no-op on an
    /// empty accepted set, so a policy pinning neither a digest nor a reference
    /// accepts any genuinely-attested Confidential Space workload — it proves
    /// "some CSP VM" rather than "the gateway build we published". Policy
    /// construction and verification both refuse that state rather than
    /// silently downgrading the guarantee.
    #[must_use]
    pub fn pins_image_identity(&self) -> bool {
        !self.expected_image_digests.is_empty()
            || self.expected_image_digest.is_some()
            || !self.expected_image_references.is_empty()
            || self.expected_image_reference.is_some()
    }
}

impl Default for AttestationPolicy {
    fn default() -> Self {
        Self {
            audience: "quill-cloud".to_owned(),
            expected_cert_sha256: None,
            expected_image_digest: None,
            expected_image_digests: Vec::new(),
            expected_image_reference: None,
            expected_image_references: Vec::new(),
            allow_debug: false,
        }
    }
}

/// TLS metadata in the signed public trust release.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TrustReleaseTls {
    /// Public TLS mode.
    #[serde(default)]
    pub mode: String,
    /// Bound public hostname.
    #[serde(default)]
    pub hostname: String,
    /// Future fields.
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

/// Prompt and control-plane commitments in the trust release.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TrustReleaseDataPolicy {
    /// Whether prompt/output storage is enabled.
    #[serde(default)]
    pub prompt_output_storage: bool,
    /// Whether the control plane receives prompts.
    #[serde(default)]
    pub control_plane_prompt_access: bool,
    /// Future fields.
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

/// Signed public release metadata used to pin the attested image.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TrustRelease {
    /// Attestation platform.
    #[serde(default)]
    pub platform: String,
    /// Source repository.
    #[serde(default)]
    pub source_repo: String,
    /// Source repository map.
    #[serde(default)]
    pub source_repositories: BTreeMap<String, String>,
    /// Source commit.
    #[serde(default)]
    pub source_commit: String,
    /// Container image reference.
    #[serde(default)]
    pub image_reference: String,
    /// Image references accepted while a staged rollout is in progress.
    #[serde(default)]
    pub accepted_image_references: Vec<String>,
    /// Container image digest.
    #[serde(default)]
    pub image_digest: String,
    /// Digests accepted while a staged rollout is in progress.
    #[serde(default)]
    pub accepted_image_digests: Vec<String>,
    /// Published issuer.
    #[serde(default)]
    pub attestation_issuer: String,
    /// Published audience.
    #[serde(default)]
    pub attestation_audience: String,
    /// Public API base URL.
    #[serde(default)]
    pub api_base_url: String,
    /// TLS metadata.
    #[serde(default)]
    pub tls: Option<TrustReleaseTls>,
    /// Data handling metadata.
    #[serde(default)]
    pub data_policy: Option<TrustReleaseDataPolicy>,
    /// Future fields.
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

/// Builds a fail-closed policy from a trust release.
pub fn policy_from_trust_release(
    release: &TrustRelease,
    cert_sha256: Option<String>,
) -> Result<AttestationPolicy> {
    let expected_image_digests = if release.accepted_image_digests.is_empty() {
        nonempty(&release.image_digest).into_iter().collect()
    } else {
        release.accepted_image_digests.clone()
    };
    let expected_image_references = if release.accepted_image_references.is_empty() {
        nonempty(&release.image_reference).into_iter().collect()
    } else {
        release.accepted_image_references.clone()
    };
    let policy = AttestationPolicy {
        audience: if release.attestation_audience.is_empty() {
            "quill-cloud".to_owned()
        } else {
            release.attestation_audience.clone()
        },
        expected_cert_sha256: cert_sha256,
        expected_image_digest: nonempty(&release.image_digest),
        expected_image_digests,
        expected_image_reference: nonempty(&release.image_reference),
        expected_image_references,
        allow_debug: false,
    };
    if !policy.pins_image_identity() {
        // A truncated body, an error page that happens to parse as JSON, or a
        // schema change all land here. Returning the policy anyway would leave
        // the caller believing it verified a specific build while both image
        // checks silently no-op, so refuse where the degraded input is visible.
        return Err(Error::Attestation(
            "trust release pins no image identity (none of image_digest, \
             accepted_image_digests, image_reference, accepted_image_references); \
             refusing to build a policy that would accept any Confidential Space workload"
                .to_owned(),
        ));
    }
    Ok(policy)
}

/// Inputs for offline or live attestation verification.
#[derive(Debug, Clone)]
pub struct AttestationVerificationOptions {
    /// Policy to enforce.
    pub policy: AttestationPolicy,
    /// Fresh caller nonce supplied to `/attestation`.
    pub nonce_hex: Option<String>,
    /// TLS leaf certificate from the same verified connection.
    pub tls_certificate_der: Option<Vec<u8>>,
    /// RFC 9266 TLS exporter from the same verified connection.
    pub tls_exporter: Option<Vec<u8>>,
    /// Pre-fetched Google JWKS for deterministic/offline verification.
    pub jwks: Option<Value>,
    /// Optional JWKS endpoint override.
    pub jwks_url: Option<String>,
    /// Optional HTTP client for JWKS retrieval.
    pub http_client: Option<reqwest::Client>,
}

/// Verified gateway attestation result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayAttestation {
    /// TLS certificate SHA-256 committed by the JWT.
    pub cert_sha256: String,
    /// Attested container digest.
    pub image_digest: String,
    /// Attested container reference.
    pub image_reference: String,
    /// Verified caller nonce.
    pub nonce: Option<String>,
    /// JWT expiration.
    pub expires_at: i64,
    /// JWT issuer.
    pub issuer: String,
    /// Required audience that matched.
    pub audience: String,
    /// Fully verified claims.
    pub raw_claims: Value,
}

/// Verifies a Google-signed Confidential Space JWT and every `TrustedRouter` pin.
#[allow(clippy::too_many_lines)]
pub async fn verify_gateway_attestation(
    document: &[u8],
    options: AttestationVerificationOptions,
) -> Result<GatewayAttestation> {
    let token = std::str::from_utf8(document)
        .map_err(|error| Error::Attestation(format!("attestation is not ASCII JWT: {error}")))?
        .trim();
    if token.split('.').count() != 3 {
        return Err(Error::Attestation("expected three JWT segments".to_owned()));
    }
    let header = decode_header(token)
        .map_err(|error| Error::Attestation(format!("invalid JWT header: {error}")))?;
    if header.alg != Algorithm::RS256 {
        return Err(Error::Attestation("expected RS256 JWT".to_owned()));
    }
    let kid = header
        .kid
        .ok_or_else(|| Error::Attestation("JWT header is missing kid".to_owned()))?;
    let jwks = match options.jwks.clone() {
        Some(value) => value,
        None => fetch_jwks(&options).await?,
    };
    let key = jwks
        .get("keys")
        .and_then(Value::as_array)
        .and_then(|keys| {
            keys.iter()
                .find(|key| key.get("kid").and_then(Value::as_str) == Some(kid.as_str()))
        })
        .ok_or_else(|| Error::Attestation("no JWK matches JWT kid".to_owned()))?;
    if key.get("kty").and_then(Value::as_str) != Some("RSA") {
        return Err(Error::Attestation("attestation JWK is not RSA".to_owned()));
    }
    let modulus = key
        .get("n")
        .and_then(Value::as_str)
        .ok_or_else(|| Error::Attestation("JWK is missing modulus".to_owned()))?;
    let exponent = key
        .get("e")
        .and_then(Value::as_str)
        .ok_or_else(|| Error::Attestation("JWK is missing exponent".to_owned()))?;
    let decoding_key = DecodingKey::from_rsa_components(modulus, exponent)
        .map_err(|error| Error::Attestation(format!("malformed RSA JWK: {error}")))?;
    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_issuer(&[GCP_ISSUER]);
    validation.set_audience(&[options.policy.audience.as_str()]);
    validation.set_required_spec_claims(&["exp", "iss", "aud"]);
    let claims = decode::<Value>(token, &decoding_key, &validation)
        .map_err(|error| Error::Attestation(format!("JWT verification failed: {error}")))?
        .claims;
    verify_claims(claims, &options)
}

async fn fetch_jwks(options: &AttestationVerificationOptions) -> Result<Value> {
    let client = options.http_client.clone().unwrap_or_default();
    let response = client
        .get(options.jwks_url.as_deref().unwrap_or(GCP_JWKS_URL))
        .send()
        .await
        .map_err(|error| Error::Attestation(format!("JWKS fetch failed: {error}")))?;
    if !response.status().is_success() {
        return Err(Error::Attestation(format!(
            "JWKS fetch returned HTTP {}",
            response.status()
        )));
    }
    response
        .json()
        .await
        .map_err(|error| Error::Attestation(format!("invalid JWKS JSON: {error}")))
}

#[allow(clippy::too_many_lines)]
fn verify_claims(
    claims: Value,
    options: &AttestationVerificationOptions,
) -> Result<GatewayAttestation> {
    let policy = &options.policy;
    if !policy.allow_debug
        && !claims
            .get("dbgstat")
            .and_then(Value::as_str)
            .is_some_and(|value| value.eq_ignore_ascii_case("disabled-since-boot"))
    {
        return Err(Error::Attestation(
            "debug state must be disabled-since-boot".to_owned(),
        ));
    }
    if claims.get("swname").and_then(Value::as_str) != Some("CONFIDENTIAL_SPACE") {
        return Err(Error::Attestation(
            "workload is not Confidential Space".to_owned(),
        ));
    }
    if claims.get("secboot").and_then(Value::as_bool) != Some(true) {
        return Err(Error::Attestation("Secure Boot is not attested".to_owned()));
    }
    let hardware = claims
        .get("hwmodel")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if !matches!(hardware, "GCP_AMD_SEV" | "GCP_AMD_SEV_ES" | "GCP_INTEL_TDX") {
        return Err(Error::Attestation(format!(
            "unsupported confidential hardware: {hardware}"
        )));
    }
    let image_digest = claims
        .pointer("/submods/container/image_digest")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let image_reference = claims
        .pointer("/submods/container/image_reference")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    if !policy.pins_image_identity() {
        // Defence in depth for hand-constructed policies: `require_one_of` is a
        // no-op on an empty accepted set, so reaching it with nothing pinned
        // would accept any attested workload.
        return Err(Error::Attestation(
            "attestation policy pins no image identity; refusing to verify against a \
             policy that cannot distinguish the gateway from any other workload"
                .to_owned(),
        ));
    }
    let accepted_image_digests = if policy.expected_image_digests.is_empty() {
        policy
            .expected_image_digest
            .iter()
            .cloned()
            .collect::<Vec<_>>()
    } else {
        policy.expected_image_digests.clone()
    };
    require_one_of("image digest", &image_digest, &accepted_image_digests)?;
    let accepted_image_references = if policy.expected_image_references.is_empty() {
        policy
            .expected_image_reference
            .iter()
            .cloned()
            .collect::<Vec<_>>()
    } else {
        policy.expected_image_references.clone()
    };
    require_one_of(
        "image reference",
        &image_reference,
        &accepted_image_references,
    )?;
    let nonces = string_list(
        claims
            .get("eat_nonce")
            .or_else(|| claims.get("nonces"))
            .unwrap_or(&Value::Null),
    );
    if let Some(nonce) = options.nonce_hex.as_ref() {
        if !nonces.iter().any(|value| safe_eq(value, nonce)) {
            return Err(Error::Attestation("nonce is not bound in JWT".to_owned()));
        }
    }
    if let Some(exporter) = options.tls_exporter.as_ref() {
        if exporter.len() != EXPORTER_LENGTH {
            return Err(Error::Attestation(format!(
                "TLS exporter must be {EXPORTER_LENGTH} bytes"
            )));
        }
        let nonce = options
            .nonce_hex
            .as_ref()
            .ok_or_else(|| Error::Attestation("fresh nonce required with exporter".to_owned()))?;
        let exporter_hex = hex(exporter);
        if safe_eq(&nonce.to_ascii_lowercase(), &exporter_hex) {
            return Err(Error::Attestation(
                "fresh nonce must differ from TLS exporter".to_owned(),
            ));
        }
        if !nonces
            .iter()
            .any(|value| safe_eq(&value.to_ascii_lowercase(), &exporter_hex))
        {
            return Err(Error::Attestation(
                "TLS exporter is not bound in JWT".to_owned(),
            ));
        }
    }
    let actual_cert = options
        .tls_certificate_der
        .as_ref()
        .map(|certificate| hex(&Sha256::digest(certificate)));
    let cert_sha256 = claims
        .get("tls_cert_sha256")
        .or_else(|| claims.get("workload_tls_cert_sha256"))
        .and_then(Value::as_str)
        .map(str::to_ascii_lowercase)
        .or_else(|| {
            actual_cert.as_ref().and_then(|actual| {
                nonces
                    .iter()
                    .any(|nonce| safe_eq(&nonce.to_ascii_lowercase(), actual))
                    .then(|| actual.clone())
            })
        })
        .ok_or_else(|| Error::Attestation("JWT does not bind a TLS certificate".to_owned()))?;
    if cert_sha256.len() != 64 || !cert_sha256.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(Error::Attestation(
            "invalid TLS certificate commitment".to_owned(),
        ));
    }
    if let Some(actual) = actual_cert.as_ref() {
        if !safe_eq(actual, &cert_sha256) {
            return Err(Error::Attestation(
                "TLS certificate does not match JWT".to_owned(),
            ));
        }
    }
    require_equal(
        "TLS certificate",
        &cert_sha256,
        policy.expected_cert_sha256.as_deref(),
    )?;
    Ok(GatewayAttestation {
        cert_sha256,
        image_digest,
        image_reference,
        nonce: options.nonce_hex.clone(),
        expires_at: claims
            .get("exp")
            .and_then(Value::as_i64)
            .unwrap_or_default(),
        issuer: claims
            .get("iss")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned(),
        audience: policy.audience.clone(),
        raw_claims: claims,
    })
}

fn string_list(value: &Value) -> Vec<String> {
    match value {
        Value::String(value) => vec![value.clone()],
        Value::Array(values) => values
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_owned)
            .collect(),
        _ => Vec::new(),
    }
}

fn require_equal(field: &str, actual: &str, expected: Option<&str>) -> Result<()> {
    if let Some(expected) = expected.filter(|value| !value.is_empty()) {
        if !safe_eq(actual, expected) {
            return Err(Error::Attestation(format!("{field} pin mismatch")));
        }
    }
    Ok(())
}

fn require_one_of(field: &str, actual: &str, expected: &[String]) -> Result<()> {
    if !expected.is_empty() && !expected.iter().any(|value| safe_eq(actual, value)) {
        return Err(Error::Attestation(format!("{field} pin mismatch")));
    }
    Ok(())
}

fn safe_eq(left: &str, right: &str) -> bool {
    left.len() == right.len() && constant_time_eq(left.as_bytes(), right.as_bytes())
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

fn nonempty(value: &str) -> Option<String> {
    (!value.is_empty()).then(|| value.to_owned())
}
