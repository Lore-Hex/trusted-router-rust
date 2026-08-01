//! Official Rust SDK for [TrustedRouter](https://trustedrouter.com).
//!
//! The crate keeps inference traffic on the attested API plane and account or
//! catalog traffic on the control plane. The async [`Client`] is the primary
//! API. Enable the default `blocking` feature for [`BlockingClient`].

mod attestation;
mod blocking;
mod client;
mod constants;
mod error;
mod oauth;
mod sse;
mod tools;
mod transport;
mod types;

pub use attestation::{
    policy_from_trust_release, verify_gateway_attestation, AttestationPolicy,
    AttestationVerificationOptions, GatewayAttestation, TrustRelease, TrustReleaseDataPolicy,
    TrustReleaseTls, EXPORTER_LABEL, EXPORTER_LENGTH, GCP_ISSUER, GCP_JWKS_URL,
};
#[cfg(feature = "blocking")]
pub use blocking::BlockingClient;
pub use client::{CallOptions, Client, ClientBuilder, Plane};
pub use constants::*;
pub use error::{ApiError, Error, ErrorKind, Result};
pub use oauth::{
    create_pkce_pair, random_oauth_state, OAuthAuthorization, OAuthAuthorizeOptions, OAuthCallback,
    OAuthKeyExchangeRequest, OAuthKeyExchangeResponse, OAuthLoopback, OAuthLoopbackOptions,
    OAuthPkcePair,
};
pub use sse::{JsonStream, ResponseEventStream, SseEvent, SseStream, TextStream};
pub use tools::{
    advisor_tool, map_reduce_tool, selector_tool, subagent_tool, synth_tool, AdvisorToolOptions,
    MapReduceToolOptions, SelectionStrategy, SelectorToolOptions, SubagentToolOptions,
    SynthToolOptions,
};
pub use types::*;
