//! The domain is a single point of failure above the whole deployment.
//!
//! These prove the candidate list exists and that a custom base URL is never
//! silently redirected. Before this the transport computed one URL outside the
//! retry loop, so failover could not move even in principle.

use trusted_router::{Client, ALIAS_API_BASE_URLS, DEFAULT_API_BASE_URL};

#[test]
fn default_client_carries_more_than_one_candidate() {
    let client = Client::builder().api_key("sk-test").build().unwrap();
    let urls = client.api_base_urls();
    assert!(
        urls.len() > 1,
        "failover cannot engage with {} candidate(s): {urls:?}",
        urls.len()
    );
    assert!(urls[0].as_str().starts_with(DEFAULT_API_BASE_URL));
    for alias in ALIAS_API_BASE_URLS {
        assert!(
            urls.iter().any(|u| u.as_str().starts_with(alias)),
            "alias {alias} missing from {urls:?}"
        );
    }
}

#[test]
fn regional_failover_false_pins_the_client_to_one_host() {
    // Parity with the other five SDKs: an explicit opt-out must leave nowhere
    // to advance to, so every attempt goes to the host the caller named.
    let client = Client::builder()
        .api_key("sk-test")
        .regional_failover(false)
        .build()
        .unwrap();
    let urls = client.api_base_urls();
    assert_eq!(
        urls.len(),
        1,
        "opted out and still has somewhere to go: {urls:?}"
    );
    assert!(urls[0].as_str().starts_with(DEFAULT_API_BASE_URL));
}

#[test]
fn regional_failover_defaults_to_on() {
    // The default must stay opt-out, not opt-in: a caller who configures
    // nothing should still survive losing the primary domain.
    let default_urls = Client::builder()
        .api_key("sk-test")
        .build()
        .unwrap()
        .api_base_urls()
        .len();
    let explicit_urls = Client::builder()
        .api_key("sk-test")
        .regional_failover(true)
        .build()
        .unwrap()
        .api_base_urls()
        .len();
    assert_eq!(default_urls, explicit_urls);
    assert!(default_urls > 1);
}

#[test]
fn a_custom_base_url_is_never_redirected_to_a_public_alias() {
    // A private deployment or test server must get exactly what it asked for.
    let client = Client::builder()
        .api_key("sk-test")
        .api_base_url("https://my.internal/v1")
        .build()
        .unwrap();
    let urls = client.api_base_urls();
    assert_eq!(urls.len(), 1, "custom base was rewritten: {urls:?}");
    assert!(urls[0].as_str().starts_with("https://my.internal/v1"));
}
