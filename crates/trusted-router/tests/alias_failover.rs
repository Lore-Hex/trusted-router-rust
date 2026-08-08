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
