#![allow(missing_docs)]

use trusted_router::{
    create_pkce_pair, random_oauth_state, Client, OAuthAuthorizeOptions, OAuthLoopback,
    OAuthLoopbackOptions,
};

#[test]
fn pkce_and_state_are_url_safe_and_deterministic_when_requested() {
    let pair = create_pkce_pair(Some("known-verifier"));
    assert_eq!(pair.code_verifier, "known-verifier");
    assert_eq!(pair.code_challenge_method, "S256");
    assert!(!pair.code_challenge.contains('='));
    let state = random_oauth_state();
    assert!(state.len() >= 32);
    assert!(!state.contains('='));
}

#[test]
fn authorize_url_binds_state_inside_callback() {
    let client = Client::builder().build().unwrap();
    let url = client
        .oauth_authorize_url(OAuthAuthorizeOptions {
            callback_url: "http://localhost:3000/callback".to_owned(),
            code_challenge: "challenge".to_owned(),
            code_challenge_method: None,
            key_label: Some("desktop".to_owned()),
            limit: Some("10.000001".to_owned()),
            usage_limit_type: Some("total".to_owned()),
            expires_at: None,
            spawn_agent: None,
            spawn_cloud: None,
            state: Some("csrf-state".to_owned()),
        })
        .unwrap();
    assert_eq!(url.path(), "/v1/auth");
    let params = url
        .query_pairs()
        .collect::<std::collections::BTreeMap<_, _>>();
    assert_eq!(params.get("limit").unwrap(), "10.000001");
    assert_eq!(params.get("code_challenge_method").unwrap(), "S256");
    assert!(params
        .get("callback_url")
        .unwrap()
        .contains("state=csrf-state"));
}

#[tokio::test]
async fn loopback_validates_state_and_captures_code() {
    let loopback = OAuthLoopback::bind(OAuthLoopbackOptions {
        port: 0,
        path: "/callback".to_owned(),
        expected_state: Some("expected".to_owned()),
    })
    .await
    .unwrap();
    let callback = loopback.callback_url().clone();
    let waiter = tokio::spawn(loopback.wait());
    let response = reqwest::get(format!("{callback}?code=code-123&state=expected"))
        .await
        .unwrap();
    assert!(response.status().is_success());
    let result = waiter.await.unwrap().unwrap();
    assert_eq!(result.code, "code-123");
    assert_eq!(result.state.as_deref(), Some("expected"));
}
