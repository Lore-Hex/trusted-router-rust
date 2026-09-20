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

#[tokio::test]
async fn shared_auth_wire_fixtures() {
    use serde_json::{json, Value};
    use trusted_router::{CallOptions, ErrorKind, OAuthKeyExchangeRequest};
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let fixtures: Value =
        serde_json::from_str(include_str!("fixtures/auth-wire-fixtures.json")).unwrap();
    let server = MockServer::start().await;
    let client = Client::builder()
        .control_base_url(format!("{}/v1", server.uri()))
        .max_retries(0)
        .build()
        .unwrap();
    for (endpoint, verb, route) in [
        ("exchange", "POST", "/v1/auth/keys"),
        ("userinfo", "GET", "/v1/auth/userinfo"),
    ] {
        for verdict in ["accept", "reject"] {
            for (name, payload) in fixtures[endpoint][verdict].as_object().unwrap() {
                server.reset().await;
                Mock::given(method(verb))
                    .and(path(route))
                    .respond_with(ResponseTemplate::new(200).set_body_json(payload))
                    .expect(1)
                    .mount(&server)
                    .await;
                let result = if endpoint == "exchange" {
                    client
                        .exchange_oauth_key(OAuthKeyExchangeRequest {
                            code: "producer-fixture-code".to_owned(),
                            code_verifier: None,
                            code_challenge_method: None,
                            call_options: CallOptions::default(),
                        })
                        .await
                        .map(|response| serde_json::to_value(response).unwrap())
                } else {
                    client
                        .user_info()
                        .await
                        .map(|response| serde_json::to_value(response).unwrap())
                };
                if verdict == "accept" {
                    let parsed =
                        result.unwrap_or_else(|error| panic!("{endpoint}/{name}: {error}"));
                    for field in fixtures[endpoint]["consumed_fields"].as_array().unwrap() {
                        assert_eq!(
                            parsed.get(field.as_str().unwrap()),
                            payload.get(field.as_str().unwrap()),
                            "{endpoint}/{name}"
                        );
                    }
                    // Every producer field, including unknown/nested metadata, survives.
                    for (field, value) in payload.as_object().unwrap() {
                        assert_eq!(parsed.get(field), Some(value), "{endpoint}/{name}/{field}");
                    }
                } else {
                    assert_eq!(
                        result.unwrap_err().kind(),
                        ErrorKind::Serialization,
                        "{endpoint}/{name}"
                    );
                }
            }
        }
    }
    // Future userinfo fields are unconstrained, just like exchange metadata.
    server.reset().await;
    Mock::given(method("GET"))
        .and(path("/v1/auth/userinfo"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(
                json!({"data": {"sub": null, "future": [1]}, "future": {"x": true}}),
            ),
        )
        .mount(&server)
        .await;
    let parsed = client.user_info().await.unwrap();
    assert_eq!(parsed.data["future"], json!([1]));
    assert_eq!(parsed.extra["future"], json!({"x": true}));
}
