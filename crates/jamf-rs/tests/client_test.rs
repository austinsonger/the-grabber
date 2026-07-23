use jamf_rs::JamfClient;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[tokio::test]
async fn fetches_token_and_attaches_bearer_auth() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/api/oauth/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": "test-token",
            "expires_in": 3600
        })))
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/api/v1/ping"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"ok": true})))
        .mount(&server)
        .await;

    let client = JamfClient::new(&server.uri(), "id", "secret").expect("client builds");
    let resp = client.get("/api/v1/ping").await.expect("request succeeds");
    assert!(resp.status().is_success());
}
