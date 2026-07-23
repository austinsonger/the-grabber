use github_rs::GithubClient;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[tokio::test]
async fn get_org_parses_security_settings() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/orgs/acme"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "login": "acme",
            "two_factor_requirement_enabled": true,
            "default_repository_permission": "read",
            "members_can_create_repositories": false,
            "members_can_create_private_repositories": true
        })))
        .mount(&server)
        .await;

    let client = GithubClient::new(&server.uri(), "tok", "acme").unwrap();
    let org = client.orgs().get().await.unwrap();
    assert_eq!(org.login, "acme");
    assert_eq!(org.two_factor_requirement_enabled, Some(true));
    assert_eq!(org.default_repository_permission.as_deref(), Some("read"));
}
