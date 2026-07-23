use github_rs::{GithubClient, GithubError};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[tokio::test]
async fn list_all_repos_parses_fields() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/orgs/acme/repos"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
            {
                "id": 1,
                "name": "widget",
                "full_name": "acme/widget",
                "private": false,
                "visibility": "public",
                "default_branch": "main",
                "archived": false,
                "created_at": "2020-01-01T00:00:00Z",
                "pushed_at": "2026-01-01T00:00:00Z"
            }
        ])))
        .mount(&server)
        .await;

    let client = GithubClient::new(&server.uri(), "tok", "acme").unwrap();
    let repos = client.repos().list_all().await.unwrap();
    assert_eq!(repos.len(), 1);
    assert_eq!(repos[0].default_branch, "main");
}

#[tokio::test]
async fn get_branch_protection_parses_review_settings() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/repos/acme/widget/branches/main/protection"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "enforce_admins": {"enabled": true},
            "required_pull_request_reviews": {
                "required_approving_review_count": 2,
                "require_code_owner_reviews": true,
                "dismiss_stale_reviews": true
            },
            "required_status_checks": {"strict": true, "contexts": ["ci"]},
            "allow_force_pushes": {"enabled": false}
        })))
        .mount(&server)
        .await;

    let client = GithubClient::new(&server.uri(), "tok", "acme").unwrap();
    let protection = client
        .repos()
        .get_branch_protection("widget", "main")
        .await
        .unwrap();
    assert_eq!(
        protection
            .required_pull_request_reviews
            .unwrap()
            .required_approving_review_count,
        Some(2)
    );
}

#[tokio::test]
async fn get_branch_protection_404_is_an_api_error() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/repos/acme/widget/branches/main/protection"))
        .respond_with(ResponseTemplate::new(404).set_body_json(serde_json::json!({
            "message": "Branch not protected"
        })))
        .mount(&server)
        .await;

    let client = GithubClient::new(&server.uri(), "tok", "acme").unwrap();
    let err = client
        .repos()
        .get_branch_protection("widget", "main")
        .await
        .unwrap_err();
    assert!(matches!(err, GithubError::Api { status: 404, .. }));
}
