use github_rs::GithubClient;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[tokio::test]
async fn list_all_teams_parses_fields() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/orgs/acme/teams"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
            {
                "id": 1,
                "name": "Platform",
                "slug": "platform",
                "description": "Platform team",
                "privacy": "closed",
                "permission": "push"
            }
        ])))
        .mount(&server)
        .await;

    let client = GithubClient::new(&server.uri(), "tok", "acme").unwrap();
    let teams = client.teams().list_all().await.unwrap();
    assert_eq!(teams.len(), 1);
    assert_eq!(teams[0].slug, "platform");
}

#[tokio::test]
async fn list_members_returns_users() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/orgs/acme/teams/platform/members"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
            {"login": "alice", "id": 1, "type": "User", "site_admin": false}
        ])))
        .mount(&server)
        .await;

    let client = GithubClient::new(&server.uri(), "tok", "acme").unwrap();
    let members = client.teams().list_members("platform").await.unwrap();
    assert_eq!(members.len(), 1);
    assert_eq!(members[0].login, "alice");
}
