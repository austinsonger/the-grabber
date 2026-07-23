use github_rs::GithubClient;
use wiremock::matchers::{method, path, query_param};
use wiremock::{Match, Mock, MockServer, Request, ResponseTemplate};

struct MissingQueryParam(&'static str);

impl Match for MissingQueryParam {
    fn matches(&self, request: &Request) -> bool {
        !request.url.query_pairs().any(|(k, _)| k == self.0)
    }
}

#[tokio::test]
async fn list_by_role_filters_and_paginates() {
    let server = MockServer::start().await;
    let page2 = format!("{}/orgs/acme/members?role=admin&per_page=100&page=2", server.uri());

    Mock::given(method("GET"))
        .and(path("/orgs/acme/members"))
        .and(query_param("role", "admin"))
        .and(MissingQueryParam("page"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("link", format!("<{}>; rel=\"next\"", page2).as_str())
                .set_body_json(serde_json::json!([
                    {"login": "alice", "id": 1, "type": "User", "site_admin": false}
                ])),
        )
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/orgs/acme/members"))
        .and(query_param("page", "2"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
            {"login": "bob", "id": 2, "type": "User", "site_admin": true}
        ])))
        .mount(&server)
        .await;

    let client = GithubClient::new(&server.uri(), "tok", "acme").unwrap();
    let admins = client.members().list_by_role("admin").await.unwrap();
    assert_eq!(admins.len(), 2);
    assert_eq!(admins[0].login, "alice");
    assert!(admins[1].site_admin);
}

#[tokio::test]
async fn list_2fa_disabled_returns_users() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/orgs/acme/members"))
        .and(query_param("filter", "2fa_disabled"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
            {"login": "carol", "id": 3, "type": "User", "site_admin": false}
        ])))
        .mount(&server)
        .await;

    let client = GithubClient::new(&server.uri(), "tok", "acme").unwrap();
    let users = client.members().list_2fa_disabled().await.unwrap();
    assert_eq!(users.len(), 1);
    assert_eq!(users[0].login, "carol");
}
