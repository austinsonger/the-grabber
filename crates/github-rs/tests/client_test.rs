use github_rs::GithubClient;
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[tokio::test]
async fn injects_bearer_auth_and_api_version_headers() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/orgs/acme/members"))
        .and(header("Authorization", "Bearer test-token"))
        .and(header("X-GitHub-Api-Version", "2022-11-28"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([])))
        .expect(1)
        .mount(&server)
        .await;

    let client = GithubClient::new(&server.uri(), "test-token", "acme").unwrap();
    let resp = client.raw_get("/orgs/acme/members").await.unwrap();
    assert_eq!(resp.status(), 200);
}

#[tokio::test]
async fn follows_link_header_pagination_next_rel() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, ResponseTemplate};

    let server = MockServer::start().await;
    let next_url = format!("{}/orgs/acme/members?page=2", server.uri());
    Mock::given(method("GET"))
        .and(path("/orgs/acme/members"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("link", format!("<{}>; rel=\"next\"", next_url).as_str())
                .set_body_json(serde_json::json!([])),
        )
        .mount(&server)
        .await;

    let client = GithubClient::new(&server.uri(), "test-token", "acme").unwrap();
    let resp = client.raw_get("/orgs/acme/members").await.unwrap();
    let link = github_rs::__test_next_link(&resp);
    assert_eq!(link, Some(next_url));
}

#[tokio::test]
async fn retries_after_429_with_retry_after_header() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, ResponseTemplate};

    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/orgs/acme/members"))
        .respond_with(ResponseTemplate::new(429).insert_header("retry-after", "1"))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/orgs/acme/members"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([])))
        .mount(&server)
        .await;

    let client = GithubClient::new(&server.uri(), "test-token", "acme").unwrap();
    let resp = client.raw_get("/orgs/acme/members").await.unwrap();
    assert_eq!(resp.status(), 200);
}

#[tokio::test]
async fn does_not_retry_a_bare_403() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, ResponseTemplate};

    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/orgs/acme/dependabot/alerts"))
        .respond_with(ResponseTemplate::new(403).set_body_json(serde_json::json!({
            "message": "Dependabot alerts are disabled for this repository."
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = GithubClient::new(&server.uri(), "test-token", "acme").unwrap();
    let resp = client.raw_get("/orgs/acme/dependabot/alerts").await.unwrap();
    assert_eq!(resp.status(), 403);
}
