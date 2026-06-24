use okta_rs::OktaClient;
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[tokio::test]
async fn injects_ssws_auth_header() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/users"))
        .and(header("Authorization", "SSWS test-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([])))
        .expect(1)
        .mount(&server)
        .await;

    let client = OktaClient::new(&server.uri(), "test-token").unwrap();
    let resp = client.raw_get("/api/v1/users").await.unwrap();
    assert_eq!(resp.status(), 200);
}

#[tokio::test]
async fn follows_link_header_pagination_next_rel() {
    use okta_rs::OktaClient;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, ResponseTemplate};

    let server = MockServer::start().await;
    let next_url = format!("{}/api/v1/users?after=cursor2", server.uri());
    Mock::given(method("GET"))
        .and(path("/api/v1/users"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("link", format!("<{}>; rel=\"next\"", next_url).as_str())
                .set_body_json(serde_json::json!([])),
        )
        .mount(&server)
        .await;

    let client = OktaClient::new(&server.uri(), "test-token").unwrap();
    let resp = client.raw_get("/api/v1/users").await.unwrap();
    let link = okta_rs::__test_next_link(&resp);
    assert_eq!(link, Some(next_url));
}

#[tokio::test]
async fn link_parser_preserves_commas_inside_urls() {
    use okta_rs::OktaClient;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, ResponseTemplate};

    let server = MockServer::start().await;
    let next_url = format!(
        "{}/api/v1/logs?filter=eventType+in+%5Ba%2Cb%5D&after=p2",
        server.uri()
    );
    let self_url = format!(
        "{}/api/v1/logs?filter=eventType+in+%5Ba%2Cb%5D",
        server.uri()
    );
    let link_header = format!("<{}>; rel=\"self\", <{}>; rel=\"next\"", self_url, next_url);

    Mock::given(method("GET"))
        .and(path("/api/v1/logs"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("link", link_header.as_str())
                .set_body_json(serde_json::json!([])),
        )
        .mount(&server)
        .await;

    let client = OktaClient::new(&server.uri(), "test-token").unwrap();
    let resp = client.raw_get("/api/v1/logs").await.unwrap();
    let link = okta_rs::__test_next_link(&resp);
    assert_eq!(link, Some(next_url));
}
