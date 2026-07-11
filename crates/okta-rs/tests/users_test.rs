use okta_rs::OktaClient;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[tokio::test]
async fn list_all_users_follows_pagination() {
    let server = MockServer::start().await;
    let page2_url = format!("{}/api/v1/users?after=p2", server.uri());

    Mock::given(method("GET"))
        .and(path("/api/v1/users"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("link", format!("<{}>; rel=\"next\"", page2_url).as_str())
                .set_body_json(serde_json::json!([
                    {
                        "id": "00u1",
                        "status": "ACTIVE",
                        "created": "2024-01-01T00:00:00.000Z",
                        "lastLogin": "2026-06-01T10:00:00.000Z",
                        "profile": { "login": "alice@example.com", "email": "alice@example.com" }
                    }
                ])),
        )
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/api/v1/users"))
        // wiremock matches by path + query separately; use a second mock on the after=p2 page
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
            {
                "id": "00u2",
                "status": "ACTIVE",
                "profile": { "login": "bob@example.com", "email": "bob@example.com" }
            }
        ])))
        .mount(&server)
        .await;

    let client = OktaClient::new(&server.uri(), "tok").unwrap();
    let users = client.users().list_all().await.unwrap();
    assert_eq!(users.len(), 2);
    assert_eq!(users[0].id, "00u1");
    assert_eq!(users[0].profile.login, "alice@example.com");
}
