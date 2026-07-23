use github_rs::GithubClient;
use wiremock::matchers::{method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[tokio::test]
async fn events_sends_created_range_phrase_and_parses_epoch_millis() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/orgs/acme/audit-log"))
        .and(query_param(
            "phrase",
            "created:2026-01-01T00:00:00Z..2026-02-01T00:00:00Z",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
            {
                "action": "team.create",
                "actor": "alice",
                "user": "alice",
                "org": "acme",
                "created_at": 1_735_689_600_000i64,
                "_document_id": "doc-1"
            }
        ])))
        .mount(&server)
        .await;

    let client = GithubClient::new(&server.uri(), "tok", "acme").unwrap();
    let events = client
        .audit_log()
        .events("2026-01-01T00:00:00Z", "2026-02-01T00:00:00Z")
        .await
        .unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].action, "team.create");
    assert_eq!(events[0].created_at, Some(1_735_689_600_000));
}
