use github_rs::GithubClient;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[tokio::test]
async fn dependabot_alerts_parses_advisory_and_package() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/orgs/acme/dependabot/alerts"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
            {
                "number": 2,
                "state": "open",
                "dependency": {
                    "package": {"ecosystem": "pip", "name": "django"},
                    "manifest_path": "requirements.txt"
                },
                "security_advisory": {
                    "ghsa_id": "GHSA-xxxx",
                    "cve_id": "CVE-2018-6188",
                    "severity": "low",
                    "summary": "Denial of service"
                },
                "created_at": "2022-06-15T07:43:03Z",
                "updated_at": "2022-08-23T14:29:47Z",
                "repository": {"full_name": "acme/widget"}
            }
        ])))
        .mount(&server)
        .await;

    let client = GithubClient::new(&server.uri(), "tok", "acme").unwrap();
    let alerts = client.alerts().dependabot_alerts().await.unwrap();
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].dependency.package.name, "django");
    assert_eq!(
        alerts[0].security_advisory.as_ref().unwrap().ghsa_id,
        "GHSA-xxxx"
    );
}

#[tokio::test]
async fn secret_scanning_alerts_parses_fields() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/orgs/acme/secret-scanning/alerts"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
            {
                "number": 5,
                "created_at": "2020-11-06T18:48:51Z",
                "state": "resolved",
                "resolution": "false_positive",
                "secret_type": "adafruit_io_key",
                "secret_type_display_name": "Adafruit IO Key",
                "push_protection_bypassed": false,
                "repository": {"full_name": "acme/widget"}
            }
        ])))
        .mount(&server)
        .await;

    let client = GithubClient::new(&server.uri(), "tok", "acme").unwrap();
    let alerts = client.alerts().secret_scanning_alerts().await.unwrap();
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].secret_type, "adafruit_io_key");
}

#[tokio::test]
async fn code_scanning_alerts_parses_rule() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/orgs/acme/code-scanning/alerts"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
            {
                "number": 4,
                "created_at": "2020-02-13T12:29:18Z",
                "state": "open",
                "rule": {
                    "id": "js/trivial-conditional",
                    "severity": "warning",
                    "security_severity_level": "high",
                    "description": "Useless conditional"
                },
                "repository": {"full_name": "acme/widget"}
            }
        ])))
        .mount(&server)
        .await;

    let client = GithubClient::new(&server.uri(), "tok", "acme").unwrap();
    let alerts = client.alerts().code_scanning_alerts().await.unwrap();
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].rule.id, "js/trivial-conditional");
}
