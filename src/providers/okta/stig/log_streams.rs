//! V-273202: Okta must off-load audit records onto a central log server —
//! evaluated by checking for at least one ACTIVE Log Stream connection.

use okta_rs::OktaClient;

use crate::stig_status::{RemediationTarget, StigCheckResult, StigStatus};

const V_ID: &str = "V-273202";

pub async fn evaluate(client: &OktaClient) -> Vec<StigCheckResult> {
    let streams = match client.log_streams().list_all().await {
        Ok(s) => s,
        Err(e) => return super::degrade_all(&[V_ID], &e, "log streams"),
    };

    let active: Vec<String> = streams
        .iter()
        .filter(|s| s.get("status").and_then(|v| v.as_str()) == Some("ACTIVE"))
        .map(|s| {
            let name = s
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("(unnamed)");
            let stype = s
                .get("type")
                .and_then(|v| v.as_str())
                .unwrap_or("(unknown type)");
            format!("{name} [{stype}]")
        })
        .collect();

    let result = if active.is_empty() {
        StigCheckResult::new(
            V_ID,
            StigStatus::Open,
            "at least one ACTIVE log stream",
            format!("{} log stream(s), none ACTIVE", streams.len()),
            "No ACTIVE Log Streaming connection found. If logs are pulled by an external SIEM via the Okta System Log API instead, verify manually and mark NotAFinding.",
        )
        .with_remediation(RemediationTarget::ManualOnly)
    } else {
        StigCheckResult::new(
            V_ID,
            StigStatus::NotAFinding,
            "at least one ACTIVE log stream",
            active.join(", "),
            "At least one ACTIVE Log Streaming connection is configured.",
        )
    };
    vec![result]
}
