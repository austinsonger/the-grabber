//! V-273188: Okta must automatically disable accounts after a 35-day
//! period of inactivity — evaluated against `/api/v1/automations`.
//!
//! This is the least-certain schema of any endpoint this feature touches;
//! field paths are guessed defensively and this check falls back to
//! `NotReviewed` with the raw automation JSON attached as evidence rather
//! than fabricating a PASS/FAIL when the shape doesn't match expectations.

use okta_rs::OktaClient;

use crate::stig_status::{RemediationTarget, StigCheckResult, StigStatus};

const V_ID: &str = "V-273188";

pub async fn evaluate(client: &OktaClient) -> Vec<StigCheckResult> {
    let automations = match client.automations().list_all().await {
        Ok(a) => a,
        Err(e) => return super::degrade_all(&[V_ID], &e, "automations"),
    };

    let active: Vec<&serde_json::Value> = automations
        .iter()
        .filter(|a| a.get("status").and_then(|v| v.as_str()) == Some("ACTIVE"))
        .collect();

    if active.is_empty() {
        return vec![StigCheckResult::new(
            V_ID,
            StigStatus::Open,
            "an ACTIVE automation disabling accounts after 35 days of inactivity",
            format!("{} automation(s), none ACTIVE", automations.len()),
            "No ACTIVE Okta Automation was found.",
        )
        .with_remediation(RemediationTarget::ManualOnly)];
    }

    for a in &active {
        if let Some(days) = inactivity_days(a) {
            let name = a
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("(unnamed)");
            let result = if days >= 35 {
                StigCheckResult::new(
                    V_ID,
                    StigStatus::NotAFinding,
                    ">= 35 days",
                    format!("{name} = {days} days"),
                    "An ACTIVE automation disables accounts after >= 35 days of inactivity.",
                )
            } else {
                StigCheckResult::new(
                    V_ID,
                    StigStatus::Open,
                    ">= 35 days",
                    format!("{name} = {days} days"),
                    "An ACTIVE inactivity automation exists but its threshold is under 35 days.",
                )
                .with_remediation(RemediationTarget::ManualOnly)
            };
            return vec![result];
        }
    }

    vec![StigCheckResult::new(
        V_ID,
        StigStatus::NotReviewed,
        ">= 35 days",
        format!("{} ACTIVE automation(s), inactivity threshold not identifiable", active.len()),
        "ACTIVE automation(s) exist but the inactivity-duration field could not be located — schema needs live-tenant verification. If user sourcing is via an external directory, this control may be Not_Applicable instead.",
    )
    .with_remediation(RemediationTarget::ManualOnly)]
}

/// Try a few plausible field shapes for "N days of inactivity" on an
/// automation's condition block.
fn inactivity_days(automation: &serde_json::Value) -> Option<i64> {
    for pointer in [
        "/conditions/user/context/inactivity/number",
        "/conditions/user/inactivity/number",
        "/conditions/user/number",
    ] {
        if let Some(n) = automation.pointer(pointer).and_then(|v| v.as_i64()) {
            return Some(n);
        }
    }
    None
}
