//! Evaluates the 2 STIG checks against `/api/v1/authenticators`:
//!
//! V-273204 (a Smart Card / PIV authenticator is configured and ACTIVE),
//! V-273205 (Okta Verify restricted to FIPS-compliant devices).
//!
//! Neither the smart-card authenticator's exact `key` literal nor the FIPS
//! field's exact path inside `okta_verify`'s `settings` is confirmed
//! against a live tenant — both are matched defensively and fall back to
//! `NotReviewed` with the raw JSON surfaced as evidence rather than
//! guessing a PASS/FAIL.

use okta_rs::OktaClient;

use super::json_bool;
use crate::stig_status::{StigCheckResult, StigStatus};

pub async fn evaluate(client: &OktaClient) -> Vec<StigCheckResult> {
    let authenticators = match client.authenticators().list_all().await {
        Ok(a) => a,
        Err(e) => return super::degrade_all(&["V-273204", "V-273205"], &e, "authenticators"),
    };

    vec![
        smart_card(&authenticators),
        okta_verify_fips(&authenticators),
    ]
}

fn smart_card(authenticators: &[serde_json::Value]) -> StigCheckResult {
    let candidates: Vec<&serde_json::Value> = authenticators
        .iter()
        .filter(|a| {
            let key = a
                .get("key")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_lowercase();
            let name = a
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_lowercase();
            ["smart_card", "smartcard", "piv", "cac"]
                .iter()
                .any(|needle| key.contains(needle) || name.contains(needle))
        })
        .collect();

    match candidates.iter().find(|a| a.get("status").and_then(|v| v.as_str()) == Some("ACTIVE")) {
        Some(a) => {
            let key = a.get("key").and_then(|v| v.as_str()).unwrap_or("(unknown key)");
            StigCheckResult::new(
                "V-273204",
                StigStatus::NotAFinding,
                "an ACTIVE Smart Card/PIV authenticator",
                format!("{key} = ACTIVE"),
                "A Smart Card/PIV-matching authenticator is configured and ACTIVE.",
            )
        }
        None if candidates.is_empty() => StigCheckResult::new(
            "V-273204",
            StigStatus::Open,
            "an ACTIVE Smart Card/PIV authenticator",
            "none found",
            "No authenticator matching smart_card/piv/cac was found. Verify the exact authenticator key on this tenant if this looks wrong.",
        ),
        None => StigCheckResult::new(
            "V-273204",
            StigStatus::Open,
            "an ACTIVE Smart Card/PIV authenticator",
            "found but not ACTIVE",
            "A Smart Card/PIV-matching authenticator exists but is not ACTIVE.",
        ),
    }
}

fn okta_verify_fips(authenticators: &[serde_json::Value]) -> StigCheckResult {
    let Some(okta_verify) = authenticators
        .iter()
        .find(|a| a.get("key").and_then(|v| v.as_str()) == Some("okta_verify"))
    else {
        return StigCheckResult::not_reviewed(
            "V-273205",
            "No authenticator with key \"okta_verify\" found on this tenant.",
        );
    };

    // Field path unconfirmed — try a few plausible shapes before giving up.
    for pointer in [
        "/settings/compliance/fips",
        "/settings/fipsCompliance",
        "/settings/complianceFips",
    ] {
        if let Some(fips_only) = json_bool(okta_verify, pointer) {
            return if fips_only {
                StigCheckResult::new(
                    "V-273205",
                    StigStatus::NotAFinding,
                    "FIPS-compliant devices only",
                    "true",
                    format!(
                        "okta_verify authenticator field {pointer} indicates FIPS-only enrollment."
                    ),
                )
            } else {
                StigCheckResult::new(
                    "V-273205",
                    StigStatus::Open,
                    "FIPS-compliant devices only",
                    "false",
                    format!("okta_verify authenticator field {pointer} indicates FIPS compliance is not required."),
                )
            };
        }
    }

    StigCheckResult::new(
        "V-273205",
        StigStatus::NotReviewed,
        "FIPS-compliant devices only",
        okta_verify.get("settings").cloned().unwrap_or_default().to_string(),
        "Could not locate a FIPS-compliance field in the okta_verify authenticator's settings — field path needs live-tenant verification. Raw settings captured in Actual Value for manual review.",
    )
}
