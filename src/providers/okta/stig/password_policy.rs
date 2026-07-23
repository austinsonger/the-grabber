//! Evaluates the 10 STIG checks that live entirely under a PASSWORD policy's
//! `settings.password.*` JSON — one shared fetch of `list_by_type("PASSWORD")`
//! covers all of them:
//!
//! V-273189 (lockout after 3 attempts), V-273195..199 (min length /
//! upper/lower/number/symbol complexity), V-273200 (min age 24h), V-273201
//! (max age 60d), V-273208 (common password check), V-273209 (history 5).

use okta_rs::types::policy::OktaPolicy;
use okta_rs::OktaClient;

use super::{is_feature_unavailable, json_bool, json_i64};
use crate::stig_status::{StigCheckResult, StigStatus};

const V_IDS: &[&str] = &[
    "V-273189", "V-273195", "V-273196", "V-273197", "V-273198", "V-273199", "V-273200", "V-273201",
    "V-273208", "V-273209",
];

pub async fn evaluate(client: &OktaClient) -> Vec<StigCheckResult> {
    let policies = match client.policies().list_by_type("PASSWORD").await {
        Ok(p) => p,
        Err(e) if is_feature_unavailable(&e) => {
            return super::degrade_all(V_IDS, &e, "PASSWORD policies");
        }
        Err(e) => return super::degrade_all(V_IDS, &e, "PASSWORD policies"),
    };

    let active: Vec<&OktaPolicy> = policies.iter().filter(|p| p.status == "ACTIVE").collect();
    if active.is_empty() {
        return V_IDS
            .iter()
            .map(|v| StigCheckResult::not_reviewed(*v, "No ACTIVE PASSWORD policies found"))
            .collect();
    }

    vec![
        at_least(
            &active,
            "V-273189",
            "/password/lockout/maxAttempts",
            1,
            3,
            "lockout after N invalid attempts",
        ),
        at_least(
            &active,
            "V-273195",
            "/password/complexity/minLength",
            15,
            i64::MAX,
            "minimum password length",
        ),
        at_least(
            &active,
            "V-273196",
            "/password/complexity/minUpperCase",
            1,
            i64::MAX,
            "minimum uppercase characters",
        ),
        at_least(
            &active,
            "V-273197",
            "/password/complexity/minLowerCase",
            1,
            i64::MAX,
            "minimum lowercase characters",
        ),
        at_least(
            &active,
            "V-273198",
            "/password/complexity/minNumber",
            1,
            i64::MAX,
            "minimum numeric characters",
        ),
        at_least(
            &active,
            "V-273199",
            "/password/complexity/minSymbol",
            1,
            i64::MAX,
            "minimum symbol characters",
        ),
        at_least(
            &active,
            "V-273200",
            "/password/age/minAgeMinutes",
            1440,
            i64::MAX,
            "minimum password age (minutes)",
        ),
        at_most(
            &active,
            "V-273201",
            "/password/age/maxAgeDays",
            60,
            "maximum password age (days)",
        ),
        common_password_check(&active),
        at_least(
            &active,
            "V-273209",
            "/password/age/historyCount",
            5,
            i64::MAX,
            "password history count",
        ),
    ]
}

/// Compliant when every active policy's numeric field is within
/// `[required, ceiling]` (a stricter/larger value than `required` still
/// passes, up to `ceiling` for fields where an unbounded max wouldn't make
/// sense — most callers pass `i64::MAX`).
#[allow(clippy::too_many_arguments)]
fn at_least(
    policies: &[&OktaPolicy],
    v_id: &str,
    pointer: &str,
    required: i64,
    ceiling: i64,
    label: &str,
) -> StigCheckResult {
    let mut failing = Vec::new();
    let mut actuals = Vec::new();
    for p in policies {
        match json_i64(&p.settings, pointer) {
            Some(v) if v >= required && v <= ceiling => actuals.push(v.to_string()),
            Some(v) => {
                actuals.push(v.to_string());
                failing.push(p.id.clone());
            }
            None => failing.push(format!("{} (field missing)", p.id)),
        }
    }
    if failing.is_empty() {
        StigCheckResult::new(
            v_id,
            StigStatus::NotAFinding,
            format!(">= {required}"),
            actuals.join(", "),
            format!(
                "All {} active PASSWORD polic{} meet the {label} requirement.",
                policies.len(),
                if policies.len() == 1 { "y" } else { "ies" }
            ),
        )
    } else {
        StigCheckResult::new(
            v_id,
            StigStatus::Open,
            format!(">= {required}"),
            actuals.join(", "),
            format!(
                "Polic{} not meeting the {label} requirement: {}",
                if failing.len() == 1 { "y" } else { "ies" },
                failing.join(", ")
            ),
        )
    }
}

/// Compliant when every active policy's numeric field is nonzero and `<=
/// required`.
fn at_most(
    policies: &[&OktaPolicy],
    v_id: &str,
    pointer: &str,
    required: i64,
    label: &str,
) -> StigCheckResult {
    let mut failing = Vec::new();
    let mut actuals = Vec::new();
    for p in policies {
        match json_i64(&p.settings, pointer) {
            Some(v) if v > 0 && v <= required => actuals.push(v.to_string()),
            Some(v) => {
                actuals.push(v.to_string());
                failing.push(p.id.clone());
            }
            None => failing.push(format!("{} (field missing)", p.id)),
        }
    }
    if failing.is_empty() {
        StigCheckResult::new(
            v_id,
            StigStatus::NotAFinding,
            format!("<= {required}"),
            actuals.join(", "),
            format!(
                "All {} active PASSWORD polic{} meet the {label} requirement.",
                policies.len(),
                if policies.len() == 1 { "y" } else { "ies" }
            ),
        )
    } else {
        StigCheckResult::new(
            v_id,
            StigStatus::Open,
            format!("<= {required}"),
            actuals.join(", "),
            format!(
                "Polic{} not meeting the {label} requirement: {}",
                if failing.len() == 1 { "y" } else { "ies" },
                failing.join(", ")
            ),
        )
    }
}

fn common_password_check(policies: &[&OktaPolicy]) -> StigCheckResult {
    let mut failing = Vec::new();
    let mut actuals = Vec::new();
    for p in policies {
        match json_bool(
            &p.settings,
            "/password/complexity/dictionary/common/exclude",
        ) {
            Some(true) => actuals.push("true".to_string()),
            Some(false) => {
                actuals.push("false".to_string());
                failing.push(p.id.clone());
            }
            None => failing.push(format!("{} (field missing)", p.id)),
        }
    }
    if failing.is_empty() {
        StigCheckResult::new(
            "V-273208",
            StigStatus::NotAFinding,
            "true",
            actuals.join(", "),
            format!(
                "All {} active PASSWORD policies exclude common passwords.",
                policies.len()
            ),
        )
    } else {
        StigCheckResult::new(
            "V-273208",
            StigStatus::Open,
            "true",
            actuals.join(", "),
            format!(
                "Policies not excluding common passwords: {}",
                failing.join(", ")
            ),
        )
    }
}
