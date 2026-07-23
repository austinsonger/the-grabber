//! Evaluates the 3 STIG checks that live on the system OKTA_SIGN_ON
//! (Global Session) policy's rule-level `actions.signon.session.*` fields:
//!
//! V-273186 (global idle timeout <=15min), V-273203 (global session
//! lifetime <=18h), V-273206 (persistent session cookie disabled).
//!
//! Policy-level `settings` from `list_by_type` does not carry these fields
//! — they only exist on the policy's rules, so this evaluator additionally
//! calls the new `list_rules` endpoint.

use okta_rs::OktaClient;

use super::{is_feature_unavailable, json_bool, json_i64};
use crate::stig_status::{RemediationTarget, StigCheckResult, StigStatus};

const V_IDS: &[&str] = &["V-273186", "V-273203", "V-273206"];

pub async fn evaluate(client: &OktaClient) -> Vec<StigCheckResult> {
    let policies = match client.policies().list_by_type("OKTA_SIGN_ON").await {
        Ok(p) => p,
        Err(e) => return super::degrade_all(V_IDS, &e, "OKTA_SIGN_ON policies"),
    };

    // The default Global Session Policy is Okta-managed; identify it by
    // `system == true` rather than by display name (display names are
    // customer-editable text, not a stable identifier).
    let Some(policy) = policies.iter().find(|p| p.system == Some(true)) else {
        return V_IDS
            .iter()
            .map(|v| StigCheckResult::not_reviewed(*v, "No system OKTA_SIGN_ON policy found"))
            .collect();
    };

    let rules = match client.policies().list_rules(&policy.id).await {
        Ok(r) => r,
        Err(e) if is_feature_unavailable(&e) => {
            return super::degrade_all(V_IDS, &e, "policy rules")
        }
        Err(e) => return super::degrade_all(V_IDS, &e, "policy rules"),
    };

    let active_rules: Vec<&serde_json::Value> = rules
        .iter()
        .filter(|r| r.get("status").and_then(|s| s.as_str()) == Some("ACTIVE"))
        .collect();

    if active_rules.is_empty() {
        return V_IDS
            .iter()
            .map(|v| {
                StigCheckResult::not_reviewed(
                    *v,
                    format!("No ACTIVE rules on Global Session Policy {}", policy.id),
                )
            })
            .collect();
    }

    vec![
        idle_timeout(&policy.id, &active_rules),
        session_lifetime(&policy.id, &active_rules),
        persistent_cookie(&policy.id, &active_rules),
    ]
}

fn idle_timeout(policy_id: &str, rules: &[&serde_json::Value]) -> StigCheckResult {
    at_most_minutes(
        policy_id,
        rules,
        "V-273186",
        "/actions/signon/session/maxSessionIdleMinutes",
        15,
        "global session idle timeout",
    )
}

fn session_lifetime(policy_id: &str, rules: &[&serde_json::Value]) -> StigCheckResult {
    at_most_minutes(
        policy_id,
        rules,
        "V-273203",
        "/actions/signon/session/maxSessionLifetimeMinutes",
        18 * 60,
        "global session lifetime",
    )
}

fn rule_id_and_name(rule: &serde_json::Value) -> (Option<String>, &str) {
    let id = rule.get("id").and_then(|v| v.as_str()).map(String::from);
    let name = rule
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or("(unnamed)");
    (id, name)
}

fn rule_field_target(
    policy_id: &str,
    rule: &serde_json::Value,
    pointer: &str,
    new_value: serde_json::Value,
) -> Option<RemediationTarget> {
    let (id, name) = rule_id_and_name(rule);
    id.map(|rule_id| RemediationTarget::PolicyField {
        policy_id: policy_id.to_string(),
        policy_type: "OKTA_SIGN_ON",
        rule_id: Some(rule_id),
        fields: vec![(pointer.to_string(), new_value)],
        resource_label: name.to_string(),
    })
}

fn at_most_minutes(
    policy_id: &str,
    rules: &[&serde_json::Value],
    v_id: &str,
    pointer: &str,
    required_minutes: i64,
    label: &str,
) -> StigCheckResult {
    let mut failing = Vec::new();
    let mut actuals = Vec::new();
    let mut targets = Vec::new();
    for r in rules {
        let (_, name) = rule_id_and_name(r);
        match json_i64(r, pointer) {
            Some(v) if v > 0 && v <= required_minutes => actuals.push(format!("{name}={v}")),
            Some(v) => {
                actuals.push(format!("{name}={v}"));
                failing.push(name.to_string());
                if let Some(t) =
                    rule_field_target(policy_id, r, pointer, serde_json::json!(required_minutes))
                {
                    targets.push(t);
                }
            }
            None => failing.push(format!("{name} (field missing)")),
        }
    }
    if failing.is_empty() {
        StigCheckResult::new(
            v_id,
            StigStatus::NotAFinding,
            format!("<= {required_minutes} minutes"),
            actuals.join(", "),
            format!("Every enabled rule meets the {label} requirement."),
        )
    } else {
        let mut result = StigCheckResult::new(
            v_id,
            StigStatus::Open,
            format!("<= {required_minutes} minutes"),
            actuals.join(", "),
            format!(
                "Rules not meeting the {label} requirement: {}",
                failing.join(", ")
            ),
        );
        for t in targets {
            result = result.with_remediation(t);
        }
        result
    }
}

fn persistent_cookie(policy_id: &str, rules: &[&serde_json::Value]) -> StigCheckResult {
    let pointer = "/actions/signon/session/usePersistentCookie";
    let mut failing = Vec::new();
    let mut actuals = Vec::new();
    let mut targets = Vec::new();
    for r in rules {
        let (_, name) = rule_id_and_name(r);
        match json_bool(r, pointer) {
            Some(false) => actuals.push(format!("{name}=false")),
            Some(true) => {
                actuals.push(format!("{name}=true"));
                failing.push(name.to_string());
                if let Some(t) = rule_field_target(policy_id, r, pointer, serde_json::json!(false))
                {
                    targets.push(t);
                }
            }
            None => failing.push(format!("{name} (field missing)")),
        }
    }
    if failing.is_empty() {
        StigCheckResult::new(
            "V-273206",
            StigStatus::NotAFinding,
            "false",
            actuals.join(", "),
            "Every enabled rule disables persistent session cookies.",
        )
    } else {
        let mut result = StigCheckResult::new(
            "V-273206",
            StigStatus::Open,
            "false",
            actuals.join(", "),
            format!(
                "Rules with persistent cookies enabled: {}",
                failing.join(", ")
            ),
        );
        for t in targets {
            result = result.with_remediation(t);
        }
        result
    }
}
