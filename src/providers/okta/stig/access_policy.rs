//! Evaluates the 4 STIG checks against the Identity Engine Authentication
//! (Access) Policies bound to the "Okta Dashboard" and "Okta Admin Console"
//! apps:
//!
//! V-273190/191 (phishing-resistant possession factor required), V-273193/194
//! (MFA required for the app's top rule).
//!
//! Policy resolution is inherently fragile — display names are
//! customer-editable text, and the app's `_links.accessPolicy.href` linkage
//! needs live-tenant confirmation. We try `_links.accessPolicy` first (via
//! the app object) and fall back to name-substring matching against
//! ACCESS_POLICY policies; if neither yields exactly one candidate, the
//! pair of checks for that app degrade to `NotReviewed` rather than
//! guessing.

use okta_rs::types::app::OktaApp;
use okta_rs::types::policy::OktaPolicy;
use okta_rs::OktaClient;

use super::{is_feature_unavailable, json_str};
use crate::stig_status::{StigCheckResult, StigStatus};

struct AppTarget {
    label_substring: &'static str,
    phishing_v_id: &'static str,
    mfa_v_id: &'static str,
}

const DASHBOARD: AppTarget = AppTarget {
    label_substring: "dashboard",
    phishing_v_id: "V-273190",
    mfa_v_id: "V-273194",
};
const ADMIN_CONSOLE: AppTarget = AppTarget {
    label_substring: "admin console",
    phishing_v_id: "V-273191",
    mfa_v_id: "V-273193",
};

const V_IDS: &[&str] = &["V-273190", "V-273191", "V-273193", "V-273194"];

pub async fn evaluate(client: &OktaClient) -> Vec<StigCheckResult> {
    let policies = match client.policies().list_by_type("ACCESS_POLICY").await {
        Ok(p) => p,
        Err(e) if is_feature_unavailable(&e) => {
            return super::degrade_all(V_IDS, &e, "ACCESS_POLICY policies")
        }
        Err(e) => return super::degrade_all(V_IDS, &e, "ACCESS_POLICY policies"),
    };

    // On error, fall back to name-matching against ACCESS_POLICY policies only.
    let apps = client.apps().list_all().await.unwrap_or_default();

    let mut out = Vec::new();
    for target in [&DASHBOARD, &ADMIN_CONSOLE] {
        out.extend(evaluate_app(client, target, &policies, &apps).await);
    }
    out
}

async fn evaluate_app(
    client: &OktaClient,
    target: &AppTarget,
    policies: &[OktaPolicy],
    apps: &[OktaApp],
) -> Vec<StigCheckResult> {
    let policy_id = resolve_policy_id(target, policies, apps);
    let Some(policy_id) = policy_id else {
        return vec![
            StigCheckResult::not_reviewed(
                target.phishing_v_id,
                format!("Could not uniquely resolve the Authentication Policy for the app matching \"{}\" — verify manually.", target.label_substring),
            ),
            StigCheckResult::not_reviewed(
                target.mfa_v_id,
                format!("Could not uniquely resolve the Authentication Policy for the app matching \"{}\" — verify manually.", target.label_substring),
            ),
        ];
    };

    let rules = match client.policies().list_rules(&policy_id).await {
        Ok(r) => r,
        Err(e) if is_feature_unavailable(&e) => {
            return super::degrade_all(
                &[target.phishing_v_id, target.mfa_v_id],
                &e,
                "policy rules",
            );
        }
        Err(e) => {
            return super::degrade_all(&[target.phishing_v_id, target.mfa_v_id], &e, "policy rules")
        }
    };

    // "Top rule" = lowest priority number among ACTIVE rules.
    let top_rule = rules
        .iter()
        .filter(|r| r.get("status").and_then(|s| s.as_str()) == Some("ACTIVE"))
        .min_by_key(|r| {
            r.get("priority")
                .and_then(|p| p.as_i64())
                .unwrap_or(i64::MAX)
        });

    let Some(rule) = top_rule else {
        return vec![
            StigCheckResult::not_reviewed(
                target.phishing_v_id,
                format!("No ACTIVE rule found on policy {policy_id}"),
            ),
            StigCheckResult::not_reviewed(
                target.mfa_v_id,
                format!("No ACTIVE rule found on policy {policy_id}"),
            ),
        ];
    };

    vec![
        phishing_resistant(target.phishing_v_id, rule, &policy_id),
        mfa_required(target.mfa_v_id, rule, &policy_id),
    ]
}

fn resolve_policy_id(
    target: &AppTarget,
    policies: &[OktaPolicy],
    apps: &[OktaApp],
) -> Option<String> {
    let matching_apps: Vec<&OktaApp> = apps
        .iter()
        .filter(|a| {
            a.label.to_lowercase().contains(target.label_substring)
                || a.name.to_lowercase().contains(target.label_substring)
        })
        .collect();

    let via_links: Vec<String> = matching_apps
        .iter()
        .filter_map(|a| json_str(&a.links, "/accessPolicy/href"))
        .filter_map(|href| href.rsplit('/').next())
        .map(|id| id.to_string())
        .collect();
    if via_links.len() == 1 {
        return via_links.into_iter().next();
    }

    let matching_policies: Vec<&OktaPolicy> = policies
        .iter()
        .filter(|p| p.name.to_lowercase().contains(target.label_substring))
        .collect();
    if matching_policies.len() == 1 {
        return Some(matching_policies[0].id.clone());
    }

    None
}

fn phishing_resistant(v_id: &str, rule: &serde_json::Value, policy_id: &str) -> StigCheckResult {
    let constraints = rule
        .pointer("/actions/appSignOn/verificationMethod/constraints")
        .and_then(|c| c.as_array())
        .cloned()
        .unwrap_or_default();

    let phishing_resistant = constraints.iter().any(|c| {
        c.pointer("/possession/phishingResistant")
            .and_then(|v| v.as_str())
            == Some("REQUIRED")
    });

    if phishing_resistant {
        StigCheckResult::new(
            v_id,
            StigStatus::NotAFinding,
            "possession.phishingResistant = REQUIRED",
            "REQUIRED",
            format!(
                "Top rule on policy {policy_id} requires a phishing-resistant possession factor."
            ),
        )
    } else {
        StigCheckResult::new(
            v_id,
            StigStatus::Open,
            "possession.phishingResistant = REQUIRED",
            "not set / OPTIONAL",
            format!("Top rule on policy {policy_id} does not require a phishing-resistant possession factor. Field path/schema for this constraint needs live-tenant verification."),
        )
    }
}

fn mfa_required(v_id: &str, rule: &serde_json::Value, policy_id: &str) -> StigCheckResult {
    let factor_mode = json_str(rule, "/actions/appSignOn/verificationMethod/factorMode");
    match factor_mode {
        Some("2FA") => StigCheckResult::new(
            v_id,
            StigStatus::NotAFinding,
            "2FA",
            "2FA",
            format!("Top rule on policy {policy_id} requires two-factor authentication."),
        ),
        Some(other) => StigCheckResult::new(
            v_id,
            StigStatus::Open,
            "2FA",
            other,
            format!("Top rule on policy {policy_id} does not require two-factor authentication."),
        ),
        None => StigCheckResult::not_reviewed(
            v_id,
            format!("verificationMethod.factorMode not found on policy {policy_id}'s top rule — field path needs live-tenant verification."),
        ),
    }
}
