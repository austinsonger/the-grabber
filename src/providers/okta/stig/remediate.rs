//! Executes a `RemediationTarget` produced by a STIG evaluator against the
//! live tenant.
//!
//! Every write is a read-modify-write: the current resource is re-fetched
//! immediately before writing (never the possibly-stale copy captured when
//! the STIG scan ran), only the target's field(s) are mutated, and the
//! whole resource is written back — Okta's Policy/Authenticator/Brand APIs
//! replace the resource, they don't merge-patch, so every other field a
//! tenant admin may have changed since the scan is preserved.

use anyhow::{Context, Result};
use okta_rs::OktaClient;
use serde_json::Value;

use crate::stig_status::{RemediationInputs, RemediationOutcome, RemediationTarget};

#[allow(dead_code)]
pub async fn apply(
    client: &OktaClient,
    target: &RemediationTarget,
    inputs: &RemediationInputs,
) -> RemediationOutcome {
    let result = match target {
        RemediationTarget::PolicyField {
            policy_id,
            policy_type,
            rule_id,
            fields,
            ..
        } => apply_policy_field(client, policy_id, policy_type, rule_id.as_deref(), fields).await,
        RemediationTarget::AccessPolicyPhishingResistant {
            policy_id, rule_id, ..
        } => apply_access_policy_phishing_resistant(client, policy_id, rule_id).await,
        RemediationTarget::AuthenticatorField {
            authenticator_id,
            fields,
            ..
        } => apply_authenticator_field(client, authenticator_id, fields).await,
        RemediationTarget::ActivateAuthenticator {
            authenticator_id, ..
        } => apply_activate_authenticator(client, authenticator_id).await,
        RemediationTarget::SetSignInBanner { brand_id } => {
            apply_set_sign_in_banner(client, brand_id, inputs).await
        }
        RemediationTarget::ManualOnly => return RemediationOutcome::ManuallyAcknowledged,
    };
    match result {
        Ok(summary) => RemediationOutcome::Applied { summary },
        Err(e) => RemediationOutcome::Failed {
            error: format!("{e:#}"),
        },
    }
}

/// Set a JSON pointer to a value inside a mutable JSON tree, creating nothing
/// — the parent object must already exist. Pointer must be non-root
/// (`/a/b/c`-shaped); the last segment is the field being written.
fn set_at_pointer(root: &mut Value, pointer: &str, new_value: Value) -> Result<()> {
    let (parent_pointer, key) = pointer
        .rsplit_once('/')
        .context("remediation field pointer must contain at least one '/'")?;
    let parent = if parent_pointer.is_empty() {
        root
    } else {
        root.pointer_mut(parent_pointer)
            .with_context(|| format!("path {parent_pointer} not found in resource"))?
    };
    let obj = parent
        .as_object_mut()
        .context("parent of remediation field pointer is not a JSON object")?;
    obj.insert(key.to_string(), new_value);
    Ok(())
}

async fn apply_policy_field(
    client: &OktaClient,
    policy_id: &str,
    policy_type: &str,
    rule_id: Option<&str>,
    fields: &[(String, Value)],
) -> Result<String> {
    if let Some(rule_id) = rule_id {
        let rules = client
            .policies()
            .list_rules(policy_id)
            .await
            .context("re-fetch policy rules")?;
        let mut rule = rules
            .into_iter()
            .find(|r| r.get("id").and_then(|v| v.as_str()) == Some(rule_id))
            .with_context(|| format!("rule {rule_id} no longer exists on policy {policy_id}"))?;
        for (pointer, value) in fields {
            set_at_pointer(&mut rule, pointer, value.clone())?;
        }
        client
            .policies()
            .update_rule(policy_id, rule_id, &rule)
            .await
            .context("write updated rule")?;
    } else {
        let policies = client
            .policies()
            .list_by_type(policy_type)
            .await
            .context("re-fetch policies")?;
        let policy = policies
            .into_iter()
            .find(|p| p.id == policy_id)
            .with_context(|| format!("policy {policy_id} no longer exists"))?;
        let mut body = serde_json::to_value(&policy).context("serialize policy for write-back")?;
        let settings = body
            .get_mut("settings")
            .context("policy body has no settings object")?;
        for (pointer, value) in fields {
            set_at_pointer(settings, pointer, value.clone())?;
        }
        client
            .policies()
            .update_policy(policy_id, &body)
            .await
            .context("write updated policy")?;
    }
    Ok(format!(
        "Updated {} field{}",
        fields.len(),
        if fields.len() == 1 { "" } else { "s" }
    ))
}

async fn apply_access_policy_phishing_resistant(
    client: &OktaClient,
    policy_id: &str,
    rule_id: &str,
) -> Result<String> {
    let rules = client
        .policies()
        .list_rules(policy_id)
        .await
        .context("re-fetch policy rules")?;
    let mut rule = rules
        .into_iter()
        .find(|r| r.get("id").and_then(|v| v.as_str()) == Some(rule_id))
        .with_context(|| format!("rule {rule_id} no longer exists on policy {policy_id}"))?;

    let has_constraints = rule
        .pointer("/actions/appSignOn/verificationMethod/constraints")
        .and_then(|c| c.as_array())
        .map(|a| !a.is_empty())
        .unwrap_or(false);

    if has_constraints {
        let constraints = rule
            .pointer_mut("/actions/appSignOn/verificationMethod/constraints")
            .and_then(|c| c.as_array_mut())
            .context("constraints array vanished after re-check")?;
        for entry in constraints.iter_mut() {
            if !entry.is_object() {
                *entry = serde_json::json!({});
            }
            let obj = entry.as_object_mut().expect("just ensured object");
            let possession = obj
                .entry("possession".to_string())
                .or_insert_with(|| serde_json::json!({}));
            if !possession.is_object() {
                *possession = serde_json::json!({});
            }
            possession
                .as_object_mut()
                .expect("just ensured object")
                .insert(
                    "phishingResistant".to_string(),
                    serde_json::json!("REQUIRED"),
                );
        }
    } else {
        set_at_pointer(
            &mut rule,
            "/actions/appSignOn/verificationMethod/constraints",
            serde_json::json!([{"possession": {"phishingResistant": "REQUIRED"}}]),
        )?;
    }

    client
        .policies()
        .update_rule(policy_id, rule_id, &rule)
        .await
        .context("write updated rule")?;
    Ok("Set possession.phishingResistant = REQUIRED on the top rule".to_string())
}

async fn apply_authenticator_field(
    client: &OktaClient,
    authenticator_id: &str,
    fields: &[(String, Value)],
) -> Result<String> {
    let authenticators = client
        .authenticators()
        .list_all()
        .await
        .context("re-fetch authenticators")?;
    let mut authenticator = authenticators
        .into_iter()
        .find(|a| a.get("id").and_then(|v| v.as_str()) == Some(authenticator_id))
        .with_context(|| format!("authenticator {authenticator_id} no longer exists"))?;
    for (pointer, value) in fields {
        set_at_pointer(&mut authenticator, pointer, value.clone())?;
    }
    client
        .authenticators()
        .update(authenticator_id, &authenticator)
        .await
        .context("write updated authenticator")?;
    Ok(format!(
        "Updated {} field{} on the authenticator",
        fields.len(),
        if fields.len() == 1 { "" } else { "s" }
    ))
}

async fn apply_activate_authenticator(
    client: &OktaClient,
    authenticator_id: &str,
) -> Result<String> {
    client
        .authenticators()
        .activate(authenticator_id)
        .await
        .context("activate authenticator")?;
    Ok("Activated the authenticator".to_string())
}

async fn apply_set_sign_in_banner(
    client: &OktaClient,
    brand_id: &str,
    inputs: &RemediationInputs,
) -> Result<String> {
    let text = inputs
        .text
        .as_deref()
        .map(str::trim)
        .filter(|t| !t.is_empty())
        .context("no banner text supplied")?;

    let mut page = client
        .sign_in_widget()
        .customized_page(brand_id)
        .await
        .unwrap_or(serde_json::json!({}));
    if !page.is_object() {
        page = serde_json::json!({});
    }
    let obj = page.as_object_mut().expect("just ensured object");
    // Mirror the same field-name ambiguity the read side already defends
    // against (src/providers/okta/stig/manual_review.rs checks both).
    if obj.contains_key("signInHtml") {
        obj.insert("signInHtml".to_string(), serde_json::json!(text));
    } else {
        obj.insert("content".to_string(), serde_json::json!(text));
    }

    client
        .sign_in_widget()
        .update_customized_page(brand_id, &page)
        .await
        .context("write custom sign-in page")?;
    Ok("Updated the sign-in page's custom content".to_string())
}
