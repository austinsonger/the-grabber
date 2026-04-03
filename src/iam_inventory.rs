use anyhow::{Context, Result};
use async_trait::async_trait;
use aws_sdk_iam::Client as IamClient;

use crate::evidence::{CsvCollector, JsonCollector};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn fmt_iam_dt(dt: &aws_sdk_iam::primitives::DateTime) -> String {
    chrono::DateTime::<chrono::Utc>::from_timestamp(dt.secs(), dt.subsec_nanos())
        .map(|c| c.to_rfc3339())
        .unwrap_or_default()
}

/// Minimal URL-decode for IAM policy documents (handles the characters AWS encodes).
fn url_decode(s: &str) -> String {
    s.replace("%22", "\"")
     .replace("%7B", "{").replace("%7D", "}")
     .replace("%5B", "[").replace("%5D", "]")
     .replace("%3A", ":").replace("%2F", "/")
     .replace("%2C", ",").replace("%20", " ")
     .replace("%0A", " ").replace("+", " ")
}

/// Summarize principals from a URL-encoded trust policy JSON.
fn trust_policy_principals(encoded: &str) -> String {
    let decoded = url_decode(encoded);
    // Quick extraction: find "Principal" and grab the next 300 chars.
    if let Some(idx) = decoded.find("\"Principal\"") {
        let snippet = &decoded[idx..];
        let end = snippet.len().min(300);
        snippet[..end].replace('\n', " ").replace("  ", " ")
    } else {
        decoded.chars().take(200).collect()
    }
}

// ---------------------------------------------------------------------------
// IAM Users
// ---------------------------------------------------------------------------

pub struct IamUserCollector {
    client: IamClient,
}

impl IamUserCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self { client: IamClient::new(config) }
    }
}

#[async_trait]
impl CsvCollector for IamUserCollector {
    fn name(&self) -> &str { "IAM Users" }
    fn filename_prefix(&self) -> &str { "IAM_Users" }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "User Name", "ARN", "MFA Enabled",
            "Password Last Used", "Access Key Status", "Created Date",
        ]
    }

    async fn collect_rows(&self, _account_id: &str, _region: &str, _dates: Option<(i64, i64)>) -> Result<Vec<Vec<String>>> {
        let mut rows = Vec::new();
        let mut marker: Option<String> = None;

        loop {
            let mut req = self.client.list_users();
            if let Some(ref m) = marker {
                req = req.marker(m);
            }
            let resp = req.send().await.context("IAM list_users")?;

            for user in resp.users() {
                let name    = user.user_name().to_string();
                let arn     = user.arn().to_string();
                let created = fmt_iam_dt(user.create_date());
                let pw_last = user.password_last_used()
                    .map(|d| fmt_iam_dt(d))
                    .unwrap_or_else(|| "Never".to_string());

                let mfa_enabled = match self.client
                    .list_mfa_devices()
                    .user_name(&name)
                    .send()
                    .await
                {
                    Ok(r) => if r.mfa_devices().is_empty() { "No" } else { "Yes" }.to_string(),
                    Err(_) => "".to_string(),
                };

                let key_status = match self.client
                    .list_access_keys()
                    .user_name(&name)
                    .send()
                    .await
                {
                    Ok(r) => {
                        let statuses: Vec<String> = r.access_key_metadata()
                            .iter()
                            .map(|k| k.status().map(|s| s.as_str()).unwrap_or("").to_string())
                            .collect();
                        statuses.join(", ")
                    }
                    Err(_) => "".to_string(),
                };

                rows.push(vec![name, arn, mfa_enabled, pw_last, key_status, created]);
            }

            marker = if resp.is_truncated() { resp.marker().map(|s| s.to_string()) } else { None };
            if marker.is_none() { break; }
        }

        Ok(rows)
    }
}

// ---------------------------------------------------------------------------
// IAM Roles
// ---------------------------------------------------------------------------

pub struct IamRoleCollector {
    client: IamClient,
}

impl IamRoleCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self { client: IamClient::new(config) }
    }
}

#[async_trait]
impl JsonCollector for IamRoleCollector {
    fn name(&self) -> &str { "IAM Roles" }
    fn filename_prefix(&self) -> &str { "IAM_Roles" }

    async fn collect_records(&self, _account_id: &str, _region: &str) -> Result<Vec<serde_json::Value>> {
        let mut records = Vec::new();
        let mut marker: Option<String> = None;

        loop {
            let mut req = self.client.list_roles();
            if let Some(ref m) = marker {
                req = req.marker(m);
            }
            let resp = req.send().await.context("IAM list_roles")?;

            for role in resp.roles() {
                let name = role.role_name().to_string();
                let arn  = role.arn().to_string();

                let trust_policy: serde_json::Value = serde_json::from_str(
                    &url_decode(role.assume_role_policy_document().unwrap_or("{}"))
                ).unwrap_or(serde_json::Value::Null);

                let last_used = role.role_last_used()
                    .and_then(|l| l.last_used_date())
                    .map(|d| fmt_iam_dt(d))
                    .unwrap_or_else(|| "Never".to_string());
                let last_used_region = role.role_last_used()
                    .and_then(|l| l.region())
                    .unwrap_or("")
                    .to_string();

                let attached_policies: Vec<String> = match self.client
                    .list_attached_role_policies()
                    .role_name(&name)
                    .send()
                    .await
                {
                    Ok(r) => r.attached_policies()
                        .iter()
                        .filter_map(|p| p.policy_name().map(|s| s.to_string()))
                        .collect(),
                    Err(_) => vec![],
                };

                records.push(serde_json::json!({
                    "role_name":          name,
                    "arn":                arn,
                    "trust_policy":       trust_policy,
                    "attached_policies":  attached_policies,
                    "last_used":          last_used,
                    "last_used_region":   last_used_region,
                }));
            }

            marker = if resp.is_truncated() { resp.marker().map(|s| s.to_string()) } else { None };
            if marker.is_none() { break; }
        }

        Ok(records)
    }
}

// ---------------------------------------------------------------------------
// IAM Policies (customer-managed)
// ---------------------------------------------------------------------------

pub struct IamPolicyCollector {
    client: IamClient,
}

impl IamPolicyCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self { client: IamClient::new(config) }
    }
}

#[async_trait]
impl CsvCollector for IamPolicyCollector {
    fn name(&self) -> &str { "IAM Policies" }
    fn filename_prefix(&self) -> &str { "IAM_Policies" }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Policy Name", "ARN", "Policy Type",
            "Attached Entities", "Permissions Summary",
        ]
    }

    async fn collect_rows(&self, _account_id: &str, _region: &str, _dates: Option<(i64, i64)>) -> Result<Vec<Vec<String>>> {
        let mut rows = Vec::new();
        let mut marker: Option<String> = None;

        // Only customer-managed policies to avoid thousands of AWS-managed rows.
        loop {
            let mut req = self.client.list_policies().scope(
                aws_sdk_iam::types::PolicyScopeType::Local,
            );
            if let Some(ref m) = marker {
                req = req.marker(m);
            }
            let resp = req.send().await.context("IAM list_policies")?;

            for policy in resp.policies() {
                let name           = policy.policy_name().unwrap_or("").to_string();
                let arn            = policy.arn().unwrap_or("").to_string();
                let policy_type    = "Customer Managed".to_string();
                let attached       = policy.attachment_count()
                    .map(|n| n.to_string())
                    .unwrap_or_default();
                let default_ver    = policy.default_version_id().unwrap_or("").to_string();

                let perms_summary = if !arn.is_empty() && !default_ver.is_empty() {
                    match self.client
                        .get_policy_version()
                        .policy_arn(&arn)
                        .version_id(&default_ver)
                        .send()
                        .await
                    {
                        Ok(r) => {
                            let doc = r.policy_version()
                                .and_then(|v| v.document())
                                .map(|d| url_decode(d))
                                .unwrap_or_default();
                            // Extract actions from policy document (very rough summary).
                            summarize_policy_actions(&doc)
                        }
                        Err(_) => "".to_string(),
                    }
                } else {
                    "".to_string()
                };

                rows.push(vec![name, arn, policy_type, attached, perms_summary]);
            }

            marker = if resp.is_truncated() { resp.marker().map(|s| s.to_string()) } else { None };
            if marker.is_none() { break; }
        }

        Ok(rows)
    }
}

fn summarize_policy_actions(doc: &str) -> String {
    // Rough extraction of "Action" values from the JSON policy document.
    let mut actions = Vec::new();
    let mut rest = doc;
    while let Some(idx) = rest.find("\"Action\"") {
        rest = &rest[idx + 8..];
        // Skip to first quote or bracket after the colon
        if let Some(start) = rest.find('"') {
            let snippet = &rest[start + 1..];
            if let Some(end) = snippet.find('"') {
                actions.push(snippet[..end].to_string());
            }
        }
        if actions.len() >= 5 { break; }
    }
    if actions.is_empty() {
        doc.chars().take(150).collect()
    } else {
        let mut result = actions.join(", ");
        if doc.matches("\"Action\"").count() > 5 {
            result.push_str(", ...");
        }
        result
    }
}

// ---------------------------------------------------------------------------
// IAM Access Keys
// ---------------------------------------------------------------------------

pub struct IamAccessKeyCollector {
    client: IamClient,
}

impl IamAccessKeyCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self { client: IamClient::new(config) }
    }
}

#[async_trait]
impl CsvCollector for IamAccessKeyCollector {
    fn name(&self) -> &str { "IAM Access Keys" }
    fn filename_prefix(&self) -> &str { "IAM_Access_Keys" }
    fn headers(&self) -> &'static [&'static str] {
        &["User Name", "Access Key ID", "Status", "Created Date", "Last Used"]
    }

    async fn collect_rows(&self, _account_id: &str, _region: &str, _dates: Option<(i64, i64)>) -> Result<Vec<Vec<String>>> {
        let mut rows = Vec::new();

        // Collect all usernames first.
        let mut user_names: Vec<String> = Vec::new();
        let mut marker: Option<String> = None;
        loop {
            let mut req = self.client.list_users();
            if let Some(ref m) = marker {
                req = req.marker(m);
            }
            let resp = req.send().await.context("IAM list_users (access keys)")?;
            for u in resp.users() {
                user_names.push(u.user_name().to_string());
            }
            marker = if resp.is_truncated() { resp.marker().map(|s| s.to_string()) } else { None };
            if marker.is_none() { break; }
        }

        // Fetch access keys for each user.
        for user_name in &user_names {
            let key_resp = match self.client
                .list_access_keys()
                .user_name(user_name)
                .send()
                .await
            {
                Ok(r) => r,
                Err(_) => continue,
            };

            for key_meta in key_resp.access_key_metadata() {
                let key_id  = key_meta.access_key_id().unwrap_or("").to_string();
                let status  = key_meta.status().map(|s| s.as_str()).unwrap_or("").to_string();
                let created = key_meta.create_date().map(|d| fmt_iam_dt(d)).unwrap_or_default();

                let last_used = match self.client
                    .get_access_key_last_used()
                    .access_key_id(&key_id)
                    .send()
                    .await
                {
                    Ok(r) => r.access_key_last_used()
                        .and_then(|l| l.last_used_date())
                        .map(|d| fmt_iam_dt(d))
                        .unwrap_or_else(|| "Never".to_string()),
                    Err(_) => "".to_string(),
                };

                rows.push(vec![user_name.clone(), key_id, status, created, last_used]);
            }
        }

        Ok(rows)
    }
}
