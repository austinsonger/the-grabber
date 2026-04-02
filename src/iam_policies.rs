use anyhow::{Context, Result};
use async_trait::async_trait;
use aws_sdk_iam::Client as IamClient;

use crate::evidence::CsvCollector;

fn url_decode(s: &str) -> String {
    s.replace("%22", "\"").replace("%7B", "{").replace("%7D", "}")
     .replace("%5B", "[").replace("%5D", "]").replace("%3A", ":")
     .replace("%2F", "/").replace("%2C", ",").replace("%20", " ")
     .replace("%0A", " ").replace("+", " ")
}

// ══════════════════════════════════════════════════════════════════════════════
// 1. IAM Role Policies
// ══════════════════════════════════════════════════════════════════════════════

pub struct IamRolePoliciesCollector {
    client: IamClient,
}

impl IamRolePoliciesCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self { client: IamClient::new(config) }
    }
}

#[async_trait]
impl CsvCollector for IamRolePoliciesCollector {
    fn name(&self) -> &str { "IAM Role Policies" }
    fn filename_prefix(&self) -> &str { "IAM_Role_Policies" }
    fn headers(&self) -> &'static [&'static str] {
        &["Role Name", "Assume Role Policy (Trust)", "Inline Policies", "Attached Managed Policies"]
    }

    async fn collect_rows(&self, _account_id: &str, _region: &str) -> Result<Vec<Vec<String>>> {
        let mut rows = Vec::new();
        let mut marker: Option<String> = None;

        loop {
            let mut req = self.client.list_roles();
            if let Some(ref m) = marker {
                req = req.marker(m);
            }
            let resp = req.send().await.context("IAM list_roles")?;

            for role in resp.roles() {
                let role_name = role.role_name().to_string();

                let trust_policy = url_decode(
                    role.assume_role_policy_document().unwrap_or("")
                );

                // Inline policies
                let inline = match self.client
                    .list_role_policies()
                    .role_name(&role_name)
                    .send()
                    .await
                {
                    Ok(r) => {
                        let mut docs: Vec<String> = Vec::new();
                        for policy_name in r.policy_names() {
                            let doc = match self.client
                                .get_role_policy()
                                .role_name(&role_name)
                                .policy_name(policy_name)
                                .send()
                                .await
                            {
                                Ok(p) => format!(
                                    "{}:{}",
                                    policy_name,
                                    url_decode(p.policy_document())
                                ),
                                Err(_) => policy_name.to_string(),
                            };
                            docs.push(doc);
                        }
                        docs.join(" | ")
                    }
                    Err(_) => String::new(),
                };

                // Attached managed policies
                let attached = match self.client
                    .list_attached_role_policies()
                    .role_name(&role_name)
                    .send()
                    .await
                {
                    Ok(r) => r.attached_policies()
                        .iter()
                        .filter_map(|p| p.policy_name())
                        .collect::<Vec<_>>()
                        .join(", "),
                    Err(_) => String::new(),
                };

                rows.push(vec![role_name, trust_policy, inline, attached]);
            }

            marker = if resp.is_truncated() { resp.marker().map(|s| s.to_string()) } else { None };
            if marker.is_none() { break; }
        }

        Ok(rows)
    }
}

// ══════════════════════════════════════════════════════════════════════════════
// 2. IAM User Policies
// ══════════════════════════════════════════════════════════════════════════════

pub struct IamUserPoliciesCollector {
    client: IamClient,
}

impl IamUserPoliciesCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self { client: IamClient::new(config) }
    }
}

#[async_trait]
impl CsvCollector for IamUserPoliciesCollector {
    fn name(&self) -> &str { "IAM User Policies" }
    fn filename_prefix(&self) -> &str { "IAM_User_Policies" }
    fn headers(&self) -> &'static [&'static str] {
        &["User Name", "Inline Policies", "Attached Policies", "Permissions Boundary"]
    }

    async fn collect_rows(&self, _account_id: &str, _region: &str) -> Result<Vec<Vec<String>>> {
        let mut rows = Vec::new();
        let mut marker: Option<String> = None;

        loop {
            let mut req = self.client.list_users();
            if let Some(ref m) = marker {
                req = req.marker(m);
            }
            let resp = req.send().await.context("IAM list_users")?;

            for user in resp.users() {
                let user_name = user.user_name().to_string();

                // Inline policies
                let inline = match self.client
                    .list_user_policies()
                    .user_name(&user_name)
                    .send()
                    .await
                {
                    Ok(r) => {
                        let mut docs: Vec<String> = Vec::new();
                        for policy_name in r.policy_names() {
                            let doc = match self.client
                                .get_user_policy()
                                .user_name(&user_name)
                                .policy_name(policy_name)
                                .send()
                                .await
                            {
                                Ok(p) => format!(
                                    "{}:{}",
                                    policy_name,
                                    url_decode(p.policy_document())
                                ),
                                Err(_) => policy_name.to_string(),
                            };
                            docs.push(doc);
                        }
                        docs.join(" | ")
                    }
                    Err(_) => String::new(),
                };

                // Attached managed policies
                let attached = match self.client
                    .list_attached_user_policies()
                    .user_name(&user_name)
                    .send()
                    .await
                {
                    Ok(r) => r.attached_policies()
                        .iter()
                        .filter_map(|p| p.policy_name())
                        .collect::<Vec<_>>()
                        .join(", "),
                    Err(_) => String::new(),
                };

                // Permissions boundary
                let boundary = user.permissions_boundary()
                    .and_then(|b| b.permissions_boundary_arn())
                    .unwrap_or("")
                    .to_string();

                rows.push(vec![user_name, inline, attached, boundary]);
            }

            marker = if resp.is_truncated() { resp.marker().map(|s| s.to_string()) } else { None };
            if marker.is_none() { break; }
        }

        Ok(rows)
    }
}

// ══════════════════════════════════════════════════════════════════════════════
// 3. IAM Account Password Policy
// ══════════════════════════════════════════════════════════════════════════════

pub struct IamPasswordPolicyCollector {
    client: IamClient,
}

impl IamPasswordPolicyCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self { client: IamClient::new(config) }
    }
}

#[async_trait]
impl CsvCollector for IamPasswordPolicyCollector {
    fn name(&self) -> &str { "IAM Account Password Policy" }
    fn filename_prefix(&self) -> &str { "IAM_Password_Policy" }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Minimum Password Length", "Require Symbols", "Require Numbers",
            "Require Uppercase", "Require Lowercase", "Allow Users To Change",
            "Expire Passwords", "Max Password Age", "Password Reuse Prevention", "Hard Expiry",
        ]
    }

    async fn collect_rows(&self, _account_id: &str, _region: &str) -> Result<Vec<Vec<String>>> {
        match self.client.get_account_password_policy().send().await {
            Ok(resp) => {
                let p = match resp.password_policy() {
                    Some(p) => p,
                    None => {
                        return Ok(vec![vec!["Not Set".to_string(); 10]]);
                    }
                };
                Ok(vec![vec![
                    p.minimum_password_length().map(|n| n.to_string()).unwrap_or_else(|| "8".to_string()),
                    p.require_symbols().to_string(),
                    p.require_numbers().to_string(),
                    p.require_uppercase_characters().to_string(),
                    p.require_lowercase_characters().to_string(),
                    p.allow_users_to_change_password().to_string(),
                    p.expire_passwords().to_string(),
                    p.max_password_age().map(|n| n.to_string()).unwrap_or_else(|| "None".to_string()),
                    p.password_reuse_prevention().map(|n| n.to_string()).unwrap_or_else(|| "None".to_string()),
                    p.hard_expiry().unwrap_or(false).to_string(),
                ]])
            }
            Err(e) => {
                let msg = format!("{e}");
                if msg.contains("NoSuchEntity") {
                    eprintln!("  WARN: No IAM password policy configured for this account");
                    Ok(vec![vec!["Not Configured".to_string(); 10]])
                } else {
                    eprintln!("  WARN: IAM get_account_password_policy: {e:#}");
                    Ok(vec![])
                }
            }
        }
    }
}
