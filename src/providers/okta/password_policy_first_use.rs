use anyhow::Result;
use async_trait::async_trait;
use okta_rs::OktaClient;
use serde_json::Value;

use crate::evidence::CsvCollector;

pub struct OktaPasswordPolicyFirstUseCollector {
    client: OktaClient,
}

impl OktaPasswordPolicyFirstUseCollector {
    pub fn new(client: OktaClient) -> Self {
        Self { client }
    }
}

/// Best-effort extraction of the "change password on first login" setting
/// from a PASSWORD policy's `settings` JSON blob. Okta doesn't expose this as
/// a single flat field, so we check a few known shapes and fall back to an
/// empty string when nothing matches.
fn first_use_flag(settings: &Value) -> String {
    if let Some(b) = settings
        .pointer("/password/passwordChangeOnFirstLogin")
        .and_then(|v| v.as_bool())
    {
        return if b { "YES".to_string() } else { "NO".to_string() };
    }
    if let Some(days) = settings.pointer("/password/passwordExpireDays").and_then(|v| v.as_i64())
    {
        return if days > 0 { "YES".to_string() } else { "NO".to_string() };
    }
    String::new()
}

/// Comma-joined summary of complexity fields present under
/// `settings.password.complexity`.
fn complexity_summary(settings: &Value) -> String {
    let complexity = match settings.pointer("/password/complexity") {
        Some(Value::Object(m)) if !m.is_empty() => m,
        _ => return String::new(),
    };
    let mut parts: Vec<String> = Vec::new();
    for (key, value) in complexity {
        let rendered = match value {
            Value::String(s) => s.clone(),
            Value::Number(n) => n.to_string(),
            Value::Bool(b) => b.to_string(),
            _ => continue,
        };
        parts.push(format!("{key}={rendered}"));
    }
    parts.sort();
    parts.join(", ")
}

#[async_trait]
impl CsvCollector for OktaPasswordPolicyFirstUseCollector {
    fn name(&self) -> &str {
        "Okta Password Policy First Use"
    }
    fn filename_prefix(&self) -> &str {
        "Okta_Password_Policy_First_Use"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Policy ID",
            "Name",
            "Status",
            "Priority",
            "Password Change On First Login",
            "Password Complexity",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let policies = match self.client.policies().list_by_type("PASSWORD").await {
            Ok(p) => p,
            Err(okta_rs::OktaError::Api { status, .. }) if status == 400 || status == 404 => {
                return Ok(vec![])
            }
            Err(e) => return Err(e.into()),
        };

        let rows = policies
            .into_iter()
            .map(|p| {
                vec![
                    p.id,
                    p.name,
                    p.status,
                    p.priority.map(|n| n.to_string()).unwrap_or_default(),
                    first_use_flag(&p.settings),
                    complexity_summary(&p.settings),
                ]
            })
            .collect();

        Ok(rows)
    }
}
