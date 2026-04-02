use anyhow::{Context, Result};
use async_trait::async_trait;
use aws_sdk_lambda::Client as LambdaClient;

use crate::evidence::CsvCollector;

// ══════════════════════════════════════════════════════════════════════════════
// 1. Lambda Function Configuration
// ══════════════════════════════════════════════════════════════════════════════

pub struct LambdaConfigCollector {
    client: LambdaClient,
}

impl LambdaConfigCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self { client: LambdaClient::new(config) }
    }
}

#[async_trait]
impl CsvCollector for LambdaConfigCollector {
    fn name(&self) -> &str { "Lambda Function Configuration" }
    fn filename_prefix(&self) -> &str { "Lambda_Config" }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Function Name", "Runtime", "Role ARN", "Handler",
            "Timeout (s)", "Memory (MB)", "VPC ID", "Env Vars (count, redacted)",
            "Dead Letter Config",
        ]
    }

    async fn collect_rows(&self, _account_id: &str, _region: &str) -> Result<Vec<Vec<String>>> {
        let mut rows = Vec::new();
        let mut marker: Option<String> = None;

        loop {
            let mut req = self.client.list_functions();
            if let Some(ref m) = marker {
                req = req.marker(m);
            }
            let resp = req.send().await.context("Lambda list_functions")?;

            for func in resp.functions() {
                let name    = func.function_name().unwrap_or("").to_string();
                let runtime = func.runtime()
                    .map(|r| r.as_str().to_string())
                    .unwrap_or_else(|| "custom".to_string());
                let role    = func.role().unwrap_or("").to_string();
                let handler = func.handler().unwrap_or("").to_string();
                let timeout = func.timeout().map(|n| n.to_string()).unwrap_or_default();
                let memory  = func.memory_size().map(|n| n.to_string()).unwrap_or_default();

                let vpc_id  = func.vpc_config()
                    .and_then(|v| v.vpc_id())
                    .unwrap_or("")
                    .to_string();

                // Count env vars but DO NOT include their values (potentially sensitive)
                let env_count = func.environment()
                    .and_then(|e| e.variables())
                    .map(|v| v.len())
                    .unwrap_or(0)
                    .to_string();

                let dlq = func.dead_letter_config()
                    .and_then(|d| d.target_arn())
                    .unwrap_or("")
                    .to_string();

                rows.push(vec![
                    name, runtime, role, handler,
                    timeout, memory, vpc_id,
                    format!("{env_count} vars (redacted)"),
                    dlq,
                ]);
            }

            marker = resp.next_marker().map(|s| s.to_string());
            if marker.is_none() { break; }
        }

        Ok(rows)
    }
}

// ══════════════════════════════════════════════════════════════════════════════
// 2. Lambda Function Permissions
// ══════════════════════════════════════════════════════════════════════════════

pub struct LambdaPermissionsCollector {
    client: LambdaClient,
}

impl LambdaPermissionsCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self { client: LambdaClient::new(config) }
    }
}

#[async_trait]
impl CsvCollector for LambdaPermissionsCollector {
    fn name(&self) -> &str { "Lambda Function Permissions" }
    fn filename_prefix(&self) -> &str { "Lambda_Permissions_Config" }
    fn headers(&self) -> &'static [&'static str] {
        &["Function Name", "Statement ID", "Principal", "Action", "Source ARN", "Effect"]
    }

    async fn collect_rows(&self, _account_id: &str, _region: &str) -> Result<Vec<Vec<String>>> {
        let mut rows = Vec::new();
        let mut marker: Option<String> = None;

        // Collect function names
        let mut function_names: Vec<String> = Vec::new();
        loop {
            let mut req = self.client.list_functions();
            if let Some(ref m) = marker {
                req = req.marker(m);
            }
            let resp = req.send().await.context("Lambda list_functions (permissions)")?;
            for func in resp.functions() {
                if let Some(name) = func.function_name() {
                    function_names.push(name.to_string());
                }
            }
            marker = resp.next_marker().map(|s| s.to_string());
            if marker.is_none() { break; }
        }

        for function_name in &function_names {
            let policy_str = match self.client
                .get_policy()
                .function_name(function_name)
                .send()
                .await
            {
                Ok(r) => r.policy().unwrap_or("").to_string(),
                Err(e) => {
                    let msg = format!("{e}");
                    // ResourceNotFoundException means no resource-based policy
                    if msg.contains("ResourceNotFoundException") {
                        continue;
                    }
                    eprintln!("  WARN: Lambda get_policy {function_name}: {e:#}");
                    continue;
                }
            };

            // Parse the JSON policy to extract statements
            if let Ok(policy) = serde_json::from_str::<serde_json::Value>(&policy_str) {
                if let Some(stmts) = policy["Statement"].as_array() {
                    for stmt in stmts {
                        let sid       = stmt["Sid"].as_str().unwrap_or("").to_string();
                        let effect    = stmt["Effect"].as_str().unwrap_or("").to_string();
                        let action    = match &stmt["Action"] {
                            serde_json::Value::String(s) => s.clone(),
                            serde_json::Value::Array(a) => a.iter()
                                .filter_map(|v| v.as_str())
                                .collect::<Vec<_>>()
                                .join(", "),
                            _ => String::new(),
                        };
                        let principal = match &stmt["Principal"] {
                            serde_json::Value::String(s) => s.clone(),
                            serde_json::Value::Object(m) => m.values()
                                .filter_map(|v| v.as_str())
                                .collect::<Vec<_>>()
                                .join(", "),
                            _ => String::new(),
                        };
                        let source_arn = stmt["Condition"]["ArnLike"]["AWS:SourceArn"]
                            .as_str()
                            .unwrap_or("")
                            .to_string();

                        rows.push(vec![
                            function_name.clone(),
                            sid,
                            principal,
                            action,
                            source_arn,
                            effect,
                        ]);
                    }
                }
            }
        }

        Ok(rows)
    }
}
