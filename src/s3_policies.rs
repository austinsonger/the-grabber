use anyhow::{Context, Result};
use async_trait::async_trait;
use aws_sdk_s3::Client as S3Client;

use crate::evidence::CsvCollector;

pub struct S3PoliciesCollector {
    client: S3Client,
}

impl S3PoliciesCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self { client: S3Client::new(config) }
    }
}

#[async_trait]
impl CsvCollector for S3PoliciesCollector {
    fn name(&self) -> &str { "S3 Bucket Policies" }
    fn filename_prefix(&self) -> &str { "S3_Policies" }
    fn headers(&self) -> &'static [&'static str] {
        &["Bucket Name", "Public Access Block All", "TLS Enforced", "Has Bucket Policy", "Policy Allows Public", "Default Encryption"]
    }

    async fn collect_rows(&self, _account_id: &str, _region: &str) -> Result<Vec<Vec<String>>> {
        let mut rows = Vec::new();

        let buckets_resp = self.client
            .list_buckets()
            .send()
            .await
            .context("S3 list_buckets")?;

        for bucket in buckets_resp.buckets() {
            let bucket_name = bucket.name().unwrap_or("").to_string();

            // ── Public access block ───────────────────────────────────────────
            let public_access_block = match self.client
                .get_public_access_block()
                .bucket(&bucket_name)
                .send()
                .await
            {
                Ok(resp) => {
                    let cfg = resp.public_access_block_configuration();
                    let all_blocked = cfg.map(|c| {
                        c.block_public_acls().unwrap_or(false)
                            && c.ignore_public_acls().unwrap_or(false)
                            && c.block_public_policy().unwrap_or(false)
                            && c.restrict_public_buckets().unwrap_or(false)
                    }).unwrap_or(false);
                    let some_blocked = cfg.map(|c| {
                        c.block_public_acls().unwrap_or(false)
                            || c.ignore_public_acls().unwrap_or(false)
                            || c.block_public_policy().unwrap_or(false)
                            || c.restrict_public_buckets().unwrap_or(false)
                    }).unwrap_or(false);
                    if all_blocked { "All Blocked" } else if some_blocked { "Partial" } else { "None" }.to_string()
                }
                Err(_) => "Not Configured".to_string(),
            };

            // ── Bucket policy ─────────────────────────────────────────────────
            let (has_policy, policy_allows_public, tls_enforced) = match self.client
                .get_bucket_policy()
                .bucket(&bucket_name)
                .send()
                .await
            {
                Ok(resp) => {
                    let policy = resp.policy().unwrap_or("").to_string();
                    if policy.is_empty() {
                        ("No".to_string(), "No".to_string(), "No".to_string())
                    } else {
                        let allows_public = if policy.contains("\"Principal\":\"*\"")
                            || policy.contains("\"Principal\":{\"AWS\":\"*\"}")
                        {
                            "Yes"
                        } else {
                            "No"
                        };

                        // TLS enforcement: look for Deny + aws:SecureTransport: false
                        let tls = check_tls_enforced(&policy);

                        ("Yes".to_string(), allows_public.to_string(), tls)
                    }
                }
                Err(e) => {
                    let msg = format!("{e}");
                    if msg.contains("NoSuchBucketPolicy") || msg.contains("no such bucket policy") {
                        ("No".to_string(), "No".to_string(), "No".to_string())
                    } else {
                        eprintln!("  WARN: S3 get_bucket_policy {bucket_name}: {e:#}");
                        ("Unknown".to_string(), "Unknown".to_string(), "Unknown".to_string())
                    }
                }
            };

            // ── Default encryption ────────────────────────────────────────────
            let encryption = match self.client
                .get_bucket_encryption()
                .bucket(&bucket_name)
                .send()
                .await
            {
                Ok(resp) => {
                    resp.server_side_encryption_configuration()
                        .and_then(|c| c.rules().first())
                        .and_then(|r| r.apply_server_side_encryption_by_default())
                        .map(|d| d.sse_algorithm().as_str().to_string())
                        .unwrap_or_else(|| "None".to_string())
                }
                Err(_) => "None".to_string(),
            };

            rows.push(vec![
                bucket_name,
                public_access_block,
                tls_enforced,
                has_policy,
                policy_allows_public,
                encryption,
            ]);
        }

        Ok(rows)
    }
}

/// Check if the bucket policy enforces TLS.
/// A policy enforces TLS if there is a statement with Effect=Deny and
/// Condition.Bool."aws:SecureTransport" = "false".
fn check_tls_enforced(policy: &str) -> String {
    let parsed: serde_json::Value = match serde_json::from_str(policy) {
        Ok(v) => v,
        Err(_) => return "Unknown".to_string(),
    };

    if let Some(stmts) = parsed.get("Statement").and_then(|s| s.as_array()) {
        for stmt in stmts {
            let effect = stmt.get("Effect").and_then(|e| e.as_str()).unwrap_or("");
            if !effect.eq_ignore_ascii_case("Deny") {
                continue;
            }
            // Look for aws:SecureTransport: false in conditions
            if let Some(cond) = stmt.get("Condition") {
                let secure_transport = cond.get("Bool")
                    .and_then(|b| b.get("aws:SecureTransport"))
                    .or_else(|| cond.get("StringEquals").and_then(|s| s.get("aws:SecureTransport")));

                if let Some(val) = secure_transport {
                    let val_str = val.as_str().unwrap_or("");
                    let val_bool = val.as_bool().map(|b| b.to_string()).unwrap_or_default();
                    if val_str == "false" || val_bool == "false" {
                        return "Yes".to_string();
                    }
                }
            }
        }
    }

    "No".to_string()
}
