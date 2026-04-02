use anyhow::{Context, Result};
use async_trait::async_trait;
use aws_sdk_cloudtrail::Client as CtClient;
use aws_sdk_cloudtrail::types::{LookupAttribute, LookupAttributeKey};

use crate::evidence::{CsvCollector, JsonCollector};

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

fn fmt_dt(dt: &aws_sdk_cloudtrail::primitives::DateTime) -> String {
    chrono::DateTime::<chrono::Utc>::from_timestamp(dt.secs(), 0)
        .map(|c| c.to_rfc3339())
        .unwrap_or_default()
}

// ══════════════════════════════════════════════════════════════════════════════
// 1. CloudTrail Configuration Change Events (Filtered)
// ══════════════════════════════════════════════════════════════════════════════

pub struct CloudTrailConfigChangesCollector {
    client: CtClient,
}

impl CloudTrailConfigChangesCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self { client: CtClient::new(config) }
    }
}

#[async_trait]
impl JsonCollector for CloudTrailConfigChangesCollector {
    fn name(&self) -> &str { "CloudTrail Configuration Change Events" }
    fn filename_prefix(&self) -> &str { "CloudTrail_Config_Changes" }

    async fn collect_records(&self, _account_id: &str, _region: &str) -> Result<Vec<serde_json::Value>> {
        let mut records = Vec::new();
        let end_secs   = now_secs();
        let start_secs = end_secs - 90 * 24 * 3600;
        let start_dt = aws_sdk_cloudtrail::primitives::DateTime::from_secs(start_secs);
        let end_dt   = aws_sdk_cloudtrail::primitives::DateTime::from_secs(end_secs);

        let config_events: &[&str] = &[
            "PutConfigRule",
            "DeleteConfigRule",
            "StopConfigurationRecorder",
            "StartConfigurationRecorder",
            "PutConfigurationRecorder",
            "DeleteConfigurationRecorder",
            "PutDeliveryChannel",
            "DeleteDeliveryChannel",
        ];

        for event_name in config_events {
            let attr = match LookupAttribute::builder()
                .attribute_key(LookupAttributeKey::EventName)
                .attribute_value(*event_name)
                .build()
                .context("build LookupAttribute")
            {
                Ok(a) => a,
                Err(_) => continue,
            };

            let mut next_token: Option<String> = None;
            let mut pages = 0;
            loop {
                if pages >= 4 { break; }
                let mut req = self.client
                    .lookup_events()
                    .lookup_attributes(attr.clone())
                    .start_time(start_dt.clone())
                    .end_time(end_dt.clone())
                    .max_results(50);
                if let Some(ref t) = next_token {
                    req = req.next_token(t);
                }
                let resp = match req.send().await {
                    Ok(r) => r,
                    Err(e) => {
                        eprintln!("  WARN: CloudTrail lookup_events [{event_name}]: {e:#}");
                        break;
                    }
                };
                for event in resp.events() {
                    let raw: serde_json::Value = event.cloud_trail_event()
                        .and_then(|s| serde_json::from_str(s).ok())
                        .unwrap_or_default();
                    let event_time = event.event_time().map(fmt_dt).unwrap_or_default();
                    let username   = event.username().unwrap_or("").to_string();
                    let source_ip  = raw.get("sourceIPAddress")
                        .and_then(|v| v.as_str()).unwrap_or("").to_string();
                    let req_params = raw.get("requestParameters").cloned()
                        .unwrap_or(serde_json::Value::Null);
                    let resp_elems = raw.get("responseElements").cloned()
                        .unwrap_or(serde_json::Value::Null);
                    records.push(serde_json::json!({
                        "event_name":           event_name,
                        "event_time":           event_time,
                        "user_identity":        username,
                        "source_ip":            source_ip,
                        "request_parameters":   req_params,
                        "response_elements":    resp_elems,
                    }));
                }
                pages += 1;
                next_token = resp.next_token().map(|s| s.to_string());
                if next_token.is_none() { break; }
                tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            }
        }

        Ok(records)
    }
}

// ══════════════════════════════════════════════════════════════════════════════
// 2. CloudTrail IAM Changes (high-risk)
// ══════════════════════════════════════════════════════════════════════════════

pub struct CloudTrailIamChangesCollector {
    client: CtClient,
}

impl CloudTrailIamChangesCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self { client: CtClient::new(config) }
    }
}

#[async_trait]
impl CsvCollector for CloudTrailIamChangesCollector {
    fn name(&self) -> &str { "CloudTrail IAM Changes (High-Risk)" }
    fn filename_prefix(&self) -> &str { "CloudTrail_IAM_Changes" }
    fn headers(&self) -> &'static [&'static str] {
        &["Event Name", "User Identity", "Event Time", "Request Parameters"]
    }

    async fn collect_rows(&self, _account_id: &str, _region: &str) -> Result<Vec<Vec<String>>> {
        let mut rows = Vec::new();
        let end_secs   = now_secs();
        let start_secs = end_secs - 90 * 24 * 3600;
        let start_dt = aws_sdk_cloudtrail::primitives::DateTime::from_secs(start_secs);
        let end_dt   = aws_sdk_cloudtrail::primitives::DateTime::from_secs(end_secs);

        let iam_events: &[&str] = &[
            "CreateUser",
            "DeleteUser",
            "AttachUserPolicy",
            "DetachUserPolicy",
            "PutUserPolicy",
            "CreateRole",
            "DeleteRole",
            "AttachRolePolicy",
            "DetachRolePolicy",
            "PutRolePolicy",
            "CreateAccessKey",
            "DeleteAccessKey",
            "UpdateAccessKey",
            "AssumeRole",
            "CreatePolicy",
            "DeletePolicy",
            "CreateGroup",
            "AttachGroupPolicy",
            "DetachGroupPolicy",
        ];

        for event_name in iam_events {
            let attr = match LookupAttribute::builder()
                .attribute_key(LookupAttributeKey::EventName)
                .attribute_value(*event_name)
                .build()
                .context("build LookupAttribute")
            {
                Ok(a) => a,
                Err(_) => continue,
            };

            let mut next_token: Option<String> = None;
            let mut pages = 0;
            loop {
                if pages >= 4 { break; }
                let mut req = self.client
                    .lookup_events()
                    .lookup_attributes(attr.clone())
                    .start_time(start_dt.clone())
                    .end_time(end_dt.clone())
                    .max_results(50);
                if let Some(ref t) = next_token {
                    req = req.next_token(t);
                }
                let resp = match req.send().await {
                    Ok(r) => r,
                    Err(e) => {
                        eprintln!("  WARN: CloudTrail lookup_events [{event_name}]: {e:#}");
                        break;
                    }
                };
                for event in resp.events() {
                    let raw: serde_json::Value = event.cloud_trail_event()
                        .and_then(|s| serde_json::from_str(s).ok())
                        .unwrap_or_default();
                    let event_time = event.event_time().map(fmt_dt).unwrap_or_default();
                    let username   = event.username().unwrap_or("").to_string();
                    let req_params = raw.get("requestParameters").map(|v| v.to_string()).unwrap_or_default();
                    rows.push(vec![event_name.to_string(), username, event_time, req_params]);
                }
                pages += 1;
                next_token = resp.next_token().map(|s| s.to_string());
                if next_token.is_none() { break; }
                tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            }
        }

        Ok(rows)
    }
}
