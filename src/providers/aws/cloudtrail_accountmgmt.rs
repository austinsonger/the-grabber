use anyhow::{Context, Result};
use async_trait::async_trait;
use aws_sdk_cloudtrail::types::{LookupAttribute, LookupAttributeKey};
use aws_sdk_cloudtrail::Client as CtClient;

use crate::evidence::CsvCollector;

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
// CloudTrail Account Management Events
// ══════════════════════════════════════════════════════════════════════════════

pub struct CloudTrailAccountMgmtCollector {
    client: CtClient,
}

impl CloudTrailAccountMgmtCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self {
            client: CtClient::new(config),
        }
    }
}

#[async_trait]
impl CsvCollector for CloudTrailAccountMgmtCollector {
    fn name(&self) -> &str {
        "CloudTrail Account Management Events"
    }
    fn filename_prefix(&self) -> &str {
        "CloudTrail_AccountMgmt_Events"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Event Name",
            "Event Time",
            "User Identity",
            "Source IP",
            "Target User",
            "Request Parameters",
            "Response Elements",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let mut rows = Vec::new();
        let (start_secs, end_secs) = dates.unwrap_or_else(|| {
            let end = now_secs();
            (end - 90 * 24 * 3600, end)
        });
        let start_dt = aws_sdk_cloudtrail::primitives::DateTime::from_secs(start_secs);
        let end_dt = aws_sdk_cloudtrail::primitives::DateTime::from_secs(end_secs);

        let acct_events: &[&str] = &[
            "CreateUser",
            "DeleteUser",
            "UpdateUser",
            "EnableMFADevice",
            "DeactivateMFADevice",
            "AttachUserPolicy",
            "DetachUserPolicy",
            "AddUserToGroup",
            "RemoveUserFromGroup",
            "CreateAccessKey",
            "DeleteAccessKey",
            "UpdateAccessKey",
        ];

        for event_name in acct_events {
            let attr = match LookupAttribute::builder()
                .attribute_key(LookupAttributeKey::EventName)
                .attribute_value(*event_name)
                .build()
                .context("build LookupAttribute")
            {
                Ok(a) => a,
                Err(_) => continue,
            };

            let mut paginator = self
                .client
                .lookup_events()
                .lookup_attributes(attr)
                .start_time(start_dt)
                .end_time(end_dt)
                .into_paginator()
                .send();

            while let Some(page) = paginator.next().await {
                let resp = match page {
                    Ok(r) => r,
                    Err(e) => {
                        eprintln!("  WARN: CloudTrail lookup_events [{event_name}]: {e:#}");
                        break;
                    }
                };
                for event in resp.events() {
                    let raw: serde_json::Value = event
                        .cloud_trail_event()
                        .and_then(|s| serde_json::from_str(s).ok())
                        .unwrap_or_default();
                    let event_time = event.event_time().map(fmt_dt).unwrap_or_default();
                    let user_identity = raw
                        .get("userIdentity")
                        .map(|v| v.to_string())
                        .unwrap_or_else(|| event.username().unwrap_or("").to_string());
                    let source_ip = raw
                        .get("sourceIPAddress")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();
                    let target_user = raw
                        .get("requestParameters")
                        .and_then(|p| p.get("userName"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();
                    let req_params = raw
                        .get("requestParameters")
                        .map(|v| v.to_string())
                        .unwrap_or_default();
                    let resp_elems = raw
                        .get("responseElements")
                        .map(|v| v.to_string())
                        .unwrap_or_default();
                    rows.push(vec![
                        event_name.to_string(),
                        event_time,
                        user_identity,
                        source_ip,
                        target_user,
                        req_params,
                        resp_elems,
                    ]);
                }
            }
        }

        Ok(rows)
    }
}
