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
// CloudTrail Session Events
// ══════════════════════════════════════════════════════════════════════════════

pub struct CloudTrailSessionEventsCollector {
    client: CtClient,
}

impl CloudTrailSessionEventsCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self {
            client: CtClient::new(config),
        }
    }
}

#[async_trait]
impl CsvCollector for CloudTrailSessionEventsCollector {
    fn name(&self) -> &str {
        "CloudTrail Session Events"
    }
    fn filename_prefix(&self) -> &str {
        "CloudTrail_Session_Events"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Event Name",
            "Event Time",
            "User Identity",
            "Source IP",
            "User Agent",
            "MFA Used",
            "Success",
            "Error Message",
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

        let session_events: &[&str] = &[
            "ConsoleLogin",
            "AssumeRole",
            "AssumeRoleWithSAML",
            "AssumeRoleWithWebIdentity",
            "GetFederationToken",
            "StartSession",
            "SwitchRole",
        ];

        for event_name in session_events {
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
                    let user_agent = raw
                        .get("userAgent")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();

                    // MFA: check additionalEventData.MFAUsed first, then sessionContext attributes
                    let mfa_used = raw
                        .get("additionalEventData")
                        .and_then(|d| d.get("MFAUsed"))
                        .map(|v| match v {
                            serde_json::Value::String(s) => s.clone(),
                            other => other.to_string(),
                        })
                        .or_else(|| {
                            raw.get("userIdentity")
                                .and_then(|u| u.get("sessionContext"))
                                .and_then(|s| s.get("attributes"))
                                .and_then(|a| a.get("mfaAuthenticated"))
                                .map(|v| match v {
                                    serde_json::Value::String(s) => s.clone(),
                                    other => other.to_string(),
                                })
                        })
                        .unwrap_or_default();

                    let error_message = raw
                        .get("errorMessage")
                        .and_then(|v| v.as_str())
                        .or_else(|| raw.get("errorCode").and_then(|v| v.as_str()))
                        .unwrap_or("")
                        .to_string();
                    let success = if error_message.is_empty() {
                        "true".to_string()
                    } else {
                        "false".to_string()
                    };

                    rows.push(vec![
                        event_name.to_string(),
                        event_time,
                        user_identity,
                        source_ip,
                        user_agent,
                        mfa_used,
                        success,
                        error_message,
                    ]);
                }
            }
        }

        Ok(rows)
    }
}
