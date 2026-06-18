use anyhow::Result;
use async_trait::async_trait;
use aws_sdk_iot::primitives::DateTime as IotDateTime;
use aws_sdk_iot::Client as IotClient;

use crate::evidence::CsvCollector;

// ══════════════════════════════════════════════════════════════════════════════
// IoT Device Defender — audit findings over the last 90 days.
// ══════════════════════════════════════════════════════════════════════════════

pub struct IotDeviceDefenderCollector {
    client: IotClient,
}

impl IotDeviceDefenderCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self {
            client: IotClient::new(config),
        }
    }
}

fn is_benign(err: &str) -> bool {
    err.contains("AccessDenied")
        || err.contains("AccessDeniedException")
        || err.contains("ResourceNotFoundException")
        || err.contains("UnauthorizedOperation")
        || err.contains("not available")
        || err.contains("UnknownEndpoint")
        || err.contains("dispatch failure")
        || err.contains("InvalidAction")
        || err.contains("OptInRequired")
        || err.contains("not enabled")
        || err.contains("NotFoundException")
        || err.contains("InvalidRequestException")
}

fn secs_to_rfc3339(secs: i64) -> String {
    chrono::DateTime::<chrono::Utc>::from_timestamp(secs, 0)
        .map(|c| c.to_rfc3339())
        .unwrap_or_default()
}

#[async_trait]
impl CsvCollector for IotDeviceDefenderCollector {
    fn name(&self) -> &str {
        "IoT Device Defender Findings"
    }
    fn filename_prefix(&self) -> &str {
        "IoT_DeviceDefender_Findings"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Finding ID",
            "Check Name",
            "Severity",
            "Task Time",
            "Resource Type",
            "Resource Identifier",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let mut rows: Vec<Vec<String>> = Vec::new();

        let now = chrono::Utc::now().timestamp();
        let start = now - 90 * 24 * 60 * 60;

        let mut paginator = self
            .client
            .list_audit_findings()
            .start_time(IotDateTime::from_secs(start))
            .end_time(IotDateTime::from_secs(now))
            .into_paginator()
            .send();

        while let Some(page) = paginator.next().await {
            let resp = match page {
                Ok(r) => r,
                Err(e) => {
                    let msg = format!("{e:#}");
                    if is_benign(&msg) {
                        return Ok(rows);
                    }
                    eprintln!("  WARN: IoT list_audit_findings: {msg}");
                    break;
                }
            };
            for f in resp.findings() {
                let id = f.finding_id().unwrap_or("").to_string();
                let check = f.check_name().unwrap_or("").to_string();
                let severity = f
                    .severity()
                    .map(|s| s.as_str().to_string())
                    .unwrap_or_default();
                let task_time = f
                    .task_start_time()
                    .map(|d| secs_to_rfc3339(d.secs()))
                    .unwrap_or_default();

                let (resource_type, resource_id) = match f.non_compliant_resource() {
                    Some(nc) => {
                        let rt = nc
                            .resource_type()
                            .map(|t| t.as_str().to_string())
                            .unwrap_or_default();
                        let rid = nc
                            .resource_identifier()
                            .and_then(|r| r.policy_version_identifier())
                            .and_then(|p| p.policy_name())
                            .unwrap_or("")
                            .to_string();
                        (rt, rid)
                    }
                    None => (String::new(), String::new()),
                };

                if id.is_empty() && check.is_empty() {
                    continue;
                }

                rows.push(vec![
                    id,
                    check,
                    severity,
                    task_time,
                    resource_type,
                    resource_id,
                ]);
            }
        }

        Ok(rows)
    }
}
