use anyhow::Result;
use async_trait::async_trait;
use aws_sdk_databasemigration::Client as DmsClient;

use crate::evidence::CsvCollector;

// ══════════════════════════════════════════════════════════════════════════════
// DMS Replication Collector — instances, endpoints, and tasks.
// ══════════════════════════════════════════════════════════════════════════════

pub struct DmsCollector {
    client: DmsClient,
}

impl DmsCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self {
            client: DmsClient::new(config),
        }
    }
}

fn is_benign(err: &str) -> bool {
    err.contains("AccessDenied")
        || err.contains("AccessDeniedException")
        || err.contains("UnauthorizedOperation")
        || err.contains("not available")
        || err.contains("UnknownEndpoint")
        || err.contains("dispatch failure")
        || err.contains("InvalidAction")
        || err.contains("OptInRequired")
}

#[async_trait]
impl CsvCollector for DmsCollector {
    fn name(&self) -> &str {
        "DMS Replication"
    }
    fn filename_prefix(&self) -> &str {
        "DMS_Replication"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Type",
            "Identifier",
            "Class / Engine",
            "Status",
            "Public / Multi-AZ",
            "KMS Key / Last Failure",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let mut rows: Vec<Vec<String>> = Vec::new();

        // Replication instances.
        let mut paginator = self
            .client
            .describe_replication_instances()
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
                    eprintln!("  WARN: DMS describe_replication_instances: {msg}");
                    break;
                }
            };
            for inst in resp.replication_instances() {
                let id = inst
                    .replication_instance_identifier()
                    .unwrap_or("")
                    .to_string();
                let class = inst.replication_instance_class().unwrap_or("").to_string();
                let status = inst.replication_instance_status().unwrap_or("").to_string();
                let pub_az = format!(
                    "public={} / multi_az={}",
                    inst.publicly_accessible(),
                    inst.multi_az()
                );
                let kms = inst.kms_key_id().unwrap_or("").to_string();
                rows.push(vec!["Instance".to_string(), id, class, status, pub_az, kms]);
            }
        }

        // Endpoints.
        let mut paginator = self.client.describe_endpoints().into_paginator().send();
        while let Some(page) = paginator.next().await {
            let resp = match page {
                Ok(r) => r,
                Err(e) => {
                    let msg = format!("{e:#}");
                    if is_benign(&msg) {
                        return Ok(rows);
                    }
                    eprintln!("  WARN: DMS describe_endpoints: {msg}");
                    break;
                }
            };
            for ep in resp.endpoints() {
                let id = ep.endpoint_identifier().unwrap_or("").to_string();
                let etype = ep
                    .endpoint_type()
                    .map(|t| t.as_str().to_string())
                    .unwrap_or_default();
                let engine = ep.engine_name().unwrap_or("").to_string();
                let status = ep.status().unwrap_or("").to_string();
                rows.push(vec![
                    "Endpoint".to_string(),
                    id,
                    engine,
                    status,
                    etype,
                    String::new(),
                ]);
            }
        }

        // Replication tasks.
        let mut paginator = self
            .client
            .describe_replication_tasks()
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
                    eprintln!("  WARN: DMS describe_replication_tasks: {msg}");
                    break;
                }
            };
            for task in resp.replication_tasks() {
                let id = task.replication_task_identifier().unwrap_or("").to_string();
                let mtype = task
                    .migration_type()
                    .map(|m| m.as_str().to_string())
                    .unwrap_or_default();
                let status = task.status().unwrap_or("").to_string();
                let failure = task.last_failure_message().unwrap_or("").to_string();
                rows.push(vec![
                    "Task".to_string(),
                    id,
                    mtype,
                    status,
                    String::new(),
                    failure,
                ]);
            }
        }

        Ok(rows)
    }
}
