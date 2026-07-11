//! GCP Cloud Audit Logs evidence collector — time-windowed equivalent to AWS CloudTrail.

use anyhow::Context;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde_json::{json, Value};

use crate::evidence::{CollectParams, EvidenceCollector, EvidenceRecord, EvidenceSource};
use crate::providers::gcp::client::GcpClient;

pub struct CloudAuditLogsCollector {
    client:     GcpClient,
    project_id: String,
}

impl CloudAuditLogsCollector {
    pub fn new(client: GcpClient, project_id: impl Into<String>) -> Self {
        Self { client, project_id: project_id.into() }
    }

    fn source(&self) -> EvidenceSource {
        EvidenceSource::GcpAuditLog
    }
}

#[async_trait]
impl EvidenceCollector for CloudAuditLogsCollector {
    fn name(&self) -> &str { "GCP Cloud Audit Logs" }
    fn filename_prefix(&self) -> &str { "GCP_Cloud_Audit_Logs" }

    async fn collect(&self, params: &CollectParams) -> anyhow::Result<Vec<EvidenceRecord>> {
        let start: DateTime<Utc> = params.start_time;
        let end: DateTime<Utc> = params.end_time;

        let filter = format!(
            r#"logName=~"cloudaudit.googleapis.com" AND timestamp >= "{start}" AND timestamp <= "{end}""#
        );

        let body = json!({
            "resourceNames": [format!("projects/{}", self.project_id)],
            "filter": filter,
            "orderBy": "timestamp desc",
            "pageSize": 1000
        });

        let mut records = Vec::new();
        let mut page_token: Option<String> = None;

        loop {
            let mut req_body = body.clone();
            if let Some(tok) = &page_token {
                req_body["pageToken"] = Value::String(tok.clone());
            }

            let resp = self
                .client
                .post("https://logging.googleapis.com/v2/entries:list", &req_body)
                .await?;

            let status = resp.status();
            let resp_body: Value = resp
                .json()
                .await
                .context("Failed to parse Cloud Logging response")?;

            if !status.is_success() {
                let msg = resp_body
                    .get("error")
                    .and_then(|e| e.get("message"))
                    .and_then(|m| m.as_str())
                    .unwrap_or("unknown error");
                anyhow::bail!("Cloud Logging API error {status}: {msg}");
            }

            if let Some(entries) = resp_body.get("entries").and_then(|e| e.as_array()) {
                for entry in entries {
                    let timestamp = entry
                        .get("timestamp")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_owned();
                    let event_name = entry
                        .get("protoPayload")
                        .and_then(|p| p.get("methodName"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_owned();
                    records.push(EvidenceRecord {
                        source: self.source(),
                        timestamp,
                        event_name,
                        job_id: None,
                        plan_id: None,
                        resource_arn: None,
                        resource_type: None,
                        status: None,
                        completion_timestamp: None,
                        raw: if params.include_raw { Some(entry.clone()) } else { None },
                    });
                }
            }

            match resp_body.get("nextPageToken").and_then(|t| t.as_str()) {
                Some(tok) => page_token = Some(tok.to_owned()),
                None => break,
            }
        }

        Ok(records)
    }
}
