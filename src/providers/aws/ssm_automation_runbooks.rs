//! Lists SSM Automation documents (customer-owned) so auditors can see
//! automated remediation runbooks tied to security anomalies for
//! FedRAMP SI-06d.

use anyhow::{Context, Result};
use async_trait::async_trait;
use aws_sdk_ssm::{types::DocumentFilter, Client as SsmClient};

use crate::evidence::CsvCollector;

pub struct SsmAutomationRunbooksCollector {
    client: SsmClient,
}

impl SsmAutomationRunbooksCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self {
            client: SsmClient::new(config),
        }
    }
}

#[async_trait]
impl CsvCollector for SsmAutomationRunbooksCollector {
    fn name(&self) -> &str {
        "SSM Automation Response Runbooks"
    }
    fn filename_prefix(&self) -> &str {
        "SSM_Automation_Response_Runbooks"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Document Name",
            "Owner",
            "Document Type",
            "Document Format",
            "Schema Version",
            "Target Type",
            "Tags",
            "Created Date",
            "Region",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let mut rows: Vec<Vec<String>> = Vec::new();
        let mut next: Option<String> = None;
        loop {
            let filter = DocumentFilter::builder()
                .key("DocumentType".into())
                .value("Automation")
                .build()
                .context("build DocumentFilter")?;
            let mut req = self.client.list_documents().document_filter_list(filter);
            if let Some(t) = next.as_ref() {
                req = req.next_token(t);
            }
            let resp = req.send().await.context("ssm:ListDocuments Automation")?;
            for d in resp.document_identifiers() {
                let tags = d
                    .tags()
                    .iter()
                    .map(|t| format!("{}={}", t.key(), t.value()))
                    .collect::<Vec<_>>()
                    .join(";");
                rows.push(vec![
                    d.name().unwrap_or("").to_string(),
                    d.owner().unwrap_or("").to_string(),
                    d.document_type()
                        .map(|t| t.as_str().to_string())
                        .unwrap_or_default(),
                    d.document_format()
                        .map(|t| t.as_str().to_string())
                        .unwrap_or_default(),
                    d.schema_version().unwrap_or("").to_string(),
                    d.target_type().unwrap_or("").to_string(),
                    tags,
                    d.created_date().map(|t| t.to_string()).unwrap_or_default(),
                    region.to_string(),
                ]);
            }
            next = resp.next_token().map(|s| s.to_string());
            if next.is_none() {
                break;
            }
        }
        Ok(rows)
    }
}
