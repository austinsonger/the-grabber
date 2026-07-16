//! Lists SSM State Manager associations and Distributor packages that
//! implement application allow-listing; each association becomes one row so
//! auditors can see the deny-by-default posture for FedRAMP CM-07(02)/(05).

use anyhow::{Context, Result};
use async_trait::async_trait;
use aws_sdk_ssm::Client as SsmClient;

use crate::evidence::CsvCollector;

pub struct SsmApplicationAllowlistCollector {
    client: SsmClient,
}

impl SsmApplicationAllowlistCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self {
            client: SsmClient::new(config),
        }
    }
}

#[async_trait]
impl CsvCollector for SsmApplicationAllowlistCollector {
    fn name(&self) -> &str {
        "SSM Application Allowlist (State Manager + Distributor)"
    }
    fn filename_prefix(&self) -> &str {
        "SSM_Application_Allowlist"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Association ID",
            "Association Name",
            "Document Name",
            "Targets",
            "Schedule",
            "Last Execution Date",
            "Status",
            "Detailed Status",
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
            let mut req = self.client.list_associations();
            if let Some(t) = next.as_ref() {
                req = req.next_token(t);
            }
            let resp = req.send().await.context("ssm:ListAssociations")?;
            for a in resp.associations() {
                let doc = a.name().unwrap_or("");
                // Filter to associations that plausibly represent allow-listing:
                // Distributor packages typically have doc names starting with
                // "AWS-ConfigureAWSPackage" or contain "Allowlist"/"Applock" tokens.
                let is_allowlist = doc.contains("Distributor")
                    || doc.contains("ConfigureAWSPackage")
                    || doc.to_lowercase().contains("allowlist")
                    || doc.to_lowercase().contains("applock");
                if !is_allowlist {
                    continue;
                }
                let targets = a
                    .targets()
                    .iter()
                    .map(|t| {
                        format!(
                            "{}={}",
                            t.key().unwrap_or(""),
                            t.values().join("|")
                        )
                    })
                    .collect::<Vec<_>>()
                    .join(";");
                let status = a
                    .overview()
                    .and_then(|o| o.status())
                    .map(|s| s.to_string())
                    .unwrap_or_default();
                let detailed = a
                    .overview()
                    .and_then(|o| o.detailed_status())
                    .map(|s| s.to_string())
                    .unwrap_or_default();
                rows.push(vec![
                    a.association_id().unwrap_or("").into(),
                    a.association_name().unwrap_or("").into(),
                    doc.into(),
                    targets,
                    a.schedule_expression().unwrap_or("").into(),
                    a.last_execution_date()
                        .map(|dt| dt.to_string())
                        .unwrap_or_default(),
                    status,
                    detailed,
                    region.into(),
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
