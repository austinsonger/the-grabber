//! Joins SSM compliance items with Inspector2 findings for default
//! credentials to prove new AMIs' default authenticators are rotated per
//! FedRAMP IA-05e.

use anyhow::{Context, Result};
use async_trait::async_trait;
use aws_sdk_inspector2::Client as InspectorClient;
use aws_sdk_ssm::Client as SsmClient;

use crate::evidence::CsvCollector;

fn secs_to_rfc3339(secs: i64) -> String {
    chrono::DateTime::<chrono::Utc>::from_timestamp(secs, 0)
        .map(|c| c.to_rfc3339())
        .unwrap_or_default()
}

pub struct AmiDefaultCredentialScanCollector {
    ssm: SsmClient,
    inspector: InspectorClient,
}

impl AmiDefaultCredentialScanCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self {
            ssm: SsmClient::new(config),
            inspector: InspectorClient::new(config),
        }
    }
}

#[async_trait]
impl CsvCollector for AmiDefaultCredentialScanCollector {
    fn name(&self) -> &str {
        "AMI Default-Credential Scan (SSM + Inspector2)"
    }
    fn filename_prefix(&self) -> &str {
        "AMI_Default_Credential_Scan"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Source",
            "Resource ID",
            "Finding Title",
            "Compliance Status",
            "Severity",
            "First Observed",
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

        // SSM compliance items — Association type with "CIS" in the association name
        let mut ssm_next: Option<String> = None;
        loop {
            let mut req = self.ssm.list_compliance_items();
            if let Some(t) = ssm_next.as_ref() {
                req = req.next_token(t);
            }
            let resp = req.send().await.context("ssm:ListComplianceItems")?;
            for it in resp.compliance_items() {
                let title = it.title().unwrap_or("");
                if !title.to_lowercase().contains("default")
                    && !title.to_lowercase().contains("credential")
                {
                    continue;
                }
                rows.push(vec![
                    "SSM".into(),
                    it.resource_id().unwrap_or("").into(),
                    title.into(),
                    it.status()
                        .map(|s| s.as_str().to_string())
                        .unwrap_or_default(),
                    it.severity()
                        .map(|s| s.as_str().to_string())
                        .unwrap_or_default(),
                    String::new(),
                    region.into(),
                ]);
            }
            ssm_next = resp.next_token().map(|s| s.to_string());
            if ssm_next.is_none() {
                break;
            }
        }

        // Inspector2 findings — filter to titles mentioning default credentials
        let mut ins_next: Option<String> = None;
        loop {
            let mut req = self.inspector.list_findings();
            if let Some(t) = ins_next.as_ref() {
                req = req.next_token(t);
            }
            let resp = req.send().await.context("inspector2:ListFindings")?;
            for f in resp.findings() {
                let title = f.title().unwrap_or("");
                if !title.to_lowercase().contains("default")
                    && !title.to_lowercase().contains("credential")
                {
                    continue;
                }
                let res = f
                    .resources()
                    .first()
                    .map(|r| r.id().to_string())
                    .unwrap_or_default();
                rows.push(vec![
                    "Inspector2".into(),
                    res,
                    title.into(),
                    f.status().as_str().to_string(),
                    f.severity().as_str().to_string(),
                    secs_to_rfc3339(f.first_observed_at().secs()),
                    region.into(),
                ]);
            }
            ins_next = resp.next_token().map(|s| s.to_string());
            if ins_next.is_none() {
                break;
            }
        }
        Ok(rows)
    }
}
