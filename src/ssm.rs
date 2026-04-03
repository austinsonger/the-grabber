use anyhow::{Context, Result};
use async_trait::async_trait;
use aws_sdk_ssm::Client as SsmClient;
use aws_sdk_ssm::types::ComplianceStringFilter;

use crate::evidence::CsvCollector;

fn fmt_ssm_dt(dt: &aws_sdk_ssm::primitives::DateTime) -> String {
    chrono::DateTime::<chrono::Utc>::from_timestamp(dt.secs(), 0)
        .map(|c| c.to_rfc3339())
        .unwrap_or_default()
}

// ══════════════════════════════════════════════════════════════════════════════
// 1. SSM Managed Instance Collector
// ══════════════════════════════════════════════════════════════════════════════

pub struct SsmManagedInstanceCollector {
    client: SsmClient,
}

impl SsmManagedInstanceCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self { client: SsmClient::new(config) }
    }
}

#[async_trait]
impl CsvCollector for SsmManagedInstanceCollector {
    fn name(&self) -> &str { "SSM Managed Instances" }
    fn filename_prefix(&self) -> &str { "SSM_ManagedInstances" }
    fn headers(&self) -> &'static [&'static str] {
        &["Instance ID", "Computer Name", "Platform", "SSM Agent Version", "Ping Status", "Last Ping"]
    }

    async fn collect_rows(&self, _account_id: &str, _region: &str, _dates: Option<(i64, i64)>) -> Result<Vec<Vec<String>>> {
        let mut rows = Vec::new();
        let mut next_token: Option<String> = None;

        loop {
            let mut req = self.client.describe_instance_information();
            if let Some(ref t) = next_token {
                req = req.next_token(t);
            }
            let resp = req.send().await.context("SSM describe_instance_information")?;

            for info in resp.instance_information_list() {
                let instance_id = info.instance_id().unwrap_or("").to_string();
                let computer_name = info.computer_name().unwrap_or("").to_string();
                let platform = info.platform_type()
                    .map(|p| p.as_str().to_string())
                    .unwrap_or_default();
                let agent_version = info.agent_version().unwrap_or("").to_string();
                let ping_status = info.ping_status()
                    .map(|p| p.as_str().to_string())
                    .unwrap_or_default();
                let last_ping = info.last_ping_date_time()
                    .map(fmt_ssm_dt)
                    .unwrap_or_default();

                rows.push(vec![
                    instance_id,
                    computer_name,
                    platform,
                    agent_version,
                    ping_status,
                    last_ping,
                ]);
            }

            next_token = resp.next_token().map(|s| s.to_string());
            if next_token.is_none() { break; }
        }

        Ok(rows)
    }
}

// ══════════════════════════════════════════════════════════════════════════════
// 2. SSM Patch Compliance Collector
// ══════════════════════════════════════════════════════════════════════════════

pub struct SsmPatchComplianceCollector {
    client: SsmClient,
}

impl SsmPatchComplianceCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self { client: SsmClient::new(config) }
    }
}

#[async_trait]
impl CsvCollector for SsmPatchComplianceCollector {
    fn name(&self) -> &str { "SSM Patch Compliance" }
    fn filename_prefix(&self) -> &str { "SSM_PatchCompliance" }
    fn headers(&self) -> &'static [&'static str] {
        &["Instance ID", "Resource Type", "Compliance Status", "Overall Severity", "Non Compliant Count"]
    }

    async fn collect_rows(&self, _account_id: &str, _region: &str, _dates: Option<(i64, i64)>) -> Result<Vec<Vec<String>>> {
        let mut rows = Vec::new();
        let mut next_token: Option<String> = None;

        let filter = ComplianceStringFilter::builder()
            .key("ComplianceType")
            .values("Patch")
            .build();

        loop {
            let mut req = self.client
                .list_resource_compliance_summaries()
                .filters(filter.clone());
            if let Some(ref t) = next_token {
                req = req.next_token(t);
            }
            let resp = match req.send().await {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("  WARN: SSM list_resource_compliance_summaries: {e:#}");
                    break;
                }
            };

            for item in resp.resource_compliance_summary_items() {
                let resource_id = item.resource_id().unwrap_or("").to_string();
                let resource_type = item.resource_type().unwrap_or("").to_string();
                let status = item.status()
                    .map(|s| s.as_str().to_string())
                    .unwrap_or_default();
                let severity = item.overall_severity()
                    .map(|s| s.as_str().to_string())
                    .unwrap_or_default();
                let non_compliant = item.non_compliant_summary()
                    .map(|s| s.non_compliant_count().to_string())
                    .unwrap_or_default();

                rows.push(vec![
                    resource_id,
                    resource_type,
                    status,
                    severity,
                    non_compliant,
                ]);
            }

            next_token = resp.next_token().map(|s| s.to_string());
            if next_token.is_none() { break; }
        }

        Ok(rows)
    }
}
