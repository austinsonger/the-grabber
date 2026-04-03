use anyhow::Result;
use async_trait::async_trait;
use aws_sdk_inspector2::Client as Inspector2Client;

use crate::evidence::CsvCollector;

pub struct InspectorConfigCollector {
    client: Inspector2Client,
}

impl InspectorConfigCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self { client: Inspector2Client::new(config) }
    }
}

#[async_trait]
impl CsvCollector for InspectorConfigCollector {
    fn name(&self) -> &str { "Inspector2 Configuration" }
    fn filename_prefix(&self) -> &str { "Inspector_Config" }
    fn headers(&self) -> &'static [&'static str] {
        &["Resource Type", "Scan Status", "Scan Type", "EC2 Status", "ECR Status", "Lambda Status"]
    }

    async fn collect_rows(&self, _account_id: &str, _region: &str, _dates: Option<(i64, i64)>) -> Result<Vec<Vec<String>>> {
        let resp = match self.client.get_configuration().send().await {
            Ok(r) => r,
            Err(e) => {
                eprintln!("  WARN: Inspector2 get_configuration (not enabled?): {e:#}");
                return Ok(vec![]);
            }
        };

        let mut rows = Vec::new();

        let ec2_status = resp.ec2_configuration()
            .and_then(|c| c.scan_mode_state())
            .map(|s| format!("{s:?}"))
            .unwrap_or_else(|| "Not Configured".to_string());

        let ecr_status = resp.ecr_configuration()
            .and_then(|c| c.rescan_duration_state())
            .map(|d| format!("{d:?}"))
            .unwrap_or_else(|| "Not Configured".to_string());

        let lambda_status = resp.ec2_configuration()
            .and_then(|c| c.scan_mode_state())
            .map(|s| format!("EC2:{s:?}"))
            .unwrap_or_else(|| "Not Configured".to_string());

        rows.push(vec![
            "All".to_string(),
            "Configured".to_string(),
            "Vulnerability Scan".to_string(),
            ec2_status,
            ecr_status,
            lambda_status,
        ]);

        Ok(rows)
    }
}
