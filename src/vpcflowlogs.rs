use anyhow::{Context, Result};
use async_trait::async_trait;
use aws_sdk_ec2::Client as Ec2Client;

use crate::evidence::CsvCollector;

pub struct VpcFlowLogCollector {
    client: Ec2Client,
}

impl VpcFlowLogCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self { client: Ec2Client::new(config) }
    }
}

#[async_trait]
impl CsvCollector for VpcFlowLogCollector {
    fn name(&self) -> &str { "VPC Flow Logging" }
    fn filename_prefix(&self) -> &str { "VPC_Flow_Logging" }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "VPC ID",
            "VPC Flow Log Name",
            "VPC Flow Log ID",
            "Filter",
            "Destination",
            "Destination Log Group",
            "IAM Role",
            "Status",
            "Log Line Format",
        ]
    }

    async fn collect_rows(&self, _account_id: &str, _region: &str) -> Result<Vec<Vec<String>>> {
        let mut rows = Vec::new();
        let mut next_token: Option<String> = None;

        loop {
            let mut req = self.client.describe_flow_logs();
            if let Some(ref t) = next_token {
                req = req.next_token(t);
            }
            let resp = req.send().await.context("EC2 describe_flow_logs")?;

            for fl in resp.flow_logs() {
                let vpc_id  = fl.resource_id().unwrap_or("").to_string();
                let log_id  = fl.flow_log_id().unwrap_or("").to_string();
                let name    = fl.tags().iter()
                    .find(|t| t.key() == Some("Name"))
                    .and_then(|t| t.value())
                    .unwrap_or("")
                    .to_string();
                let filter  = fl.traffic_type()
                    .map(|t| t.as_str().to_string())
                    .unwrap_or_default();
                let dest_type = fl.log_destination_type()
                    .map(|t| t.as_str().to_string())
                    .unwrap_or_default();
                let dest_log_group = fl.log_group_name()
                    .map(|s| s.to_string())
                    .or_else(|| fl.log_destination().map(|s| s.to_string()))
                    .unwrap_or_default();
                let iam_role = fl.deliver_logs_permission_arn().unwrap_or("").to_string();
                let status   = fl.flow_log_status().unwrap_or("").to_string();
                let format   = fl.log_format().unwrap_or("").to_string();

                rows.push(vec![
                    vpc_id, name, log_id, filter,
                    dest_type, dest_log_group, iam_role, status, format,
                ]);
            }

            next_token = resp.next_token().map(|s| s.to_string());
            if next_token.is_none() { break; }
        }

        Ok(rows)
    }
}
