use anyhow::{Context, Result};
use async_trait::async_trait;
use aws_sdk_ec2::Client as Ec2Client;

use crate::evidence::CsvCollector;

pub struct SecurityGroupConfigCollector {
    client: Ec2Client,
}

impl SecurityGroupConfigCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self {
            client: Ec2Client::new(config),
        }
    }
}

#[async_trait]
impl CsvCollector for SecurityGroupConfigCollector {
    fn name(&self) -> &str {
        "Security Group Configuration"
    }
    fn filename_prefix(&self) -> &str {
        "Security_Group_Config"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Group ID",
            "Name",
            "Description",
            "VPC ID",
            "Ingress Rules",
            "Egress Rules",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let mut rows = Vec::new();
        let mut next_token: Option<String> = None;

        loop {
            let mut req = self.client.describe_security_groups();
            if let Some(ref t) = next_token {
                req = req.next_token(t);
            }
            let resp = req.send().await.context("EC2 describe_security_groups")?;

            for sg in resp.security_groups() {
                let group_id = sg.group_id().unwrap_or("").to_string();
                let name = sg.group_name().unwrap_or("").to_string();
                let desc = sg.description().unwrap_or("").to_string();
                let vpc_id = sg.vpc_id().unwrap_or("").to_string();
                let ingress = super::fmt_ip_perm(sg.ip_permissions());
                let egress = super::fmt_ip_perm(sg.ip_permissions_egress());

                rows.push(vec![group_id, name, desc, vpc_id, ingress, egress]);
            }

            next_token = resp.next_token().map(|s| s.to_string());
            if next_token.is_none() {
                break;
            }
        }

        Ok(rows)
    }
}
