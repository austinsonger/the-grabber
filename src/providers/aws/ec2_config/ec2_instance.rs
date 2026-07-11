use anyhow::{Context, Result};
use async_trait::async_trait;
use aws_sdk_ec2::Client as Ec2Client;

use crate::evidence::CsvCollector;

pub struct Ec2InstanceConfigCollector {
    client: Ec2Client,
}

impl Ec2InstanceConfigCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self {
            client: Ec2Client::new(config),
        }
    }
}

#[async_trait]
impl CsvCollector for Ec2InstanceConfigCollector {
    fn name(&self) -> &str {
        "EC2 Instance Configuration"
    }
    fn filename_prefix(&self) -> &str {
        "EC2_Config"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Instance ID",
            "Image ID",
            "Instance Type",
            "State",
            "IMDS Version",
            "IAM Instance Profile",
            "Block Devices",
            "Monitoring",
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
            let mut req = self.client.describe_instances();
            if let Some(ref t) = next_token {
                req = req.next_token(t);
            }
            let resp = req.send().await.context("EC2 describe_instances")?;

            for reservation in resp.reservations() {
                for inst in reservation.instances() {
                    let instance_id = inst.instance_id().unwrap_or("").to_string();
                    let image_id = inst.image_id().unwrap_or("").to_string();
                    let inst_type = inst
                        .instance_type()
                        .map(|t| t.as_str().to_string())
                        .unwrap_or_default();
                    let state = inst
                        .state()
                        .and_then(|s| s.name())
                        .map(|s| s.as_str().to_string())
                        .unwrap_or_default();

                    // IMDSv2 enforcement
                    let imds = inst
                        .metadata_options()
                        .and_then(|m| m.http_tokens())
                        .map(|t| t.as_str().to_string())
                        .unwrap_or_else(|| "optional".to_string());

                    // IAM instance profile
                    let iam_profile = inst
                        .iam_instance_profile()
                        .and_then(|p| p.arn())
                        .unwrap_or("")
                        .to_string();

                    // Block device mappings summary
                    let block_devs: Vec<String> = inst
                        .block_device_mappings()
                        .iter()
                        .map(|bd| {
                            let dev = bd.device_name().unwrap_or("");
                            let vol = bd.ebs().and_then(|e| e.volume_id()).unwrap_or("");
                            let del = bd
                                .ebs()
                                .and_then(|e| e.delete_on_termination())
                                .unwrap_or(true);
                            format!("{dev}:{vol}(delete={del})")
                        })
                        .collect();

                    let monitoring = inst
                        .monitoring()
                        .and_then(|m| m.state())
                        .map(|s| s.as_str().to_string())
                        .unwrap_or_default();

                    rows.push(vec![
                        instance_id,
                        image_id,
                        inst_type,
                        state,
                        imds,
                        iam_profile,
                        block_devs.join("; "),
                        monitoring,
                    ]);
                }
            }

            next_token = resp.next_token().map(|s| s.to_string());
            if next_token.is_none() {
                break;
            }
        }

        Ok(rows)
    }
}
