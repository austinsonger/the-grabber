use anyhow::{Context, Result};
use async_trait::async_trait;
use aws_sdk_ec2::Client as Ec2Client;
use std::collections::HashMap;

use crate::evidence::CsvCollector;

pub struct Ec2DetailedCollector {
    client: Ec2Client,
}

impl Ec2DetailedCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self { client: Ec2Client::new(config) }
    }
}

#[async_trait]
impl CsvCollector for Ec2DetailedCollector {
    fn name(&self) -> &str { "EC2 Instance Details" }
    fn filename_prefix(&self) -> &str { "EC2_Detailed" }
    fn headers(&self) -> &'static [&'static str] {
        &["Instance ID", "Instance Type", "AMI ID", "AMI Owner ID", "IMDS Version", "EBS Optimized", "Monitoring"]
    }

    async fn collect_rows(&self, _account_id: &str, _region: &str, _dates: Option<(i64, i64)>) -> Result<Vec<Vec<String>>> {
        let mut rows = Vec::new();

        // ── 1. Collect all instances ─────────────────────────────────────────
        struct InstanceInfo {
            instance_id: String,
            instance_type: String,
            ami_id: String,
            imds_version: String,
            ebs_optimized: String,
            monitoring: String,
        }

        let mut instances: Vec<InstanceInfo> = Vec::new();
        let mut ami_ids: std::collections::HashSet<String> = std::collections::HashSet::new();
        let mut next_token: Option<String> = None;

        loop {
            let mut req = self.client.describe_instances();
            if let Some(ref t) = next_token {
                req = req.next_token(t);
            }
            let resp = req.send().await.context("EC2 describe_instances")?;

            for reservation in resp.reservations() {
                for instance in reservation.instances() {
                    let instance_id = instance.instance_id().unwrap_or("").to_string();
                    let instance_type = instance.instance_type()
                        .map(|t| t.as_str().to_string())
                        .unwrap_or_default();
                    let ami_id = instance.image_id().unwrap_or("").to_string();

                    let imds_version = instance.metadata_options()
                        .and_then(|m| m.http_tokens())
                        .map(|t| t.as_str().to_string())
                        .unwrap_or_else(|| "optional".to_string());

                    let ebs_optimized = if instance.ebs_optimized().unwrap_or(false) { "Yes" } else { "No" }.to_string();

                    let monitoring = instance.monitoring()
                        .and_then(|m| m.state())
                        .map(|s| s.as_str().to_string())
                        .unwrap_or_default();

                    if !ami_id.is_empty() {
                        ami_ids.insert(ami_id.clone());
                    }

                    instances.push(InstanceInfo {
                        instance_id,
                        instance_type,
                        ami_id,
                        imds_version,
                        ebs_optimized,
                        monitoring,
                    });
                }
            }

            next_token = resp.next_token().map(|s| s.to_string());
            if next_token.is_none() { break; }
        }

        // ── 2. Batch-fetch AMI owner IDs ─────────────────────────────────────
        let mut images_by_ami: HashMap<String, String> = HashMap::new();
        let ami_list: Vec<String> = ami_ids.into_iter().collect();

        if !ami_list.is_empty() {
            let resp = match self.client
                .describe_images()
                .set_image_ids(Some(ami_list.clone()))
                .owners("self")
                .owners("amazon")
                .owners("aws-marketplace")
                .send()
                .await
            {
                Ok(r) => Some(r),
                Err(e) => {
                    eprintln!("  WARN: EC2 describe_images: {e:#}");
                    None
                }
            };

            if let Some(resp) = resp {
                for image in resp.images() {
                    let ami_id = image.image_id().unwrap_or("").to_string();
                    let owner_id = image.owner_id().unwrap_or("").to_string();
                    images_by_ami.insert(ami_id, owner_id);
                }
            }
        }

        // ── 3. Build rows ─────────────────────────────────────────────────────
        for inst in instances {
            let ami_owner = images_by_ami.get(&inst.ami_id)
                .cloned()
                .unwrap_or_default();

            rows.push(vec![
                inst.instance_id,
                inst.instance_type,
                inst.ami_id,
                ami_owner,
                inst.imds_version,
                inst.ebs_optimized,
                inst.monitoring,
            ]);
        }

        Ok(rows)
    }
}
