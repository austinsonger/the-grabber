use anyhow::{Context, Result};
use async_trait::async_trait;
use aws_sdk_ec2::Client as Ec2Client;

use crate::evidence::CsvCollector;

pub struct EbsCollector {
    client: Ec2Client,
}

impl EbsCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self { client: Ec2Client::new(config) }
    }
}

#[async_trait]
impl CsvCollector for EbsCollector {
    fn name(&self) -> &str { "EBS Volumes" }
    fn filename_prefix(&self) -> &str { "EBS" }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Volume ID", "Volume ARN", "Availability Zone",
            "Encryption Status", "KMS Key ARN", "Region",
        ]
    }

    async fn collect_rows(&self, account_id: &str, region: &str, _dates: Option<(i64, i64)>) -> Result<Vec<Vec<String>>> {
        let mut rows = Vec::new();
        let mut next_token: Option<String> = None;

        loop {
            let mut req = self.client.describe_volumes();
            if let Some(ref t) = next_token {
                req = req.next_token(t);
            }
            let resp = req.send().await.context("EC2 describe_volumes")?;

            for vol in resp.volumes() {
                let vol_id  = vol.volume_id().unwrap_or("").to_string();
                let az      = vol.availability_zone().unwrap_or("").to_string();
                let enc     = if vol.encrypted() == Some(true) { "Encrypted" } else { "Not Encrypted" }.to_string();
                let kms_key = vol.kms_key_id().unwrap_or("").to_string();
                // EBS volumes don't have an ARN field — construct it.
                let arn = format!("arn:aws:ec2:{region}:{account_id}:volume/{vol_id}");

                rows.push(vec![vol_id, arn, az, enc, kms_key, region.to_string()]);
            }

            next_token = resp.next_token().map(|s| s.to_string());
            if next_token.is_none() { break; }
        }

        Ok(rows)
    }
}
