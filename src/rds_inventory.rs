use anyhow::{Context, Result};
use async_trait::async_trait;
use aws_sdk_rds::Client as RdsClient;

use crate::evidence::CsvCollector;

pub struct RdsInventoryCollector {
    client: RdsClient,
}

impl RdsInventoryCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self { client: RdsClient::new(config) }
    }
}

#[async_trait]
impl CsvCollector for RdsInventoryCollector {
    fn name(&self) -> &str { "RDS Inventory" }
    fn filename_prefix(&self) -> &str { "RDS" }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "DB Instance ARN", "Engine", "Engine Version",
            "Encryption Status", "KMS Key ARN",
            "Publicly Accessible", "Auto Minor Version Upgrades", "Region",
        ]
    }

    async fn collect_rows(&self, _account_id: &str, region: &str) -> Result<Vec<Vec<String>>> {
        let mut rows = Vec::new();
        let mut marker: Option<String> = None;

        loop {
            let mut req = self.client.describe_db_instances();
            if let Some(ref m) = marker {
                req = req.marker(m);
            }
            let resp = req.send().await.context("RDS describe_db_instances")?;

            for db in resp.db_instances() {
                let arn     = db.db_instance_arn().unwrap_or("").to_string();
                let engine  = db.engine().unwrap_or("").to_string();
                let version = db.engine_version().unwrap_or("").to_string();
                let enc     = if db.storage_encrypted().unwrap_or(false) { "Encrypted" } else { "Not Encrypted" }.to_string();
                let kms_key = db.kms_key_id().unwrap_or("").to_string();
                let public  = bool_yn(db.publicly_accessible());
                let auto_mv = bool_yn(db.auto_minor_version_upgrade());

                rows.push(vec![
                    arn, engine, version,
                    enc, kms_key,
                    public, auto_mv, region.to_string(),
                ]);
            }

            marker = resp.marker().map(|s| s.to_string());
            if marker.is_none() { break; }
        }

        Ok(rows)
    }
}

fn bool_yn(val: Option<bool>) -> String {
    match val {
        Some(true)  => "Yes".to_string(),
        Some(false) => "No".to_string(),
        None        => "".to_string(),
    }
}
