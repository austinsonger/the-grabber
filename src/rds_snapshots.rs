use anyhow::{Context, Result};
use async_trait::async_trait;
use aws_sdk_rds::Client as RdsClient;

use crate::evidence::CsvCollector;

fn fmt_rds_dt(dt: &aws_sdk_rds::primitives::DateTime) -> String {
    chrono::DateTime::<chrono::Utc>::from_timestamp(dt.secs(), 0)
        .map(|c| c.to_rfc3339())
        .unwrap_or_default()
}

pub struct RdsSnapshotCollector {
    client: RdsClient,
}

impl RdsSnapshotCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self { client: RdsClient::new(config) }
    }
}

#[async_trait]
impl CsvCollector for RdsSnapshotCollector {
    fn name(&self) -> &str { "RDS Snapshots" }
    fn filename_prefix(&self) -> &str { "RDS_Snapshots" }
    fn headers(&self) -> &'static [&'static str] {
        &["Snapshot ID", "DB Instance ID", "Snapshot Type", "Encrypted", "KMS Key ID", "Created Time", "Public Accessible"]
    }

    async fn collect_rows(&self, _account_id: &str, _region: &str, dates: Option<(i64, i64)>) -> Result<Vec<Vec<String>>> {
        let mut rows = Vec::new();
        let mut marker: Option<String> = None;

        loop {
            let mut req = self.client.describe_db_snapshots();
            if let Some(ref m) = marker {
                req = req.marker(m);
            }
            let resp = req.send().await.context("RDS describe_db_snapshots")?;

            for snapshot in resp.db_snapshots() {
                // Filter by creation time when a date window is provided.
                if let Some((start, end)) = dates {
                    let create_secs = snapshot.snapshot_create_time().map(|d| d.secs()).unwrap_or(0);
                    if create_secs < start || create_secs > end {
                        continue;
                    }
                }

                let snapshot_id = snapshot.db_snapshot_identifier().unwrap_or("").to_string();
                let db_instance_id = snapshot.db_instance_identifier().unwrap_or("").to_string();
                let snapshot_type = snapshot.snapshot_type().unwrap_or("").to_string();
                let encrypted = snapshot.encrypted().unwrap_or(false).to_string();
                let kms_key_id = snapshot.kms_key_id().unwrap_or("").to_string();
                let created_time = snapshot.snapshot_create_time().map(fmt_rds_dt).unwrap_or_default();

                // Check if snapshot is public
                let public_accessible = match self.client
                    .describe_db_snapshot_attributes()
                    .db_snapshot_identifier(&snapshot_id)
                    .send()
                    .await
                {
                    Ok(resp) => {
                        let is_public = resp.db_snapshot_attributes_result()
                            .map(|r| r.db_snapshot_attributes())
                            .unwrap_or_default()
                            .iter()
                            .any(|attr| {
                                attr.attribute_name() == Some("restore")
                                    && attr.attribute_values().iter().any(|v| v == "all")
                            });
                        if is_public { "Public" } else { "Private" }.to_string()
                    }
                    Err(e) => {
                        eprintln!("  WARN: RDS describe_db_snapshot_attributes {snapshot_id}: {e:#}");
                        "Unknown".to_string()
                    }
                };

                rows.push(vec![
                    snapshot_id,
                    db_instance_id,
                    snapshot_type,
                    encrypted,
                    kms_key_id,
                    created_time,
                    public_accessible,
                ]);
            }

            marker = resp.marker().map(|s| s.to_string());
            if marker.is_none() { break; }
        }

        Ok(rows)
    }
}
