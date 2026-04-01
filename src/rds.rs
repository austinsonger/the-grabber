use anyhow::{Context, Result};
use async_trait::async_trait;
use aws_sdk_rds::Client;

use crate::evidence::{CollectParams, EvidenceCollector, EvidenceRecord, EvidenceSource};

pub struct RdsCollector {
    client: Client,
}

impl RdsCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self {
            client: Client::new(config),
        }
    }
}

#[async_trait]
impl EvidenceCollector for RdsCollector {
    fn name(&self) -> &str {
        "RDS Automated Snapshots"
    }

    fn filename_prefix(&self) -> &str {
        "RDS_automated_snapshot_exports"
    }

    async fn collect(&self, params: &CollectParams) -> Result<Vec<EvidenceRecord>> {
        let mut records = Vec::new();

        // Collect both DB instance snapshots and Aurora cluster snapshots.
        let mut instance_records = self.collect_instance_snapshots(params).await?;
        let mut cluster_records = self.collect_cluster_snapshots(params).await?;

        records.append(&mut instance_records);
        records.append(&mut cluster_records);

        Ok(records)
    }
}

impl RdsCollector {
    async fn collect_instance_snapshots(
        &self,
        params: &CollectParams,
    ) -> Result<Vec<EvidenceRecord>> {
        let mut records = Vec::new();
        let mut marker: Option<String> = None;

        loop {
            let mut req = self
                .client
                .describe_db_snapshots()
                .snapshot_type("automated");

            if let Some(ref m) = marker {
                req = req.marker(m);
            }

            let resp = req
                .send()
                .await
                .context("Failed to describe RDS DB snapshots")?;

            for snap in resp.db_snapshots() {
                let created_at = snap.snapshot_create_time();

                // Filter to the requested date window.
                if let Some(ts) = created_at {
                    let secs = ts.secs();
                    if secs < params.start_time.timestamp()
                        || secs > params.end_time.timestamp()
                    {
                        continue;
                    }
                } else {
                    continue;
                }

                // Optional filter: treat params.filter as a DB instance identifier prefix.
                if let Some(ref f) = params.filter {
                    if !snap
                        .db_instance_identifier()
                        .unwrap_or("")
                        .contains(f.as_str())
                    {
                        continue;
                    }
                }

                let timestamp = fmt_rds_dt(created_at.unwrap());
                let resource_arn = snap.db_snapshot_arn().map(|s| s.to_string());
                let snap_id = snap.db_snapshot_identifier().map(|s| s.to_string());
                let status = snap.status().map(|s| s.to_string());

                records.push(EvidenceRecord {
                    source: EvidenceSource::RdsApi,
                    event_name: "CreateDBSnapshot (automated)".to_string(),
                    timestamp: timestamp.clone(),
                    job_id: snap_id,
                    plan_id: None,
                    resource_arn,
                    resource_type: Some("RDS Instance".to_string()),
                    status,
                    completion_timestamp: Some(timestamp),
                    raw: if params.include_raw {
                        build_instance_raw(snap)
                    } else {
                        None
                    },
                });
            }

            marker = resp.marker().map(|s| s.to_string());
            if marker.is_none() {
                break;
            }
        }

        Ok(records)
    }

    async fn collect_cluster_snapshots(
        &self,
        params: &CollectParams,
    ) -> Result<Vec<EvidenceRecord>> {
        let mut records = Vec::new();
        let mut marker: Option<String> = None;

        loop {
            let mut req = self
                .client
                .describe_db_cluster_snapshots()
                .snapshot_type("automated");

            if let Some(ref m) = marker {
                req = req.marker(m);
            }

            let resp = req
                .send()
                .await
                .context("Failed to describe RDS cluster snapshots")?;

            for snap in resp.db_cluster_snapshots() {
                let created_at = snap.snapshot_create_time();

                if let Some(ts) = created_at {
                    let secs = ts.secs();
                    if secs < params.start_time.timestamp()
                        || secs > params.end_time.timestamp()
                    {
                        continue;
                    }
                } else {
                    continue;
                }

                if let Some(ref f) = params.filter {
                    if !snap
                        .db_cluster_identifier()
                        .unwrap_or("")
                        .contains(f.as_str())
                    {
                        continue;
                    }
                }

                let timestamp = fmt_rds_dt(created_at.unwrap());
                let resource_arn = snap.db_cluster_snapshot_arn().map(|s| s.to_string());
                let cluster_id = snap.db_cluster_identifier().map(|s| s.to_string());
                let snap_id = snap.db_cluster_snapshot_identifier().map(|s| s.to_string());
                let status = snap.status().map(|s| s.to_string());
                let engine = snap.engine().map(|s| s.to_string());

                records.push(EvidenceRecord {
                    source: EvidenceSource::RdsApi,
                    event_name: "CreateDBClusterSnapshot (automated)".to_string(),
                    timestamp: timestamp.clone(),
                    job_id: snap_id,
                    plan_id: cluster_id,
                    resource_arn,
                    resource_type: engine,
                    status,
                    completion_timestamp: Some(timestamp),
                    raw: if params.include_raw {
                        build_cluster_raw(snap)
                    } else {
                        None
                    },
                });
            }

            marker = resp.marker().map(|s| s.to_string());
            if marker.is_none() {
                break;
            }
        }

        Ok(records)
    }
}

fn fmt_rds_dt(dt: &aws_sdk_rds::primitives::DateTime) -> String {
    chrono::DateTime::<chrono::Utc>::from_timestamp(dt.secs(), dt.subsec_nanos())
        .map(|c| c.to_rfc3339())
        .unwrap_or_else(|| format!("epoch:{}", dt.secs()))
}

fn build_instance_raw(
    snap: &aws_sdk_rds::types::DbSnapshot,
) -> Option<serde_json::Value> {
    Some(serde_json::json!({
        "dbSnapshotIdentifier": snap.db_snapshot_identifier(),
        "dbInstanceIdentifier": snap.db_instance_identifier(),
        "snapshotType": snap.snapshot_type(),
        "status": snap.status(),
        "engine": snap.engine(),
        "engineVersion": snap.engine_version(),
        "allocatedStorage": snap.allocated_storage(),
        "availabilityZone": snap.availability_zone(),
        "dbSnapshotArn": snap.db_snapshot_arn(),
    }))
}

fn build_cluster_raw(
    snap: &aws_sdk_rds::types::DbClusterSnapshot,
) -> Option<serde_json::Value> {
    Some(serde_json::json!({
        "dbClusterSnapshotIdentifier": snap.db_cluster_snapshot_identifier(),
        "dbClusterIdentifier": snap.db_cluster_identifier(),
        "snapshotType": snap.snapshot_type(),
        "status": snap.status(),
        "engine": snap.engine(),
        "engineVersion": snap.engine_version(),
        "allocatedStorage": snap.allocated_storage(),
        "dbClusterSnapshotArn": snap.db_cluster_snapshot_arn(),
        "storageEncrypted": snap.storage_encrypted(),
    }))
}
