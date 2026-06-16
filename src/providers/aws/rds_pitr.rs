use anyhow::{Context, Result};
use async_trait::async_trait;
use aws_sdk_rds::Client as RdsClient;

use crate::evidence::CsvCollector;

// ══════════════════════════════════════════════════════════════════════════════
// RDS PITR & Cluster Backtrack Collector
// ══════════════════════════════════════════════════════════════════════════════

pub struct RdsPitrCollector {
    client: RdsClient,
}

impl RdsPitrCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self {
            client: RdsClient::new(config),
        }
    }
}

fn fmt_dt(dt: &aws_sdk_rds::primitives::DateTime) -> String {
    chrono::DateTime::<chrono::Utc>::from_timestamp(dt.secs(), dt.subsec_nanos())
        .map(|c| c.to_rfc3339())
        .unwrap_or_default()
}

#[async_trait]
impl CsvCollector for RdsPitrCollector {
    fn name(&self) -> &str {
        "RDS PITR & Cluster Backtrack"
    }
    fn filename_prefix(&self) -> &str {
        "RDS_PITR_Backtrack"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Identifier",
            "Type",
            "Engine",
            "Backup Retention (days)",
            "Earliest Restorable",
            "Latest Restorable",
            "Backtrack Window (s)",
            "Earliest Backtrack",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let mut rows = Vec::new();

        // ── DB instances ────────────────────────────────────────────────────
        let mut marker: Option<String> = None;
        loop {
            let mut req = self.client.describe_db_instances();
            if let Some(ref m) = marker {
                req = req.marker(m);
            }
            let resp = req.send().await.context("RDS describe_db_instances")?;

            for inst in resp.db_instances() {
                let id = inst.db_instance_identifier().unwrap_or("").to_string();
                let engine = inst.engine().unwrap_or("").to_string();
                let retention = inst
                    .backup_retention_period()
                    .map(|n| n.to_string())
                    .unwrap_or_default();
                let latest = inst
                    .latest_restorable_time()
                    .map(fmt_dt)
                    .unwrap_or_default();

                rows.push(vec![
                    id,
                    "Instance".to_string(),
                    engine,
                    retention,
                    String::new(),
                    latest,
                    String::new(),
                    String::new(),
                ]);
            }

            marker = resp.marker().map(|s| s.to_string());
            if marker.is_none() {
                break;
            }
        }

        // ── DB clusters ─────────────────────────────────────────────────────
        let mut marker: Option<String> = None;
        loop {
            let mut req = self.client.describe_db_clusters();
            if let Some(ref m) = marker {
                req = req.marker(m);
            }
            let resp = req.send().await.context("RDS describe_db_clusters")?;

            for cluster in resp.db_clusters() {
                let id = cluster.db_cluster_identifier().unwrap_or("").to_string();
                let engine = cluster.engine().unwrap_or("").to_string();
                let retention = cluster
                    .backup_retention_period()
                    .map(|n| n.to_string())
                    .unwrap_or_default();
                let earliest = cluster
                    .earliest_restorable_time()
                    .map(fmt_dt)
                    .unwrap_or_default();
                let latest = cluster
                    .latest_restorable_time()
                    .map(fmt_dt)
                    .unwrap_or_default();
                let backtrack = cluster
                    .backtrack_window()
                    .map(|n| n.to_string())
                    .unwrap_or_default();
                let earliest_backtrack = cluster
                    .earliest_backtrack_time()
                    .map(fmt_dt)
                    .unwrap_or_default();

                rows.push(vec![
                    id,
                    "Cluster".to_string(),
                    engine,
                    retention,
                    earliest,
                    latest,
                    backtrack,
                    earliest_backtrack,
                ]);
            }

            marker = resp.marker().map(|s| s.to_string());
            if marker.is_none() {
                break;
            }
        }

        Ok(rows)
    }
}
