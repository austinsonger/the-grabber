use std::collections::HashMap;

use anyhow::{Context, Result};
use async_trait::async_trait;
use aws_sdk_elasticache::Client as ElastiCacheClient;

use crate::evidence::CsvCollector;

// ---------------------------------------------------------------------------
// ElastiCache Clusters (Redis Replication Groups + Memcached)
// ---------------------------------------------------------------------------

pub struct ElastiCacheCollector {
    client: ElastiCacheClient,
}

impl ElastiCacheCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self { client: ElastiCacheClient::new(config) }
    }
}

#[async_trait]
impl CsvCollector for ElastiCacheCollector {
    fn name(&self) -> &str { "ElastiCache Clusters" }
    fn filename_prefix(&self) -> &str { "ElastiCache" }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Cluster Name", "Engine", "Engine Version",
            "Encryption In Transit", "Encryption At Rest",
            "Availability Zone", "Cluster ARN", "KMS Key ARN", "Region",
        ]
    }

    async fn collect_rows(&self, _account_id: &str, region: &str) -> Result<Vec<Vec<String>>> {
        let mut rows = Vec::new();

        // --- Redis: use replication groups (logical cluster level) ----------
        let mut rg_marker: Option<String> = None;
        loop {
            let mut req = self.client.describe_replication_groups();
            if let Some(ref m) = rg_marker {
                req = req.marker(m);
            }
            let resp = req.send().await.context("ElastiCache describe_replication_groups")?;

            for rg in resp.replication_groups() {
                let name       = rg.replication_group_id().unwrap_or("").to_string();
                let transit    = bool_yn(rg.transit_encryption_enabled());
                let at_rest    = bool_yn(rg.at_rest_encryption_enabled());
                let arn        = rg.arn().unwrap_or("").to_string();
                let kms_key    = rg.kms_key_id().unwrap_or("").to_string();

                // Get engine info from the first member cluster.
                let (engine, engine_version, az) = if let Some(cluster_id) = rg.member_clusters().first() {
                    match self.client
                        .describe_cache_clusters()
                        .cache_cluster_id(cluster_id)
                        .send()
                        .await
                    {
                        Ok(cr) => {
                            let c = cr.cache_clusters().first();
                            (
                                c.and_then(|c| c.engine()).unwrap_or("redis").to_string(),
                                c.and_then(|c| c.engine_version()).unwrap_or("").to_string(),
                                c.and_then(|c| c.preferred_availability_zone()).unwrap_or("").to_string(),
                            )
                        }
                        Err(_) => ("redis".to_string(), "".to_string(), "".to_string()),
                    }
                } else {
                    ("redis".to_string(), "".to_string(), "".to_string())
                };

                rows.push(vec![
                    name, engine, engine_version,
                    transit, at_rest,
                    az, arn, kms_key, region.to_string(),
                ]);
            }

            rg_marker = resp.marker().map(|s| s.to_string());
            if rg_marker.is_none() { break; }
        }

        // --- Memcached: standalone cache clusters (no replication group) ----
        let mut cc_marker: Option<String> = None;
        // Track which cluster IDs we already captured via replication groups.
        let mut seen_rg_members: HashMap<String, bool> = HashMap::new();
        // Re-fetch replication groups to build the member set.
        {
            let mut m: Option<String> = None;
            loop {
                let mut req = self.client.describe_replication_groups();
                if let Some(ref mk) = m {
                    req = req.marker(mk);
                }
                let resp = req.send().await?;
                for rg in resp.replication_groups() {
                    for member in rg.member_clusters() {
                        seen_rg_members.insert(member.to_string(), true);
                    }
                }
                m = resp.marker().map(|s| s.to_string());
                if m.is_none() { break; }
            }
        }

        loop {
            let mut req = self.client.describe_cache_clusters();
            if let Some(ref m) = cc_marker {
                req = req.marker(m);
            }
            let resp = req.send().await.context("ElastiCache describe_cache_clusters")?;

            for cluster in resp.cache_clusters() {
                let cluster_id = cluster.cache_cluster_id().unwrap_or("").to_string();
                // Skip Redis nodes already covered by their replication group.
                if seen_rg_members.contains_key(&cluster_id) { continue; }

                let engine   = cluster.engine().unwrap_or("").to_string();
                let version  = cluster.engine_version().unwrap_or("").to_string();
                let transit  = bool_yn(cluster.transit_encryption_enabled());
                let at_rest  = bool_yn(cluster.at_rest_encryption_enabled());
                let az       = cluster.preferred_availability_zone().unwrap_or("").to_string();
                let arn      = cluster.arn().unwrap_or("").to_string();

                rows.push(vec![
                    cluster_id, engine, version,
                    transit, at_rest,
                    az, arn, "".to_string(), region.to_string(),
                ]);
            }

            cc_marker = resp.marker().map(|s| s.to_string());
            if cc_marker.is_none() { break; }
        }

        Ok(rows)
    }
}

// ---------------------------------------------------------------------------
// ElastiCache Global Datastores
// ---------------------------------------------------------------------------

pub struct ElastiCacheGlobalCollector {
    client: ElastiCacheClient,
}

impl ElastiCacheGlobalCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self { client: ElastiCacheClient::new(config) }
    }
}

#[async_trait]
impl CsvCollector for ElastiCacheGlobalCollector {
    fn name(&self) -> &str { "ElastiCache Global Datastores" }
    fn filename_prefix(&self) -> &str { "ElastiCache_Global_Datastore" }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Name", "Engine", "Engine Version",
            "Encryption In Transit", "Encryption At Rest",
            "ARN", "Region",
        ]
    }

    async fn collect_rows(&self, account_id: &str, _region: &str) -> Result<Vec<Vec<String>>> {
        let mut rows = Vec::new();
        let mut marker: Option<String> = None;

        loop {
            let mut req = self.client.describe_global_replication_groups().show_member_info(true);
            if let Some(ref m) = marker {
                req = req.marker(m);
            }
            let resp = req.send().await
                .context("ElastiCache describe_global_replication_groups")?;

            for group in resp.global_replication_groups() {
                let name    = group.global_replication_group_id().unwrap_or("").to_string();
                let engine  = group.engine().unwrap_or("").to_string();
                let version = group.engine_version().unwrap_or("").to_string();
                let transit = bool_yn(group.transit_encryption_enabled());
                let at_rest = bool_yn(group.at_rest_encryption_enabled());
                // Global replication groups don't have a standard ARN — construct one.
                let arn = format!(
                    "arn:aws:elasticache::{account_id}:globalreplicationgroup:{name}"
                );

                rows.push(vec![name, engine, version, transit, at_rest, arn, "global".to_string()]);
            }

            marker = resp.marker().map(|s| s.to_string());
            if marker.is_none() { break; }
        }

        Ok(rows)
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn bool_yn(val: Option<bool>) -> String {
    match val {
        Some(true)  => "Yes".to_string(),
        Some(false) => "No".to_string(),
        None        => "".to_string(),
    }
}
