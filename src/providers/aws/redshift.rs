use anyhow::Result;
use async_trait::async_trait;
use aws_sdk_redshift::Client as RedshiftClient;

use crate::evidence::CsvCollector;

// ---------------------------------------------------------------------------
// Redshift Clusters — encryption, public-access, enhanced VPC routing, logging
// ---------------------------------------------------------------------------

pub struct RedshiftClustersCollector {
    client: RedshiftClient,
}

impl RedshiftClustersCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self {
            client: RedshiftClient::new(config),
        }
    }
}

#[async_trait]
impl CsvCollector for RedshiftClustersCollector {
    fn name(&self) -> &str {
        "Redshift Clusters"
    }
    fn filename_prefix(&self) -> &str {
        "Redshift_Clusters"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Cluster ID",
            "Node Type",
            "Status",
            "Encrypted",
            "KMS Key",
            "Publicly Accessible",
            "Enhanced VPC Routing",
            "Logging Enabled",
            "Log Bucket",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let mut rows = Vec::new();
        let mut marker: Option<String> = None;

        loop {
            let mut req = self.client.describe_clusters();
            if let Some(ref m) = marker {
                req = req.marker(m);
            }
            let resp = match req.send().await {
                Ok(r) => r,
                Err(e) => {
                    let msg = format!("{e:#}");
                    if msg.contains("not supported")
                        || msg.contains("not available")
                        || msg.contains("UnsupportedOperation")
                    {
                        return Ok(rows);
                    }
                    eprintln!("  WARN: Redshift describe_clusters: {e:#}");
                    return Ok(rows);
                }
            };

            for cluster in resp.clusters() {
                let cid = cluster.cluster_identifier().unwrap_or("").to_string();
                let node_type = cluster.node_type().unwrap_or("").to_string();
                let status = cluster.cluster_status().unwrap_or("").to_string();
                let encrypted = bool_yn(cluster.encrypted());
                let kms = cluster.kms_key_id().unwrap_or("").to_string();
                let public = bool_yn(cluster.publicly_accessible());
                let evpc = bool_yn(cluster.enhanced_vpc_routing());

                let (logging, bucket) = if cid.is_empty() {
                    (String::new(), String::new())
                } else {
                    match self
                        .client
                        .describe_logging_status()
                        .cluster_identifier(&cid)
                        .send()
                        .await
                    {
                        Ok(ls) => (
                            bool_yn(ls.logging_enabled()),
                            ls.bucket_name().unwrap_or("").to_string(),
                        ),
                        Err(_) => (String::new(), String::new()),
                    }
                };

                rows.push(vec![
                    cid, node_type, status, encrypted, kms, public, evpc, logging, bucket,
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

fn bool_yn(val: Option<bool>) -> String {
    match val {
        Some(true) => "Yes".to_string(),
        Some(false) => "No".to_string(),
        None => String::new(),
    }
}
