use anyhow::{Context, Result};
use async_trait::async_trait;
use aws_sdk_eks::Client as EksClient;

use crate::evidence::CsvCollector;

pub struct EksClusterCollector {
    client: EksClient,
}

impl EksClusterCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self { client: EksClient::new(config) }
    }
}

#[async_trait]
impl CsvCollector for EksClusterCollector {
    fn name(&self) -> &str { "EKS Clusters" }
    fn filename_prefix(&self) -> &str { "EKS_Clusters" }
    fn headers(&self) -> &'static [&'static str] {
        &["Cluster Name", "Version", "Endpoint Public Access", "Logging Enabled"]
    }

    async fn collect_rows(&self, _account_id: &str, _region: &str, _dates: Option<(i64, i64)>) -> Result<Vec<Vec<String>>> {
        let mut rows = Vec::new();
        let mut next_token: Option<String> = None;
        let mut all_names: Vec<String> = Vec::new();

        loop {
            let mut req = self.client.list_clusters();
            if let Some(ref t) = next_token {
                req = req.next_token(t);
            }
            let resp = req.send().await.context("EKS list_clusters")?;
            all_names.extend(resp.clusters().iter().map(|s| s.to_string()));
            next_token = resp.next_token().map(|s| s.to_string());
            if next_token.is_none() { break; }
        }

        for cluster_name in &all_names {
            let resp = match self.client
                .describe_cluster()
                .name(cluster_name)
                .send()
                .await
            {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("  WARN: EKS describe_cluster {cluster_name}: {e:#}");
                    continue;
                }
            };

            let cluster = match resp.cluster() {
                Some(c) => c,
                None    => continue,
            };

            let version        = cluster.version().unwrap_or("").to_string();
            let public_access  = cluster.resources_vpc_config()
                .map(|v| if v.endpoint_public_access() { "Yes" } else { "No" })
                .unwrap_or("")
                .to_string();

            let logging_types: Vec<String> = cluster.logging()
                .map(|l| l.cluster_logging())
                .unwrap_or_default()
                .iter()
                .filter(|ls| ls.enabled().unwrap_or(false))
                .flat_map(|ls| ls.types())
                .map(|t| t.as_str().to_string())
                .collect();

            let logging = if logging_types.is_empty() {
                "Disabled".to_string()
            } else {
                logging_types.join(", ")
            };

            rows.push(vec![cluster_name.clone(), version, public_access, logging]);
        }

        Ok(rows)
    }
}
