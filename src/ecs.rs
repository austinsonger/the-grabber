use anyhow::{Context, Result};
use async_trait::async_trait;
use aws_sdk_ecs::Client as EcsClient;

use crate::evidence::CsvCollector;

pub struct EcsClusterCollector {
    client: EcsClient,
}

impl EcsClusterCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self { client: EcsClient::new(config) }
    }
}

#[async_trait]
impl CsvCollector for EcsClusterCollector {
    fn name(&self) -> &str { "ECS Clusters" }
    fn filename_prefix(&self) -> &str { "ECS_Clusters" }
    fn headers(&self) -> &'static [&'static str] {
        &["Cluster Name", "Status", "Running Tasks", "Container Insights Enabled"]
    }

    async fn collect_rows(&self, _account_id: &str, _region: &str) -> Result<Vec<Vec<String>>> {
        let mut rows = Vec::new();
        let mut next_token: Option<String> = None;
        let mut all_arns: Vec<String> = Vec::new();

        // Collect all cluster ARNs first.
        loop {
            let mut req = self.client.list_clusters();
            if let Some(ref t) = next_token {
                req = req.next_token(t);
            }
            let resp = req.send().await.context("ECS list_clusters")?;
            all_arns.extend(resp.cluster_arns().iter().map(|s| s.to_string()));
            next_token = resp.next_token().map(|s| s.to_string());
            if next_token.is_none() { break; }
        }

        // Describe clusters in batches of 100.
        for chunk in all_arns.chunks(100) {
            let resp = match self.client
                .describe_clusters()
                .set_clusters(Some(chunk.to_vec()))
                .include(aws_sdk_ecs::types::ClusterField::Settings)
                .send()
                .await
            {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("  WARN: ECS describe_clusters: {e:#}");
                    continue;
                }
            };

            for cluster in resp.clusters() {
                let name   = cluster.cluster_name().unwrap_or("").to_string();
                let status = cluster.status().unwrap_or("").to_string();
                let running = cluster.running_tasks_count().to_string();

                let container_insights = cluster.settings()
                    .iter()
                    .find(|s| s.name().map(|n| n.as_str()) == Some("containerInsights"))
                    .and_then(|s| s.value())
                    .map(|v| if v == "enabled" { "Yes" } else { "No" })
                    .unwrap_or("No")
                    .to_string();

                rows.push(vec![name, status, running, container_insights]);
            }
        }

        Ok(rows)
    }
}
