use anyhow::Result;
use async_trait::async_trait;
use aws_sdk_eks::Client as EksClient;

use crate::evidence::CsvCollector;

pub struct EksAddonsCollector {
    client: EksClient,
}

impl EksAddonsCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self {
            client: EksClient::new(config),
        }
    }
}

#[async_trait]
impl CsvCollector for EksAddonsCollector {
    fn name(&self) -> &str {
        "EKS Add-ons"
    }
    fn filename_prefix(&self) -> &str {
        "EKS_AddOns"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Cluster Name",
            "Addon Name",
            "Addon Version",
            "Status",
            "Health Issues",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let mut rows = Vec::new();

        // 1. list_clusters paginated.
        let mut cluster_names: Vec<String> = Vec::new();
        let mut next_token: Option<String> = None;
        loop {
            let mut req = self.client.list_clusters();
            if let Some(ref t) = next_token {
                req = req.next_token(t);
            }
            let resp = match req.send().await {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("  WARN: EKS list_clusters: {e:#}");
                    return Ok(rows);
                }
            };
            cluster_names.extend(resp.clusters().iter().map(|s| s.to_string()));
            next_token = resp.next_token().map(|s| s.to_string());
            if next_token.is_none() {
                break;
            }
        }

        // 2. For each cluster, list addons paginated.
        for cluster_name in &cluster_names {
            let mut addon_names: Vec<String> = Vec::new();
            let mut a_token: Option<String> = None;
            loop {
                let mut req = self.client.list_addons().cluster_name(cluster_name);
                if let Some(ref t) = a_token {
                    req = req.next_token(t);
                }
                let resp = match req.send().await {
                    Ok(r) => r,
                    Err(e) => {
                        eprintln!("  WARN: EKS list_addons cluster={cluster_name}: {e:#}");
                        break;
                    }
                };
                addon_names.extend(resp.addons().iter().map(|s| s.to_string()));
                a_token = resp.next_token().map(|s| s.to_string());
                if a_token.is_none() {
                    break;
                }
            }

            // 3. describe_addon for each.
            for addon_name in &addon_names {
                let resp = match self
                    .client
                    .describe_addon()
                    .cluster_name(cluster_name)
                    .addon_name(addon_name)
                    .send()
                    .await
                {
                    Ok(r) => r,
                    Err(e) => {
                        eprintln!(
                            "  WARN: EKS describe_addon cluster={cluster_name} addon={addon_name}: {e:#}"
                        );
                        continue;
                    }
                };

                let addon = match resp.addon() {
                    Some(a) => a,
                    None => continue,
                };

                let version = addon.addon_version().unwrap_or("").to_string();
                let status = addon
                    .status()
                    .map(|s| s.as_str().to_string())
                    .unwrap_or_default();

                let health_issues = match addon.health() {
                    Some(h) => {
                        let issues = h.issues();
                        if issues.is_empty() {
                            String::new()
                        } else {
                            let first_code = issues
                                .first()
                                .and_then(|i| i.code())
                                .map(|c| c.as_str().to_string())
                                .unwrap_or_default();
                            format!("{} (first: {})", issues.len(), first_code)
                        }
                    }
                    None => String::new(),
                };

                rows.push(vec![
                    cluster_name.clone(),
                    addon_name.clone(),
                    version,
                    status,
                    health_issues,
                ]);
            }
        }

        Ok(rows)
    }
}
