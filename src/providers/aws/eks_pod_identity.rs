use anyhow::Result;
use async_trait::async_trait;
use aws_sdk_eks::Client as EksClient;

use crate::evidence::CsvCollector;

pub struct EksPodIdentityCollector {
    client: EksClient,
}

impl EksPodIdentityCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self {
            client: EksClient::new(config),
        }
    }
}

#[async_trait]
impl CsvCollector for EksPodIdentityCollector {
    fn name(&self) -> &str {
        "EKS Pod Identity"
    }
    fn filename_prefix(&self) -> &str {
        "EKS_PodIdentity"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Cluster Name",
            "Namespace",
            "Service Account",
            "Role ARN",
            "Association ID",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let mut rows = Vec::new();

        // list_clusters paginated.
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

        for cluster_name in &cluster_names {
            let mut a_token: Option<String> = None;
            loop {
                let mut req = self
                    .client
                    .list_pod_identity_associations()
                    .cluster_name(cluster_name);
                if let Some(ref t) = a_token {
                    req = req.next_token(t);
                }
                let resp = match req.send().await {
                    Ok(r) => r,
                    Err(e) => {
                        eprintln!(
                            "  WARN: EKS list_pod_identity_associations cluster={cluster_name}: {e:#}"
                        );
                        break;
                    }
                };

                for summary in resp.associations() {
                    let namespace = summary.namespace().unwrap_or("").to_string();
                    let service_account = summary.service_account().unwrap_or("").to_string();
                    let assoc_id = summary.association_id().unwrap_or("").to_string();

                    let role_arn = if assoc_id.is_empty() {
                        String::new()
                    } else {
                        match self
                            .client
                            .describe_pod_identity_association()
                            .cluster_name(cluster_name)
                            .association_id(&assoc_id)
                            .send()
                            .await
                        {
                            Ok(d) => d
                                .association()
                                .and_then(|a| a.role_arn())
                                .unwrap_or("")
                                .to_string(),
                            Err(e) => {
                                eprintln!(
                                    "  WARN: EKS describe_pod_identity_association cluster={cluster_name} assoc={assoc_id}: {e:#}"
                                );
                                String::new()
                            }
                        }
                    };

                    rows.push(vec![
                        cluster_name.clone(),
                        namespace,
                        service_account,
                        role_arn,
                        assoc_id,
                    ]);
                }

                a_token = resp.next_token().map(|s| s.to_string());
                if a_token.is_none() {
                    break;
                }
            }
        }

        Ok(rows)
    }
}
