use anyhow::Result;
use async_trait::async_trait;
use aws_sdk_eks::Client as EksClient;

use crate::evidence::CsvCollector;

pub struct EksAccessEntriesCollector {
    client: EksClient,
}

impl EksAccessEntriesCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self {
            client: EksClient::new(config),
        }
    }
}

#[async_trait]
impl CsvCollector for EksAccessEntriesCollector {
    fn name(&self) -> &str {
        "EKS Access Entries"
    }
    fn filename_prefix(&self) -> &str {
        "EKS_AccessEntries"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Cluster Name",
            "Principal ARN",
            "Type",
            "K8s Groups",
            "Access Policies",
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

        for cluster_name in &cluster_names {
            // 2. list_access_entries paginated.
            let mut principals: Vec<String> = Vec::new();
            let mut a_token: Option<String> = None;
            loop {
                let mut req = self.client.list_access_entries().cluster_name(cluster_name);
                if let Some(ref t) = a_token {
                    req = req.next_token(t);
                }
                let resp = match req.send().await {
                    Ok(r) => r,
                    Err(e) => {
                        eprintln!("  WARN: EKS list_access_entries cluster={cluster_name}: {e:#}");
                        break;
                    }
                };
                principals.extend(resp.access_entries().iter().map(|s| s.to_string()));
                a_token = resp.next_token().map(|s| s.to_string());
                if a_token.is_none() {
                    break;
                }
            }

            for principal_arn in &principals {
                // 3. describe_access_entry
                let entry_resp = match self
                    .client
                    .describe_access_entry()
                    .cluster_name(cluster_name)
                    .principal_arn(principal_arn)
                    .send()
                    .await
                {
                    Ok(r) => r,
                    Err(e) => {
                        eprintln!(
                            "  WARN: EKS describe_access_entry cluster={cluster_name} principal={principal_arn}: {e:#}"
                        );
                        continue;
                    }
                };

                let (entry_type, k8s_groups) = match entry_resp.access_entry() {
                    Some(ae) => {
                        let t = ae.r#type().unwrap_or("").to_string();
                        let groups = ae.kubernetes_groups().join(",");
                        (t, groups)
                    }
                    None => (String::new(), String::new()),
                };

                // 4. list_associated_access_policies paginated.
                let mut policy_arns: Vec<String> = Vec::new();
                let mut p_token: Option<String> = None;
                loop {
                    let mut req = self
                        .client
                        .list_associated_access_policies()
                        .cluster_name(cluster_name)
                        .principal_arn(principal_arn);
                    if let Some(ref t) = p_token {
                        req = req.next_token(t);
                    }
                    let resp = match req.send().await {
                        Ok(r) => r,
                        Err(e) => {
                            eprintln!(
                                "  WARN: EKS list_associated_access_policies cluster={cluster_name} principal={principal_arn}: {e:#}"
                            );
                            break;
                        }
                    };
                    for assoc in resp.associated_access_policies() {
                        if let Some(arn) = assoc.policy_arn() {
                            policy_arns.push(arn.to_string());
                        }
                    }
                    p_token = resp.next_token().map(|s| s.to_string());
                    if p_token.is_none() {
                        break;
                    }
                }

                rows.push(vec![
                    cluster_name.clone(),
                    principal_arn.clone(),
                    entry_type,
                    k8s_groups,
                    policy_arns.join(","),
                ]);
            }
        }

        Ok(rows)
    }
}
