//! Azure Kubernetes Service (AKS) collector.
//!
//! Maps to AWS EKS.  Uses the Azure Resource Management REST API directly
//! (via `azure_core`) to list all managed clusters across the subscription.
//! This avoids the `azure_mgmt_containerservice` crate which is on an older
//! `azure_core` version and is not compatible with the rest of the v0.21 SDK.

use std::sync::Arc;

use anyhow::{Context, Result};
use async_trait::async_trait;
use azure_core::{new_http_client, Request};
use serde_json::Value;

use crate::evidence::CsvCollector;

const AKS_API_VERSION: &str = "2023-01-01";

pub struct AksCollector {
    credential:      Arc<dyn azure_core::auth::TokenCredential>,
    subscription_id: String,
}

impl AksCollector {
    pub fn new(
        credential: Arc<dyn azure_core::auth::TokenCredential>,
        subscription_id: String,
    ) -> Self {
        Self { credential, subscription_id }
    }
}

#[async_trait]
impl CsvCollector for AksCollector {
    fn name(&self) -> &str { "Azure Kubernetes Service" }
    fn filename_prefix(&self) -> &str { "Azure_AKS_Clusters" }

    fn headers(&self) -> &'static [&'static str] {
        &[
            "Cluster Name",
            "Resource Group",
            "Location",
            "Kubernetes Version",
            "Provisioning State",
            "RBAC Enabled",
            "Node Count",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let token = self.credential
            .get_token(&["https://management.azure.com/.default"])
            .await
            .context("AKS: failed to obtain access token")?;

        let auth_value = format!("Bearer {}", token.token.secret());
        let http_client = new_http_client();
        let mut rows = Vec::new();

        let mut next_url = Some(format!(
            "https://management.azure.com/subscriptions/{}/providers/\
             Microsoft.ContainerService/managedClusters?api-version={}",
            self.subscription_id, AKS_API_VERSION
        ));

        while let Some(url_str) = next_url.take() {
            let url = url_str.parse().context("AKS: invalid URL")?;
            let mut req = Request::new(url, azure_core::Method::Get);
            req.insert_header("Authorization", auth_value.clone());
            req.insert_header("Content-Type", "application/json");

            let resp = http_client
                .execute_request(&req)
                .await
                .context("AKS: HTTP request failed")?;

            let page: Value = resp
                .into_body()
                .json()
                .await
                .context("AKS: failed to parse response")?;

            if let Some(clusters) = page.get("value").and_then(|v| v.as_array()) {
                for cluster in clusters {
                    let name = cluster["name"].as_str().unwrap_or_default().to_string();
                    let location =
                        cluster["location"].as_str().unwrap_or_default().to_string();
                    let rg = cluster["id"]
                        .as_str()
                        .unwrap_or_default()
                        .split("/resourceGroups/")
                        .nth(1)
                        .and_then(|s| s.split('/').next())
                        .unwrap_or_default()
                        .to_string();

                    let props = &cluster["properties"];
                    let k8s_version = props["kubernetesVersion"]
                        .as_str()
                        .unwrap_or_default()
                        .to_string();
                    let prov_state = props["provisioningState"]
                        .as_str()
                        .unwrap_or_default()
                        .to_string();
                    let rbac_enabled = props["enableRBAC"]
                        .as_bool()
                        .map(|b| b.to_string())
                        .unwrap_or_default();
                    let node_count: i64 = props["agentPoolProfiles"]
                        .as_array()
                        .map(|pools| {
                            pools
                                .iter()
                                .filter_map(|p| p["count"].as_i64())
                                .sum()
                        })
                        .unwrap_or(0);

                    rows.push(vec![
                        name,
                        rg,
                        location,
                        k8s_version,
                        prov_state,
                        rbac_enabled,
                        node_count.to_string(),
                    ]);
                }
            }

            // Follow pagination.
            next_url = page["nextLink"].as_str().map(|s| s.to_string());
        }

        Ok(rows)
    }
}
