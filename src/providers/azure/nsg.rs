//! Azure Network Security Groups (NSG) collector.
//!
//! Maps to AWS Security Groups + NACLs.  Uses `azure_mgmt_network` to list all
//! NSGs and their security rules across the subscription.

use std::sync::Arc;

use anyhow::{Context, Result};
use async_trait::async_trait;
use azure_mgmt_network::Client as NetworkClient;
use futures::StreamExt;

use crate::evidence::CsvCollector;

pub struct NsgCollector {
    client:          NetworkClient,
    subscription_id: String,
}

impl NsgCollector {
    pub fn new(
        credential: Arc<dyn azure_core::auth::TokenCredential>,
        subscription_id: String,
    ) -> Self {
        Self {
            client: NetworkClient::builder(credential).build(),
            subscription_id,
        }
    }
}

#[async_trait]
impl CsvCollector for NsgCollector {
    fn name(&self) -> &str { "Azure Network Security Groups" }
    fn filename_prefix(&self) -> &str { "Azure_Network_Security_Groups" }

    fn headers(&self) -> &'static [&'static str] {
        &[
            "NSG Name",
            "Resource Group",
            "Location",
            "Rule Name",
            "Direction",
            "Protocol",
            "Source",
            "Destination",
            "Destination Port",
            "Access",
            "Priority",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let mut rows = Vec::new();

        let mut stream = self.client
            .network_security_groups_client()
            .list_all(&self.subscription_id)
            .into_stream();

        while let Some(page) = stream.next().await {
            let page = page.context("NSG: list_all page failed")?;
            for nsg in page.value {
                let nsg_name = nsg.resource.name.clone().unwrap_or_default();
                let location = nsg.resource.location.clone().unwrap_or_default();
                let rg = nsg.resource.id.as_deref()
                    .and_then(|id| id.split("/resourceGroups/").nth(1))
                    .and_then(|s| s.split('/').next())
                    .unwrap_or("")
                    .to_string();

                let rules = nsg.properties
                    .as_ref()
                    .map(|p| p.security_rules.as_slice())
                    .unwrap_or_default();

                for rule in rules {
                    let rp = rule.properties.as_ref();
                    rows.push(vec![
                        nsg_name.clone(),
                        rg.clone(),
                        location.clone(),
                        rule.name.clone().unwrap_or_default(),
                        rp.map(|p| format!("{:?}", p.direction)).unwrap_or_default(),
                        rp.map(|p| format!("{:?}", p.protocol)).unwrap_or_default(),
                        rp.and_then(|p| p.source_address_prefix.clone()).unwrap_or_default(),
                        rp.and_then(|p| p.destination_address_prefix.clone()).unwrap_or_default(),
                        rp.and_then(|p| p.destination_port_range.clone()).unwrap_or_default(),
                        rp.map(|p| format!("{:?}", p.access)).unwrap_or_default(),
                        rp.map(|p| p.priority.to_string()).unwrap_or_default(),
                    ]);
                }
            }
        }

        Ok(rows)
    }
}
