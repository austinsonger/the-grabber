//! Azure Container Registry (ACR) collector.
//!
//! Maps to AWS ECR.  Uses `azure_mgmt_containerregistry` to list all registries
//! in the subscription.

use std::sync::Arc;

use anyhow::{Context, Result};
use async_trait::async_trait;
use futures::StreamExt;

use crate::evidence::CsvCollector;

pub struct AcrCollector {
    client:          AcrClient,
    subscription_id: String,
}

impl AcrCollector {
    pub fn new(
        credential: Arc<dyn azure_core::auth::TokenCredential>,
        subscription_id: String,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            client: AcrClient::builder(credential).build()
                .context("Failed to build ACR client")?,
            subscription_id,
        })
    }
}

#[async_trait]
impl CsvCollector for AcrCollector {
    fn name(&self) -> &str { "Azure Container Registry" }
    fn filename_prefix(&self) -> &str { "Azure_Container_Registries" }

    fn headers(&self) -> &'static [&'static str] {
        &[
            "Registry Name",
            "Resource Group",
            "Location",
            "SKU",
            "Admin User Enabled",
            "Login Server",
            "Provisioning State",
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
            .registries_client()
            .list(&self.subscription_id)
            .into_stream();

        while let Some(page) = stream.next().await {
            let page = page.context("ACR: list page failed")?;
            for reg in page.value {
                let props = reg.properties.as_ref();
                let rg = reg.resource.id.as_deref()
                    .and_then(|id| id.split("/resourceGroups/").nth(1))
                    .and_then(|s| s.split('/').next())
                    .unwrap_or("")
                    .to_string();

                rows.push(vec![
                    reg.resource.name.clone().unwrap_or_default(),
                    rg,
                    reg.resource.location.clone(),
                    format!("{:?}", reg.sku.name),
                    props.and_then(|p| p.admin_user_enabled)
                        .map(|b| b.to_string())
                        .unwrap_or_default(),
                    props.and_then(|p| p.login_server.clone()).unwrap_or_default(),
                    props.and_then(|p| p.provisioning_state.as_ref())
                        .map(|s| format!("{:?}", s))
                        .unwrap_or_default(),
                ]);
            }
        }

        Ok(rows)
    }
}
