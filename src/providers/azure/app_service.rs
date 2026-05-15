//! Azure App Service collector.
//!
//! Maps to AWS ECS / Lambda.  Uses `azure_mgmt_web` to list all Web Apps and
//! Function Apps in the subscription.

use std::sync::Arc;

use anyhow::{Context, Result};
use async_trait::async_trait;
use azure_mgmt_web::Client as WebClient;
use futures::StreamExt;

use crate::evidence::CsvCollector;

pub struct AppServiceCollector {
    client:          WebClient,
    subscription_id: String,
}

impl AppServiceCollector {
    pub fn new(
        credential: Arc<dyn azure_core::auth::TokenCredential>,
        subscription_id: String,
    ) -> Self {
        Self {
            client: WebClient::builder(credential).build(),
            subscription_id,
        }
    }
}

#[async_trait]
impl CsvCollector for AppServiceCollector {
    fn name(&self) -> &str { "Azure App Service" }
    fn filename_prefix(&self) -> &str { "Azure_App_Service" }

    fn headers(&self) -> &'static [&'static str] {
        &[
            "App Name",
            "Resource Group",
            "Location",
            "Kind",
            "State",
            "HTTPS Only",
            "Default Host Name",
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
            .web_apps_client()
            .list(&self.subscription_id)
            .into_stream();

        while let Some(page) = stream.next().await {
            let page = page.context("App Service: list page failed")?;
            for app in page.value {
                let props = app.properties.as_ref();
                let rg = app.resource.id.as_deref()
                    .and_then(|id| id.split("/resourceGroups/").nth(1))
                    .and_then(|s| s.split('/').next())
                    .unwrap_or("")
                    .to_string();

                rows.push(vec![
                    app.resource.name.clone().unwrap_or_default(),
                    rg,
                    app.resource.location.clone(),
                    app.resource.kind.clone().unwrap_or_default(),
                    props.and_then(|p| p.state.clone()).unwrap_or_default(),
                    props.and_then(|p| p.https_only)
                        .map(|b| b.to_string())
                        .unwrap_or_default(),
                    props.and_then(|p| p.default_host_name.clone()).unwrap_or_default(),
                ]);
            }
        }

        Ok(rows)
    }
}
