//! Azure Monitor Alert Rules collector.
//!
//! Maps to AWS CloudWatch Alarms.  Uses `azure_mgmt_monitor` to list all
//! metric alert rules in the subscription.

use std::sync::Arc;

use anyhow::{Context, Result};
use async_trait::async_trait;
use azure_mgmt_monitor::Client as MonitorClient;

use crate::evidence::CsvCollector;

pub struct MonitorAlertsCollector {
    client:          MonitorClient,
    subscription_id: String,
}

impl MonitorAlertsCollector {
    pub fn new(
        credential: Arc<dyn azure_core::auth::TokenCredential>,
        subscription_id: String,
    ) -> Self {
        Self {
            client: MonitorClient::builder(credential).build(),
            subscription_id,
        }
    }
}

#[async_trait]
impl CsvCollector for MonitorAlertsCollector {
    fn name(&self) -> &str { "Azure Monitor Alert Rules" }
    fn filename_prefix(&self) -> &str { "Azure_Monitor_Alert_Rules" }

    fn headers(&self) -> &'static [&'static str] {
        &[
            "Alert Name",
            "Resource Group",
            "Location",
            "Severity",
            "Enabled",
            "Description",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        // The metric alerts list endpoint does not support server-side pagination,
        // so we fetch a single response page.
        let result = self.client
            .metric_alerts_client()
            .list_by_subscription(&self.subscription_id)
            .send()
            .await
            .context("Monitor Alerts: send failed")?
            .into_body()
            .await
            .context("Monitor Alerts: parse response failed")?;

        let mut rows = Vec::new();
        for alert in result.value {
            let rg = alert.resource.id.as_deref()
                .and_then(|id| id.split("/resourceGroups/").nth(1))
                .and_then(|s| s.split('/').next())
                .unwrap_or("")
                .to_string();

            rows.push(vec![
                alert.resource.name.clone().unwrap_or_default(),
                rg,
                alert.resource.location.clone(),
                alert.properties.severity.to_string(),
                alert.properties.enabled.to_string(),
                alert.properties.description.clone().unwrap_or_default(),
            ]);
        }

        Ok(rows)
    }
}
