//! Azure Policy Compliance collector.
//!
//! Maps to AWS Config Rules + SCPs.  Uses `azure_mgmt_policyinsights` to query
//! the latest policy compliance state for all resources in the subscription.

use std::sync::Arc;

use anyhow::{Context, Result};
use async_trait::async_trait;
use azure_mgmt_policyinsights::Client as PolicyInsightsClient;
use futures::StreamExt;
use serde_json::Value;

use crate::evidence::JsonCollector;

pub struct PolicyCollector {
    client:          PolicyInsightsClient,
    subscription_id: String,
}

impl PolicyCollector {
    pub fn new(
        credential: Arc<dyn azure_core::auth::TokenCredential>,
        subscription_id: String,
    ) -> Self {
        Self {
            client: PolicyInsightsClient::builder(credential).build(),
            subscription_id,
        }
    }
}

#[async_trait]
impl JsonCollector for PolicyCollector {
    fn name(&self) -> &str { "Azure Policy Compliance" }
    fn filename_prefix(&self) -> &str { "Azure_Policy_Compliance" }

    async fn collect_records(
        &self,
        _account_id: &str,
        _region: &str,
    ) -> Result<Vec<Value>> {
        let mut records = Vec::new();

        // Query latest policy states at subscription scope.
        let mut stream = self.client
            .policy_states_client()
            .list_query_results_for_subscription("latest", &self.subscription_id)
            .into_stream();

        while let Some(page) = stream.next().await {
            let page = page.context("Azure Policy: compliance query failed")?;
            for state in page.value {
                let val = serde_json::to_value(&state).unwrap_or(Value::Null);
                records.push(val);
            }
        }

        Ok(records)
    }
}
