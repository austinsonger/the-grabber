use anyhow::Result;
use async_trait::async_trait;
use jumpcloud_rs::JumpCloudClient;

use crate::evidence::JsonCollector;

pub struct JumpCloudPoliciesCollector {
    client: JumpCloudClient,
}

impl JumpCloudPoliciesCollector {
    pub fn new(client: JumpCloudClient) -> Self {
        Self { client }
    }
}

#[async_trait]
impl JsonCollector for JumpCloudPoliciesCollector {
    fn name(&self) -> &str {
        "JumpCloud Policies"
    }

    fn filename_prefix(&self) -> &str {
        "JumpCloud_Policies"
    }

    async fn collect_records(
        &self,
        _account_id: &str,
        _region: &str,
    ) -> Result<Vec<serde_json::Value>> {
        let policies = match self.client.policies().list_all().await {
            Ok(p) => p,
            Err(jumpcloud_rs::JumpCloudError::Api { status: 404, .. }) => return Ok(vec![]),
            Err(e) => return Err(e.into()),
        };

        let records = policies
            .into_iter()
            .map(|policy| serde_json::to_value(&policy).unwrap_or(serde_json::Value::Null))
            .collect();

        Ok(records)
    }
}
