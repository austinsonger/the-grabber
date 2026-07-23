use anyhow::Result;
use async_trait::async_trait;
use jamf_rs::JamfClient;

use crate::evidence::JsonCollector;

pub struct JamfPoliciesCollector {
    client: JamfClient,
}

impl JamfPoliciesCollector {
    pub fn new(client: JamfClient) -> Self {
        Self { client }
    }
}

#[async_trait]
impl JsonCollector for JamfPoliciesCollector {
    fn name(&self) -> &str {
        "Jamf Policies"
    }
    fn filename_prefix(&self) -> &str {
        "Jamf_Policies"
    }

    async fn collect_records(
        &self,
        _account_id: &str,
        _region: &str,
    ) -> Result<Vec<serde_json::Value>> {
        let policies = match self.client.policies().list_all().await {
            Ok(p) => p,
            Err(jamf_rs::JamfError::Api { status: 404, .. }) => return Ok(vec![]),
            Err(e) => return Err(e.into()),
        };
        Ok(policies
            .into_iter()
            .map(|p| serde_json::to_value(p).unwrap_or(serde_json::Value::Null))
            .collect())
    }
}
