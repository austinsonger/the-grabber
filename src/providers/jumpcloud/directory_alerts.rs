use anyhow::Result;
use async_trait::async_trait;
use jumpcloud_rs::types::pagination::InsightsAlertsQuery;
use jumpcloud_rs::JumpCloudClient;

use crate::evidence::{CollectParams, EvidenceCollector, EvidenceRecord, EvidenceSource};

pub struct JumpCloudDirectoryAlertsCollector {
    client: JumpCloudClient,
}

impl JumpCloudDirectoryAlertsCollector {
    pub fn new(client: JumpCloudClient) -> Self {
        Self { client }
    }
}

#[async_trait]
impl EvidenceCollector for JumpCloudDirectoryAlertsCollector {
    fn name(&self) -> &str {
        "JumpCloud Directory Alerts"
    }

    fn filename_prefix(&self) -> &str {
        "JumpCloud_DirectoryAlerts"
    }

    async fn collect(&self, params: &CollectParams) -> Result<Vec<EvidenceRecord>> {
        let query = InsightsAlertsQuery {
            start_time: params.start_time.format("%Y-%m-%dT%H:%M:%SZ").to_string(),
            end_time: params.end_time.format("%Y-%m-%dT%H:%M:%SZ").to_string(),
            limit: 100,
        };

        let alerts = match self.client.insights().alerts(&query).await {
            Ok(alerts) => alerts,
            Err(jumpcloud_rs::JumpCloudError::Api { status: 404, .. }) => return Ok(vec![]),
            Err(e) => return Err(e.into()),
        };

        let records = alerts
            .into_iter()
            .map(|a| EvidenceRecord {
                source: EvidenceSource::JumpCloudDirectoryAlerts,
                event_name: a.alert_type.clone(),
                timestamp: a
                    .last_occurred
                    .clone()
                    .or_else(|| a.first_occurred.clone())
                    .unwrap_or_default(),
                job_id: None,
                plan_id: None,
                resource_arn: None,
                resource_type: None,
                status: Some(a.status.clone()),
                completion_timestamp: None,
                raw: if params.include_raw {
                    serde_json::to_value(&a).ok()
                } else {
                    None
                },
            })
            .collect();

        Ok(records)
    }
}
