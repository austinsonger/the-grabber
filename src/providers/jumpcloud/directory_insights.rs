use anyhow::Result;
use async_trait::async_trait;
use jumpcloud_rs::types::pagination::InsightsEventsQuery;
use jumpcloud_rs::JumpCloudClient;

use crate::evidence::{CollectParams, EvidenceCollector, EvidenceRecord, EvidenceSource};

pub struct JumpCloudDirectoryInsightsCollector {
    client: JumpCloudClient,
}

impl JumpCloudDirectoryInsightsCollector {
    pub fn new(client: JumpCloudClient) -> Self {
        Self { client }
    }
}

#[async_trait]
impl EvidenceCollector for JumpCloudDirectoryInsightsCollector {
    fn name(&self) -> &str {
        "JumpCloud Directory Insights"
    }

    fn filename_prefix(&self) -> &str {
        "JumpCloud_DirectoryInsights"
    }

    async fn collect(&self, params: &CollectParams) -> Result<Vec<EvidenceRecord>> {
        let query = InsightsEventsQuery {
            service: vec![
                "directory".to_string(),
                "systems".to_string(),
                "radius".to_string(),
                "sso".to_string(),
                "ldap".to_string(),
                "mdm".to_string(),
                "alerts".to_string(),
            ],
            start_time: params.start_time.format("%Y-%m-%dT%H:%M:%SZ").to_string(),
            end_time: params.end_time.format("%Y-%m-%dT%H:%M:%SZ").to_string(),
            search_after: None,
            limit: 100,
        };

        let events = match self.client.insights().events(&query).await {
            Ok(events) => events,
            Err(jumpcloud_rs::JumpCloudError::Api { status: 404, .. }) => return Ok(vec![]),
            Err(e) => return Err(e.into()),
        };

        let records = events
            .into_iter()
            .map(|e| EvidenceRecord {
                source: EvidenceSource::JumpCloudDirectoryInsights,
                event_name: e.event_type.clone(),
                timestamp: e.timestamp.clone(),
                job_id: None,
                plan_id: None,
                resource_arn: None,
                resource_type: Some(e.service.clone()),
                status: e.success.map(|s| {
                    if s {
                        "SUCCESS".to_string()
                    } else {
                        "FAILURE".to_string()
                    }
                }),
                completion_timestamp: None,
                raw: if params.include_raw {
                    serde_json::to_value(&e).ok()
                } else {
                    None
                },
            })
            .collect();

        Ok(records)
    }
}
