use anyhow::Result;
use async_trait::async_trait;
use jumpcloud_rs::JumpCloudClient;
use serde_json::json;

use crate::evidence::JsonCollector;

pub struct JumpCloudSystemUserAssociationsCollector {
    client: JumpCloudClient,
}
impl JumpCloudSystemUserAssociationsCollector {
    pub fn new(client: JumpCloudClient) -> Self {
        Self { client }
    }
}

#[async_trait]
impl JsonCollector for JumpCloudSystemUserAssociationsCollector {
    fn name(&self) -> &str {
        "JumpCloud System-User Associations"
    }
    fn filename_prefix(&self) -> &str {
        "JumpCloud_SystemUserAssociations"
    }
    async fn collect_records(
        &self,
        _account_id: &str,
        _region: &str,
    ) -> Result<Vec<serde_json::Value>> {
        let systems = match self.client.systems().list_all().await {
            Ok(s) => s,
            Err(jumpcloud_rs::JumpCloudError::Api { status: 404, .. }) => {
                return Ok(vec![])
            }
            Err(e) => return Err(e.into()),
        };
        let ids: Vec<(String, String)> = systems
            .iter()
            .map(|s| (s.id.clone(), s.hostname.clone()))
            .collect();

        let client = self.client.clone();
        let results = client
            .fan_out(
                ids.iter().map(|(id, _)| id.clone()).collect(),
                8,
                |id| {
                    let c = client.clone();
                    async move { c.systems().list_users(&id).await }
                },
            )
            .await;

        let mut out = Vec::new();
        for (id, res) in results {
            let hostname = ids
                .iter()
                .find(|(sid, _)| sid == &id)
                .map(|(_, h)| h.clone())
                .unwrap_or_default();
            match res {
                Ok(users) => out.push(json!({
                    "system_id": id,
                    "hostname": hostname,
                    "user_count": users.len(),
                    "users": users,
                })),
                Err(e) => out.push(json!({
                    "system_id": id,
                    "hostname": hostname,
                    "error": e.to_string(),
                })),
            }
        }
        Ok(out)
    }
}
