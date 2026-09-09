use anyhow::Result;
use async_trait::async_trait;
use jumpcloud_rs::JumpCloudClient;
use serde_json::json;

use crate::evidence::{CsvCollector, JsonCollector};

pub struct JumpCloudSystemGroupsCollector {
    client: JumpCloudClient,
}
impl JumpCloudSystemGroupsCollector {
    pub fn new(client: JumpCloudClient) -> Self {
        Self { client }
    }
}

#[async_trait]
impl CsvCollector for JumpCloudSystemGroupsCollector {
    fn name(&self) -> &str {
        "JumpCloud System Groups"
    }
    fn filename_prefix(&self) -> &str {
        "JumpCloud_SystemGroups"
    }
    fn headers(&self) -> &'static [&'static str] {
        &["Group ID", "Name", "Type", "Description"]
    }
    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let groups = match self.client.system_groups().list_all().await {
            Ok(g) => g,
            Err(jumpcloud_rs::JumpCloudError::Api { status: 404, .. }) => return Ok(vec![]),
            Err(e) => return Err(e.into()),
        };
        let rows = groups
            .into_iter()
            .map(|g| vec![g.id, g.name, g.kind, g.description.unwrap_or_default()])
            .collect();
        Ok(rows)
    }
}

pub struct JumpCloudSystemGroupMembersCollector {
    client: JumpCloudClient,
}
impl JumpCloudSystemGroupMembersCollector {
    pub fn new(client: JumpCloudClient) -> Self {
        Self { client }
    }
}

#[async_trait]
impl JsonCollector for JumpCloudSystemGroupMembersCollector {
    fn name(&self) -> &str {
        "JumpCloud System Group Members"
    }
    fn filename_prefix(&self) -> &str {
        "JumpCloud_SystemGroupMembers"
    }
    async fn collect_records(
        &self,
        _account_id: &str,
        _region: &str,
    ) -> Result<Vec<serde_json::Value>> {
        let groups = match self.client.system_groups().list_all().await {
            Ok(g) => g,
            Err(jumpcloud_rs::JumpCloudError::Api { status: 404, .. }) => return Ok(vec![]),
            Err(e) => return Err(e.into()),
        };
        let ids: Vec<(String, String)> = groups
            .iter()
            .map(|g| (g.id.clone(), g.name.clone()))
            .collect();

        let client = self.client.clone();
        let results = client
            .fan_out(ids.iter().map(|(id, _)| id.clone()).collect(), 8, |id| {
                let c = client.clone();
                async move { c.system_groups().list_members(&id).await }
            })
            .await;

        let mut out = Vec::new();
        for (id, res) in results {
            let name = ids
                .iter()
                .find(|(gid, _)| gid == &id)
                .map(|(_, n)| n.clone())
                .unwrap_or_default();
            match res {
                Ok(members) => out.push(json!({
                    "group_id": id,
                    "name": name,
                    "members": members,
                })),
                Err(e) => out.push(json!({
                    "group_id": id,
                    "name": name,
                    "error": e.to_string(),
                })),
            }
        }
        Ok(out)
    }
}
