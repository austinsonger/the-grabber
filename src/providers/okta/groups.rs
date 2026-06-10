use anyhow::Result;
use async_trait::async_trait;
use okta_rs::OktaClient;
use serde_json::json;

use crate::evidence::{CsvCollector, JsonCollector};

pub struct OktaGroupsCollector {
    client: OktaClient,
}

impl OktaGroupsCollector {
    pub fn new(client: OktaClient) -> Self {
        Self { client }
    }
}

#[async_trait]
impl CsvCollector for OktaGroupsCollector {
    fn name(&self) -> &str {
        "Okta Groups"
    }
    fn filename_prefix(&self) -> &str {
        "Okta_Groups"
    }

    fn headers(&self) -> &'static [&'static str] {
        &[
            "Group ID",
            "Name",
            "Type",
            "Description",
            "Created",
            "Last Updated",
            "Last Membership Updated",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let groups = match self.client.groups().list_all().await {
            Ok(g) => g,
            Err(okta_rs::OktaError::Api { status: 404, .. }) => return Ok(vec![]),
            Err(e) => return Err(e.into()),
        };
        let rows = groups
            .into_iter()
            .map(|g| {
                vec![
                    g.id,
                    g.profile.name,
                    g.group_type,
                    g.profile.description.unwrap_or_default(),
                    g.created.unwrap_or_default(),
                    g.last_updated.unwrap_or_default(),
                    g.last_membership_updated.unwrap_or_default(),
                ]
            })
            .collect();
        Ok(rows)
    }
}

pub struct OktaGroupMembersCollector {
    client: OktaClient,
}

impl OktaGroupMembersCollector {
    pub fn new(client: OktaClient) -> Self {
        Self { client }
    }
}

#[async_trait]
impl JsonCollector for OktaGroupMembersCollector {
    fn name(&self) -> &str {
        "Okta Group Members"
    }
    fn filename_prefix(&self) -> &str {
        "Okta_Group_Members"
    }

    async fn collect_records(
        &self,
        _account_id: &str,
        _region: &str,
    ) -> Result<Vec<serde_json::Value>> {
        let groups = match self.client.groups().list_all().await {
            Ok(g) => g,
            Err(okta_rs::OktaError::Api { status: 404, .. }) => return Ok(vec![]),
            Err(e) => return Err(e.into()),
        };
        let mut out = Vec::with_capacity(groups.len());
        for g in groups {
            // Skip member fan-out for built-in "Everyone" group: it duplicates user count
            // and is rarely useful for evidence.
            let is_everyone = g.profile.name == "Everyone";
            let members = if is_everyone {
                Vec::new()
            } else {
                match self.client.groups().list_members(&g.id).await {
                    Ok(m) => m,
                    Err(okta_rs::OktaError::Api { status: 404, .. }) => Vec::new(),
                    Err(e) => return Err(e.into()),
                }
            };
            let member_summaries: Vec<serde_json::Value> = members
                .into_iter()
                .map(|u| {
                    json!({
                        "id": u.id,
                        "login": u.profile.login,
                        "email": u.profile.email,
                        "status": u.status,
                    })
                })
                .collect();
            out.push(json!({
                "group_id": g.id,
                "group_name": g.profile.name,
                "group_type": g.group_type,
                "member_count": member_summaries.len(),
                "members": member_summaries,
                "members_skipped_built_in": is_everyone,
            }));
        }
        Ok(out)
    }
}
