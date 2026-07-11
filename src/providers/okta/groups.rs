use anyhow::Result;
use async_trait::async_trait;
use okta_rs::OktaClient;

use crate::evidence::CsvCollector;

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
impl CsvCollector for OktaGroupMembersCollector {
    fn name(&self) -> &str {
        "Okta Group Members"
    }
    fn filename_prefix(&self) -> &str {
        "Okta_Group_Members"
    }

    fn headers(&self) -> &'static [&'static str] {
        &[
            "Group ID",
            "Group Name",
            "Group Type",
            "Member ID",
            "Member Login",
            "Member Email",
            "Member Status",
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
        let mut rows: Vec<Vec<String>> = Vec::new();
        for g in groups {
            // Skip member fan-out for built-in "Everyone" group: it duplicates user count
            // and is rarely useful for evidence.
            let is_everyone = g.profile.name == "Everyone";
            if is_everyone {
                // Still emit one row so the group appears in the CSV.
                rows.push(vec![
                    g.id.clone(),
                    g.profile.name.clone(),
                    g.group_type.clone(),
                    String::new(),
                    String::new(),
                    String::new(),
                    String::new(),
                ]);
                continue;
            }
            let members = match self.client.groups().list_members(&g.id).await {
                Ok(m) => m,
                Err(okta_rs::OktaError::Api { status: 404, .. }) => Vec::new(),
                Err(e) => return Err(e.into()),
            };
            if members.is_empty() {
                rows.push(vec![
                    g.id.clone(),
                    g.profile.name.clone(),
                    g.group_type.clone(),
                    String::new(),
                    String::new(),
                    String::new(),
                    String::new(),
                ]);
                continue;
            }
            for u in members {
                rows.push(vec![
                    g.id.clone(),
                    g.profile.name.clone(),
                    g.group_type.clone(),
                    u.id,
                    u.profile.login,
                    u.profile.email,
                    u.status,
                ]);
            }
        }
        Ok(rows)
    }
}
