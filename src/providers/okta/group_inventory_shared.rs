use anyhow::Result;
use async_trait::async_trait;
use okta_rs::OktaClient;

use crate::evidence::CsvCollector;

const SHARED_TOKENS: &[&str] = &["shared", "service", "svc", "team-", "role-", "svc_"];

pub struct OktaGroupInventorySharedCollector {
    client: OktaClient,
}

impl OktaGroupInventorySharedCollector {
    pub fn new(client: OktaClient) -> Self {
        Self { client }
    }
}

#[async_trait]
impl CsvCollector for OktaGroupInventorySharedCollector {
    fn name(&self) -> &str {
        "Okta Group Inventory (Shared Accounts)"
    }
    fn filename_prefix(&self) -> &str {
        "Okta_Group_Inventory_Shared_Accounts"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Group ID",
            "Name",
            "Type",
            "Description",
            "Members Count",
            "Shared Naming Match",
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
                let name_lower = g.profile.name.to_lowercase();
                let matched = SHARED_TOKENS
                    .iter()
                    .find(|tok| name_lower.contains(*tok))
                    .map(|tok| tok.to_string())
                    .unwrap_or_default();

                vec![
                    g.id,
                    g.profile.name,
                    g.group_type,
                    g.profile.description.unwrap_or_default(),
                    String::new(),
                    matched,
                ]
            })
            .collect();

        Ok(rows)
    }
}
