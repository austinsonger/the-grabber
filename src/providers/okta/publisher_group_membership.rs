use anyhow::Result;
use async_trait::async_trait;
use okta_rs::OktaClient;

use crate::evidence::CsvCollector;

const PUBLISHER_KEYWORDS: &[&str] =
    &["publisher", "content-editor", "cms", "wiki-admin"];

pub struct OktaPublisherGroupMembershipCollector {
    client: OktaClient,
}

impl OktaPublisherGroupMembershipCollector {
    pub fn new(client: OktaClient) -> Self {
        Self { client }
    }
}

#[async_trait]
impl CsvCollector for OktaPublisherGroupMembershipCollector {
    fn name(&self) -> &str {
        "Okta Publisher Group Membership"
    }
    fn filename_prefix(&self) -> &str {
        "Okta_Publisher_Group_Membership"
    }
    fn headers(&self) -> &'static [&'static str] {
        &["Group ID", "Group Name", "Member ID", "Member Login"]
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

        let matching: Vec<_> = groups
            .into_iter()
            .filter(|g| {
                let name_lower = g.profile.name.to_lowercase();
                PUBLISHER_KEYWORDS
                    .iter()
                    .any(|kw| name_lower.contains(kw))
            })
            .collect();

        let mut rows: Vec<Vec<String>> = Vec::new();
        // TODO(okta-rs): GroupsApi::list_members exists and is used here to
        // fan out members per matching group.
        for g in matching {
            let members = match self.client.groups().list_members(&g.id).await {
                Ok(m) => m,
                Err(okta_rs::OktaError::Api { status: 404, .. }) => Vec::new(),
                Err(e) => return Err(e.into()),
            };
            if members.is_empty() {
                rows.push(vec![
                    g.id.clone(),
                    g.profile.name.clone(),
                    String::new(),
                    String::new(),
                ]);
                continue;
            }
            for u in members {
                rows.push(vec![
                    g.id.clone(),
                    g.profile.name.clone(),
                    u.id,
                    u.profile.login,
                ]);
            }
        }

        Ok(rows)
    }
}
