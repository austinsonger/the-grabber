use anyhow::Result;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use okta_rs::OktaClient;

use crate::evidence::CsvCollector;

pub struct OktaGroupMembershipChangeLogCollector {
    client: OktaClient,
}

impl OktaGroupMembershipChangeLogCollector {
    pub fn new(client: OktaClient) -> Self {
        Self { client }
    }
}

#[async_trait]
impl CsvCollector for OktaGroupMembershipChangeLogCollector {
    fn name(&self) -> &str {
        "Okta Group Membership Change Log"
    }
    fn filename_prefix(&self) -> &str {
        "Okta_Group_Membership_Change_Log"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Event ID",
            "Published",
            "Actor",
            "Change Type",
            "Target Group",
            "Target User",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let since_iso = dates
            .map(|(s, _)| DateTime::<Utc>::from_timestamp(s, 0).unwrap_or_else(Utc::now))
            .unwrap_or_else(|| Utc::now() - chrono::Duration::days(90))
            .to_rfc3339();

        let adds = match self
            .client
            .lifecycle()
            .events_all("group.user_membership.add", &since_iso)
            .await
        {
            Ok(e) => e,
            Err(okta_rs::OktaError::Api { status: 404, .. }) => vec![],
            Err(e) => return Err(e.into()),
        };

        let removes = match self
            .client
            .lifecycle()
            .events_all("group.user_membership.remove", &since_iso)
            .await
        {
            Ok(e) => e,
            Err(okta_rs::OktaError::Api { status: 404, .. }) => vec![],
            Err(e) => return Err(e.into()),
        };

        let mut rows = Vec::with_capacity(adds.len() + removes.len());

        for (events, change_type) in [(adds, "ADD"), (removes, "REMOVE")] {
            for e in events {
                let target_arr = e.target.as_array();
                let group_target = target_arr.and_then(|a| {
                    a.iter()
                        .find(|t| t.get("type").and_then(|v| v.as_str()) == Some("UserGroup"))
                });
                let user_target = target_arr.and_then(|a| {
                    a.iter()
                        .find(|t| t.get("type").and_then(|v| v.as_str()) == Some("User"))
                });

                let target_group = group_target
                    .and_then(|t| t.get("displayName").and_then(|v| v.as_str()))
                    .unwrap_or("")
                    .to_string();
                let target_user = user_target
                    .and_then(|t| t.get("alternateId").and_then(|v| v.as_str()))
                    .unwrap_or("")
                    .to_string();

                let actor = e
                    .actor
                    .as_ref()
                    .and_then(|a| a.display_name.clone())
                    .unwrap_or_default();

                rows.push(vec![
                    e.uuid,
                    e.published,
                    actor,
                    change_type.to_string(),
                    target_group,
                    target_user,
                ]);
            }
        }

        Ok(rows)
    }
}
