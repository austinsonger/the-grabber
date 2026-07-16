use anyhow::Result;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use okta_rs::OktaClient;

use crate::evidence::CsvCollector;

pub struct OktaTransferAccessDiffCollector {
    client: OktaClient,
}

impl OktaTransferAccessDiffCollector {
    pub fn new(client: OktaClient) -> Self {
        Self { client }
    }
}

#[async_trait]
impl CsvCollector for OktaTransferAccessDiffCollector {
    fn name(&self) -> &str {
        "Okta Transfer Access Diff"
    }
    fn filename_prefix(&self) -> &str {
        "Okta_Transfer_Access_Diff"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "User ID",
            "Login",
            "Status",
            "Status Changed",
            "Apps Count",
            "Groups Count",
            "Snapshot Time",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let users = match self.client.users().list_all().await {
            Ok(u) => u,
            Err(okta_rs::OktaError::Api { status: 404, .. }) => return Ok(vec![]),
            Err(e) => return Err(e.into()),
        };

        let cutoff = Utc::now() - chrono::Duration::days(90);
        let snapshot_time = Utc::now().to_rfc3339();

        // TODO: no per-user apps/groups list endpoint in okta-rs yet; Apps Count
        // and Groups Count are left empty until UsersApi grows list_apps/list_groups.
        let rows = users
            .into_iter()
            .filter(|u| {
                u.status_changed
                    .as_deref()
                    .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
                    .map(|dt| dt.with_timezone(&Utc) >= cutoff)
                    .unwrap_or(false)
            })
            .map(|u| {
                vec![
                    u.id,
                    u.profile.login,
                    u.status,
                    u.status_changed.unwrap_or_default(),
                    String::new(),
                    String::new(),
                    snapshot_time.clone(),
                ]
            })
            .collect();

        Ok(rows)
    }
}
