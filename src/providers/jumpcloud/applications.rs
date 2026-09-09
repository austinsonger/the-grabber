use anyhow::Result;
use async_trait::async_trait;
use jumpcloud_rs::JumpCloudClient;

use crate::evidence::CsvCollector;

pub struct JumpCloudApplicationsCollector {
    client: JumpCloudClient,
}

impl JumpCloudApplicationsCollector {
    pub fn new(client: JumpCloudClient) -> Self {
        Self { client }
    }
}

#[async_trait]
impl CsvCollector for JumpCloudApplicationsCollector {
    fn name(&self) -> &str {
        "JumpCloud Applications"
    }
    fn filename_prefix(&self) -> &str {
        "JumpCloud_Applications"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Application ID",
            "Name",
            "Display Label",
            "Active",
            "SSO URL",
            "SSO Type",
            "Description",
            "Created",
        ]
    }
    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let apps = match self.client.applications().list_all().await {
            Ok(a) => a,
            Err(jumpcloud_rs::JumpCloudError::Api { status: 404, .. }) => return Ok(vec![]),
            Err(e) => return Err(e.into()),
        };
        let rows = apps
            .into_iter()
            .map(|a| {
                let sso_type = a
                    .sso
                    .as_ref()
                    .and_then(|v| v.get("type"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                vec![
                    a.id,
                    a.name,
                    a.display_label.unwrap_or_default(),
                    a.active.to_string(),
                    a.sso_url.unwrap_or_default(),
                    sso_type,
                    a.description.unwrap_or_default(),
                    a.created.unwrap_or_default(),
                ]
            })
            .collect();
        Ok(rows)
    }
}
