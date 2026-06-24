use anyhow::Result;
use async_trait::async_trait;
use okta_rs::OktaClient;

use crate::evidence::CsvCollector;

pub struct OktaAppsCollector {
    client: OktaClient,
}
impl OktaAppsCollector {
    pub fn new(client: OktaClient) -> Self {
        Self { client }
    }
}

#[async_trait]
impl CsvCollector for OktaAppsCollector {
    fn name(&self) -> &str {
        "Okta Applications"
    }
    fn filename_prefix(&self) -> &str {
        "Okta_Applications"
    }

    fn headers(&self) -> &'static [&'static str] {
        &[
            "App ID",
            "Name",
            "Label",
            "Status",
            "Sign-On Mode",
            "Created",
            "Last Updated",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let apps = match self.client.apps().list_all().await {
            Ok(a) => a,
            Err(okta_rs::OktaError::Api { status: 404, .. }) => return Ok(vec![]),
            Err(e) => return Err(e.into()),
        };
        let rows = apps
            .into_iter()
            .map(|a| {
                vec![
                    a.id,
                    a.name,
                    a.label,
                    a.status,
                    a.sign_on_mode.unwrap_or_default(),
                    a.created.unwrap_or_default(),
                    a.last_updated.unwrap_or_default(),
                ]
            })
            .collect();
        Ok(rows)
    }
}
