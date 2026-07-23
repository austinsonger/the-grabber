use anyhow::Result;
use async_trait::async_trait;
use jamf_rs::JamfClient;

use crate::evidence::CsvCollector;

pub struct JamfPatchTitlesCollector {
    client: JamfClient,
}

impl JamfPatchTitlesCollector {
    pub fn new(client: JamfClient) -> Self {
        Self { client }
    }
}

#[async_trait]
impl CsvCollector for JamfPatchTitlesCollector {
    fn name(&self) -> &str {
        "Jamf Patch Titles"
    }
    fn filename_prefix(&self) -> &str {
        "Jamf_Patch_Titles"
    }

    fn headers(&self) -> &'static [&'static str] {
        &["Title ID", "Display Name"]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let titles = match self.client.patch().list_titles().await {
            Ok(t) => t,
            Err(jamf_rs::JamfError::Api { status: 404, .. }) => return Ok(vec![]),
            Err(e) => return Err(e.into()),
        };
        let rows = titles.into_iter().map(|t| vec![t.id, t.display_name]).collect();
        Ok(rows)
    }
}
