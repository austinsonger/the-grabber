use anyhow::Result;
use async_trait::async_trait;
use jamf_rs::JamfClient;

use crate::evidence::CsvCollector;

pub struct JamfPatchComplianceCollector {
    client: JamfClient,
}

impl JamfPatchComplianceCollector {
    pub fn new(client: JamfClient) -> Self {
        Self { client }
    }
}

#[async_trait]
impl CsvCollector for JamfPatchComplianceCollector {
    fn name(&self) -> &str {
        "Jamf Patch Compliance"
    }
    fn filename_prefix(&self) -> &str {
        "Jamf_Patch_Compliance"
    }

    fn headers(&self) -> &'static [&'static str] {
        &[
            "Title ID",
            "Display Name",
            "Latest Version",
            "Compliant Devices",
            "Out Of Date Devices",
        ]
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
        let mut rows = Vec::with_capacity(titles.len());
        for title in titles {
            let summary = match self.client.patch().summary(&title.id).await {
                Ok(s) => s,
                Err(jamf_rs::JamfError::Api { status: 404, .. }) => continue,
                Err(e) => return Err(e.into()),
            };
            rows.push(vec![
                title.id,
                title.display_name,
                summary.latest_version.clone(),
                summary.compliant_count().to_string(),
                summary.out_of_date_count().to_string(),
            ]);
        }
        Ok(rows)
    }
}
