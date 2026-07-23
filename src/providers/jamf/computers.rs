use anyhow::Result;
use async_trait::async_trait;
use jamf_rs::JamfClient;

use crate::evidence::CsvCollector;

pub struct JamfComputersCollector {
    client: JamfClient,
}

impl JamfComputersCollector {
    pub fn new(client: JamfClient) -> Self {
        Self { client }
    }
}

#[async_trait]
impl CsvCollector for JamfComputersCollector {
    fn name(&self) -> &str {
        "Jamf Computers"
    }
    fn filename_prefix(&self) -> &str {
        "Jamf_Computers"
    }

    fn headers(&self) -> &'static [&'static str] {
        &[
            "Computer ID",
            "Name",
            "Serial Number",
            "Model",
            "OS Version",
            "Last Contact Time",
            "Managed",
            "FileVault Status",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let computers = match self.client.computers().list_all().await {
            Ok(c) => c,
            Err(jamf_rs::JamfError::Api { status: 404, .. }) => return Ok(vec![]),
            Err(e) => return Err(e.into()),
        };
        let rows = computers
            .into_iter()
            .map(|c| {
                vec![
                    c.id,
                    c.general.name,
                    c.hardware.serial_number,
                    c.hardware.model,
                    c.operating_system.version,
                    c.general.last_contact_time.unwrap_or_default(),
                    c.general.remote_management.managed.to_string(),
                    c.security.filevault2_status,
                ]
            })
            .collect();
        Ok(rows)
    }
}
