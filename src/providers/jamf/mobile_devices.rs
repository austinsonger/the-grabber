use anyhow::Result;
use async_trait::async_trait;
use jamf_rs::JamfClient;

use crate::evidence::CsvCollector;

pub struct JamfMobileDevicesCollector {
    client: JamfClient,
}

impl JamfMobileDevicesCollector {
    pub fn new(client: JamfClient) -> Self {
        Self { client }
    }
}

#[async_trait]
impl CsvCollector for JamfMobileDevicesCollector {
    fn name(&self) -> &str {
        "Jamf Mobile Devices"
    }
    fn filename_prefix(&self) -> &str {
        "Jamf_Mobile_Devices"
    }

    fn headers(&self) -> &'static [&'static str] {
        &[
            "Device ID",
            "Name",
            "Serial Number",
            "Model",
            "OS Version",
            "Last Enrolled",
            "Managed",
            "Supervised",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let devices = match self.client.mobile_devices().list_all().await {
            Ok(d) => d,
            Err(jamf_rs::JamfError::Api { status: 404, .. }) => return Ok(vec![]),
            Err(e) => return Err(e.into()),
        };
        let rows = devices
            .into_iter()
            .map(|d| {
                vec![
                    d.id,
                    d.name,
                    d.serial_number,
                    d.model,
                    d.os_version,
                    d.last_enrolled_date.unwrap_or_default(),
                    d.managed.to_string(),
                    d.supervised.to_string(),
                ]
            })
            .collect();
        Ok(rows)
    }
}
