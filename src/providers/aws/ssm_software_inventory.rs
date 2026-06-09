use anyhow::Result;
use async_trait::async_trait;
use aws_sdk_ssm::Client as SsmClient;

use crate::evidence::CsvCollector;

pub struct SsmSoftwareInventoryCollector {
    client: SsmClient,
}

impl SsmSoftwareInventoryCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self {
            client: SsmClient::new(config),
        }
    }
}

#[async_trait]
impl CsvCollector for SsmSoftwareInventoryCollector {
    fn name(&self) -> &str {
        "SSM Software Inventory"
    }
    fn filename_prefix(&self) -> &str {
        "SSM_Software_Inventory"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Instance ID",
            "Application Name",
            "Version",
            "Publisher",
            "Architecture",
            "Install Time",
            "Package ID",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let mut rows = Vec::new();
        let mut next_token: Option<String> = None;

        loop {
            let mut req = self.client.get_inventory();
            if let Some(ref t) = next_token {
                req = req.next_token(t);
            }
            let resp = match req.send().await {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("  WARN: ssm get_inventory: {e:#}");
                    break;
                }
            };

            for entity in resp.entities() {
                let instance_id = entity.id().unwrap_or("").to_string();
                // data() returns Option<&HashMap<String, InventoryResultItem>>
                let Some(data) = entity.data() else {
                    continue;
                };
                let Some(app_data) = data.get("AWS:Application") else {
                    continue;
                };
                // content() returns &[HashMap<String, String>]
                for content in app_data.content() {
                    let name = content.get("Name").cloned().unwrap_or_default();
                    let version = content.get("Version").cloned().unwrap_or_default();
                    let publisher = content.get("Publisher").cloned().unwrap_or_default();
                    let arch = content.get("Architecture").cloned().unwrap_or_default();
                    let install_time = content.get("InstalledTime").cloned().unwrap_or_default();
                    let pkg_id = content.get("PackageId").cloned().unwrap_or_default();
                    rows.push(vec![
                        instance_id.clone(),
                        name,
                        version,
                        publisher,
                        arch,
                        install_time,
                        pkg_id,
                    ]);
                }
            }

            next_token = resp.next_token().map(|s| s.to_string());
            if next_token.is_none() {
                break;
            }
        }

        Ok(rows)
    }
}
