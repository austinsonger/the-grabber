use anyhow::{Context, Result};
use async_trait::async_trait;
use aws_sdk_config::Client as ConfigClient;
use aws_sdk_config::types::ResourceType;

use crate::evidence::CsvCollector;

fn fmt_config_dt(dt: &aws_sdk_config::primitives::DateTime) -> String {
    chrono::DateTime::<chrono::Utc>::from_timestamp(dt.secs(), 0)
        .map(|c| c.to_rfc3339())
        .unwrap_or_default()
}

pub struct ConfigHistoryCollector {
    client: ConfigClient,
}

impl ConfigHistoryCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self { client: ConfigClient::new(config) }
    }
}

#[async_trait]
impl CsvCollector for ConfigHistoryCollector {
    fn name(&self) -> &str { "AWS Config Resource History" }
    fn filename_prefix(&self) -> &str { "Config_ResourceHistory" }
    fn headers(&self) -> &'static [&'static str] {
        &["Resource Type", "Resource ID", "Resource Name", "Change Type", "Capture Time", "Config Status"]
    }

    async fn collect_rows(&self, _account_id: &str, _region: &str, _dates: Option<(i64, i64)>) -> Result<Vec<Vec<String>>> {
        let mut rows = Vec::new();

        let resource_types = &[
            "AWS::EC2::SecurityGroup",
            "AWS::EC2::Instance",
            "AWS::IAM::Role",
            "AWS::S3::Bucket",
            "AWS::KMS::Key",
        ];

        for rt_str in resource_types {
            let rt = ResourceType::from(*rt_str);

            // List discovered resources (cap at 20)
            let resources_resp = match self.client
                .list_discovered_resources()
                .resource_type(rt.clone())
                .limit(20)
                .send()
                .await
            {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("  WARN: Config list_discovered_resources {rt_str}: {e:#}");
                    continue;
                }
            };

            for resource in resources_resp.resource_identifiers() {
                let resource_id = resource.resource_id().unwrap_or("").to_string();
                if resource_id.is_empty() { continue; }

                let history_resp = match self.client
                    .get_resource_config_history()
                    .resource_type(rt.clone())
                    .resource_id(&resource_id)
                    .limit(3)
                    .send()
                    .await
                {
                    Ok(r) => r,
                    Err(e) => {
                        eprintln!("  WARN: Config get_resource_config_history {resource_id}: {e:#}");
                        continue;
                    }
                };

                for item in history_resp.configuration_items() {
                    let item_rt = item.resource_type()
                        .map(|t| t.as_str().to_string())
                        .unwrap_or_else(|| rt_str.to_string());
                    let item_id = item.resource_id().unwrap_or("").to_string();
                    let item_name = item.resource_name().unwrap_or("").to_string();
                    let capture_time = item.configuration_item_capture_time()
                        .map(fmt_config_dt)
                        .unwrap_or_default();
                    let status_raw = item.configuration_item_status()
                        .map(|s| s.as_str().to_string())
                        .unwrap_or_default();
                    let change_type = status_to_change_type(&status_raw);

                    rows.push(vec![
                        item_rt,
                        item_id,
                        item_name,
                        change_type,
                        capture_time,
                        status_raw,
                    ]);
                }
            }
        }

        Ok(rows)
    }
}

fn status_to_change_type(status: &str) -> String {
    match status {
        "ResourceDiscovered" => "Created",
        "ResourceDeleted" | "ResourceDeletedNotRecorded" => "Deleted",
        "OK" | "ResourceNotRecorded" => "Modified",
        _ => "Unknown",
    }.to_string()
}
