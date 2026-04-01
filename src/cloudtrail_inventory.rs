use anyhow::{Context, Result};
use async_trait::async_trait;
use aws_sdk_cloudtrail::Client as CtClient;

use crate::evidence::CsvCollector;

pub struct CloudTrailInventoryCollector {
    client: CtClient,
}

impl CloudTrailInventoryCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self { client: CtClient::new(config) }
    }
}

#[async_trait]
impl CsvCollector for CloudTrailInventoryCollector {
    fn name(&self) -> &str { "CloudTrail Logs" }
    fn filename_prefix(&self) -> &str { "CloudTrail_Logs" }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Cloud Trail Name",
            "Apply Trail To All Regions",
            "Log File Validation",
            "S3 Bucket",
            "Cloud Watch Logs Log Group ARN",
            "Is Logging",
            "Include Management Events",
            "Read/Write Type",
        ]
    }

    async fn collect_rows(&self, _account_id: &str, _region: &str) -> Result<Vec<Vec<String>>> {
        let mut rows = Vec::new();

        let resp = self.client.describe_trails()
            .include_shadow_trails(false)
            .send()
            .await
            .context("CloudTrail describe_trails")?;

        for trail in resp.trail_list() {
            let name = trail.name().unwrap_or("").to_string();
            let multi_region = bool_yn(trail.is_multi_region_trail());
            let validation    = bool_yn(trail.log_file_validation_enabled());
            let s3_bucket     = trail.s3_bucket_name().unwrap_or("").to_string();
            let cw_log_group  = trail.cloud_watch_logs_log_group_arn().unwrap_or("").to_string();

            // Fetch logging status.
            let is_logging = match self.client
                .get_trail_status()
                .name(&name)
                .send()
                .await
            {
                Ok(s) => bool_yn(s.is_logging()),
                Err(_) => "".to_string(),
            };

            // Fetch event selectors for management events + read/write type.
            let (include_mgmt, rw_type) = match self.client
                .get_event_selectors()
                .trail_name(&name)
                .send()
                .await
            {
                Ok(es) => {
                    let sel = es.event_selectors();
                    let mgmt = sel.first()
                        .and_then(|s| s.include_management_events())
                        .map(|b| if b { "Yes" } else { "No" })
                        .unwrap_or("")
                        .to_string();
                    let rw = sel.first()
                        .and_then(|s| s.read_write_type())
                        .map(|t| t.as_str().to_string())
                        .unwrap_or_default();
                    (mgmt, rw)
                }
                Err(_) => ("".to_string(), "".to_string()),
            };

            rows.push(vec![
                name, multi_region, validation, s3_bucket,
                cw_log_group, is_logging, include_mgmt, rw_type,
            ]);
        }

        Ok(rows)
    }
}

fn bool_yn(val: Option<bool>) -> String {
    match val {
        Some(true)  => "Yes".to_string(),
        Some(false) => "No".to_string(),
        None        => "".to_string(),
    }
}
