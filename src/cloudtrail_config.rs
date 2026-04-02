use anyhow::{Context, Result};
use async_trait::async_trait;
use aws_sdk_cloudtrail::Client as CtClient;

use crate::evidence::CsvCollector;

pub struct CloudTrailFullConfigCollector {
    client: CtClient,
}

impl CloudTrailFullConfigCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self { client: CtClient::new(config) }
    }
}

#[async_trait]
impl CsvCollector for CloudTrailFullConfigCollector {
    fn name(&self) -> &str { "CloudTrail Configuration" }
    fn filename_prefix(&self) -> &str { "CloudTrail_Config" }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Trail Name", "Trail ARN", "Is Multi-Region", "Home Region",
            "Log File Validation", "S3 Bucket", "Is Logging",
            "Event Selectors", "Insight Selectors",
        ]
    }

    async fn collect_rows(&self, _account_id: &str, _region: &str) -> Result<Vec<Vec<String>>> {
        let mut rows = Vec::new();

        let trails_resp = self.client
            .describe_trails()
            .include_shadow_trails(false)
            .send()
            .await
            .context("CloudTrail describe_trails")?;

        for trail in trails_resp.trail_list() {
            let name       = trail.name().unwrap_or("").to_string();
            let trail_arn  = trail.trail_arn().unwrap_or("").to_string();
            let multi      = trail.is_multi_region_trail().unwrap_or(false).to_string();
            let home_region = trail.home_region().unwrap_or("").to_string();
            let validation = trail.log_file_validation_enabled().unwrap_or(false).to_string();
            let bucket     = trail.s3_bucket_name().unwrap_or("").to_string();

            // Is logging status
            let is_logging = match self.client
                .get_trail_status()
                .name(&trail_arn)
                .send()
                .await
            {
                Ok(r) => r.is_logging().unwrap_or(false).to_string(),
                Err(_) => "Unknown".to_string(),
            };

            // Event selectors
            let event_selectors = match self.client
                .get_event_selectors()
                .trail_name(&trail_arn)
                .send()
                .await
            {
                Ok(r) => {
                    let classic: Vec<String> = r.event_selectors().iter().map(|es| {
                        let rw = es.read_write_type()
                            .map(|t| t.as_str())
                            .unwrap_or("All");
                        let mgmt = es.include_management_events()
                            .unwrap_or(false);
                        let data: Vec<String> = es.data_resources().iter()
                            .map(|dr| dr.r#type().unwrap_or("").to_string())
                            .collect();
                        format!("ReadWrite={rw},Mgmt={mgmt},Data=[{}]", data.join(","))
                    }).collect();
                    let advanced: Vec<String> = r.advanced_event_selectors().iter()
                        .map(|aes| aes.name().unwrap_or("advanced").to_string())
                        .collect();
                    let mut all = classic;
                    all.extend(advanced);
                    all.join(" | ")
                }
                Err(_) => String::new(),
            };

            // Insight selectors
            let insight_selectors = match self.client
                .get_insight_selectors()
                .trail_name(&trail_arn)
                .send()
                .await
            {
                Ok(r) => {
                    r.insight_selectors().iter()
                        .filter_map(|is| is.insight_type().map(|t| t.as_str().to_string()))
                        .collect::<Vec<_>>()
                        .join(", ")
                }
                Err(e) => {
                    let msg = format!("{e}");
                    if msg.contains("InsightNotEnabledException") {
                        "Not Enabled".to_string()
                    } else {
                        String::new()
                    }
                }
            };

            rows.push(vec![
                name,
                trail_arn,
                multi,
                home_region,
                validation,
                bucket,
                is_logging,
                event_selectors,
                insight_selectors,
            ]);
        }

        Ok(rows)
    }
}
