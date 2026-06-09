use anyhow::{Context, Result};
use async_trait::async_trait;
use aws_sdk_licensemanager::Client as LmClient;

use crate::evidence::CsvCollector;

pub struct LicenseManagerCollector {
    client: LmClient,
}

impl LicenseManagerCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self {
            client: LmClient::new(config),
        }
    }
}

#[async_trait]
impl CsvCollector for LicenseManagerCollector {
    fn name(&self) -> &str {
        "License Manager"
    }
    fn filename_prefix(&self) -> &str {
        "LicenseManager_Config"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Config ARN",
            "Name",
            "Description",
            "License Count",
            "License Count Hard Limit",
            "License Counting Type",
            "Status",
            "Consumed Licenses",
            "Owner Account",
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
            let mut req = self.client.list_license_configurations();
            if let Some(ref t) = next_token {
                req = req.next_token(t);
            }
            let resp = req
                .send()
                .await
                .context("license-manager list_license_configurations")?;

            for cfg_item in resp.license_configurations() {
                let arn = cfg_item
                    .license_configuration_arn()
                    .unwrap_or("")
                    .to_string();
                let name = cfg_item.name().unwrap_or("").to_string();
                let desc = cfg_item.description().unwrap_or("").to_string();
                let count = cfg_item
                    .license_count()
                    .map(|n| n.to_string())
                    .unwrap_or_default();
                let hard = cfg_item
                    .license_count_hard_limit()
                    .map(|b| b.to_string())
                    .unwrap_or_default();
                let ctype = cfg_item
                    .license_counting_type()
                    .map(|t| t.as_str().to_string())
                    .unwrap_or_default();
                let status = cfg_item.status().unwrap_or("").to_string();
                let consumed = cfg_item
                    .consumed_licenses()
                    .map(|n| n.to_string())
                    .unwrap_or_default();
                let owner = cfg_item.owner_account_id().unwrap_or("").to_string();

                rows.push(vec![
                    arn, name, desc, count, hard, ctype, status, consumed, owner,
                ]);
            }

            next_token = resp.next_token().map(|s| s.to_string());
            if next_token.is_none() {
                break;
            }
        }

        Ok(rows)
    }
}
