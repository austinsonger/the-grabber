use anyhow::Result;
use async_trait::async_trait;
use aws_sdk_ssm::types::{OpsItemFilter, OpsItemFilterKey, OpsItemFilterOperator};
use aws_sdk_ssm::Client as SsmClient;

use crate::evidence::CsvCollector;

fn fmt_ssm_dt(dt: &aws_sdk_ssm::primitives::DateTime) -> String {
    chrono::DateTime::<chrono::Utc>::from_timestamp(dt.secs(), 0)
        .map(|c| c.to_rfc3339())
        .unwrap_or_default()
}

pub struct SsmOpsItemsCollector {
    client: SsmClient,
}

impl SsmOpsItemsCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self {
            client: SsmClient::new(config),
        }
    }
}

#[async_trait]
impl CsvCollector for SsmOpsItemsCollector {
    fn name(&self) -> &str {
        "SSM OpsItems"
    }
    fn filename_prefix(&self) -> &str {
        "SSM_OpsItems"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "OpsItem ID",
            "Title",
            "Status",
            "Priority",
            "Source",
            "Category",
            "Severity",
            "Created",
            "Last Modified",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let mut rows = Vec::new();

        let filter = match OpsItemFilter::builder()
            .key(OpsItemFilterKey::Status)
            .values("Open")
            .values("InProgress")
            .operator(OpsItemFilterOperator::Equal)
            .build()
        {
            Ok(f) => f,
            Err(e) => {
                eprintln!("  WARN: SSM OpsItemFilter build: {e:#}");
                return Ok(rows);
            }
        };

        let mut next_token: Option<String> = None;
        loop {
            let mut req = self
                .client
                .describe_ops_items()
                .ops_item_filters(filter.clone());
            if let Some(ref t) = next_token {
                req = req.next_token(t);
            }
            let resp = match req.send().await {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("  WARN: SSM describe_ops_items: {e:#}");
                    return Ok(rows);
                }
            };

            for item in resp.ops_item_summaries() {
                let id = item.ops_item_id().unwrap_or("").to_string();
                let title = item.title().unwrap_or("").to_string();
                let status = item
                    .status()
                    .map(|s| s.as_str().to_string())
                    .unwrap_or_default();
                let priority = item.priority().map(|p| p.to_string()).unwrap_or_default();
                let source = item.source().unwrap_or("").to_string();
                let category = item.category().unwrap_or("").to_string();
                let severity = item.severity().unwrap_or("").to_string();
                let created = item.created_time().map(fmt_ssm_dt).unwrap_or_default();
                let modified = item
                    .last_modified_time()
                    .map(fmt_ssm_dt)
                    .unwrap_or_default();

                rows.push(vec![
                    id, title, status, priority, source, category, severity, created, modified,
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
