use anyhow::Result;
use async_trait::async_trait;
use aws_sdk_cloudtrail::Client as CtClient;

use crate::evidence::CsvCollector;

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

// ══════════════════════════════════════════════════════════════════════════════
// CloudTrail Lake Event Data Stores
// ══════════════════════════════════════════════════════════════════════════════

pub struct CloudTrailLakeCollector {
    client: CtClient,
}

impl CloudTrailLakeCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self {
            client: CtClient::new(config),
        }
    }
}

#[async_trait]
impl CsvCollector for CloudTrailLakeCollector {
    fn name(&self) -> &str {
        "CloudTrail Lake Event Data Stores"
    }
    fn filename_prefix(&self) -> &str {
        "CloudTrail_Lake_Queries"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Event Data Store Name",
            "ARN",
            "Retention Period (days)",
            "Multi-Region",
            "Org Enabled",
            "Status",
            "KMS Key",
            "Recent Query Count (30d)",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let mut rows = Vec::new();

        // Enumerate event data stores via list_event_data_stores pagination.
        let mut store_arns: Vec<String> = Vec::new();
        let mut paginator = self.client.list_event_data_stores().into_paginator().send();
        while let Some(page) = paginator.next().await {
            let resp = match page {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("  WARN: CloudTrail list_event_data_stores: {e:#}");
                    break;
                }
            };
            for s in resp.event_data_stores() {
                if let Some(arn) = s.event_data_store_arn() {
                    store_arns.push(arn.to_string());
                }
            }
        }

        let end_secs = now_secs();
        let start_secs = end_secs - 30 * 24 * 3600;
        let start_dt = aws_sdk_cloudtrail::primitives::DateTime::from_secs(start_secs);
        let end_dt = aws_sdk_cloudtrail::primitives::DateTime::from_secs(end_secs);

        for arn in &store_arns {
            // Fetch the full event data store details.
            let detail = match self
                .client
                .get_event_data_store()
                .event_data_store(arn)
                .send()
                .await
            {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("  WARN: CloudTrail get_event_data_store [{arn}]: {e:#}");
                    continue;
                }
            };

            let name = detail.name().unwrap_or("").to_string();
            let retention = detail
                .retention_period()
                .map(|p| p.to_string())
                .unwrap_or_default();
            let multi_region = detail
                .multi_region_enabled()
                .map(|v| v.to_string())
                .unwrap_or_default();
            let org_enabled = detail
                .organization_enabled()
                .map(|v| v.to_string())
                .unwrap_or_default();
            let status = detail
                .status()
                .map(|s| s.as_str().to_string())
                .unwrap_or_default();
            let kms_key = detail.kms_key_id().unwrap_or("").to_string();

            // Count queries submitted in the last 30 days for this store.
            let mut query_count: usize = 0;
            let mut q_paginator = self
                .client
                .list_queries()
                .event_data_store(arn)
                .start_time(start_dt)
                .end_time(end_dt)
                .into_paginator()
                .send();
            while let Some(page) = q_paginator.next().await {
                let resp = match page {
                    Ok(r) => r,
                    Err(e) => {
                        eprintln!("  WARN: CloudTrail list_queries [{arn}]: {e:#}");
                        break;
                    }
                };
                query_count += resp.queries().len();
            }

            rows.push(vec![
                name,
                arn.clone(),
                retention,
                multi_region,
                org_enabled,
                status,
                kms_key,
                query_count.to_string(),
            ]);
        }

        Ok(rows)
    }
}
