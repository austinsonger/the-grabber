use anyhow::Result;
use async_trait::async_trait;
use aws_sdk_securitylake::Client as SecurityLakeClient;

use crate::evidence::CsvCollector;

pub struct SecurityLakeCollector {
    client: SecurityLakeClient,
}

impl SecurityLakeCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self {
            client: SecurityLakeClient::new(config),
        }
    }
}

fn is_benign(err: &str) -> bool {
    err.contains("AccessDenied")
        || err.contains("AccessDeniedException")
        || err.contains("UnauthorizedOperation")
        || err.contains("not available")
        || err.contains("UnknownEndpoint")
        || err.contains("dispatch failure")
        || err.contains("ResourceNotFoundException")
}

#[async_trait]
impl CsvCollector for SecurityLakeCollector {
    fn name(&self) -> &str {
        "Security Lake"
    }
    fn filename_prefix(&self) -> &str {
        "SecurityLake_Config"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Type",
            "ARN / Name",
            "Detail",
            "KMS Key / Access Types",
            "Source Version",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let mut rows: Vec<Vec<String>> = Vec::new();

        // Data lakes (per region).
        let dl_resp = match self
            .client
            .list_data_lakes()
            .regions(region.to_string())
            .send()
            .await
        {
            Ok(r) => r,
            Err(e) => {
                let msg = format!("{e:#}");
                if is_benign(&msg) {
                    return Ok(rows);
                }
                eprintln!("  WARN: SecurityLake list_data_lakes: {msg}");
                return Ok(rows);
            }
        };
        for dl in dl_resp.data_lakes() {
            let arn = dl.data_lake_arn().to_string();
            let s3 = dl.s3_bucket_arn().unwrap_or("").to_string();
            let kms = dl
                .encryption_configuration()
                .and_then(|e| e.kms_key_id())
                .unwrap_or("")
                .to_string();
            rows.push(vec!["DataLake".to_string(), arn, s3, kms, String::new()]);
        }

        // Log sources (paginated).
        let mut ls_paginator = self.client.list_log_sources().into_paginator().send();
        while let Some(page) = ls_paginator.next().await {
            let resp = match page {
                Ok(r) => r,
                Err(e) => {
                    let msg = format!("{e:#}");
                    if is_benign(&msg) {
                        break;
                    }
                    eprintln!("  WARN: SecurityLake list_log_sources: {msg}");
                    break;
                }
            };
            for src in resp.sources() {
                let account = src.account().unwrap_or("").to_string();
                let src_region = src.region().unwrap_or("").to_string();
                for sr in src.sources() {
                    let (name, version) = if sr.is_aws_log_source() {
                        match sr.as_aws_log_source() {
                            Ok(aws_src) => (
                                aws_src
                                    .source_name()
                                    .map(|n| n.as_str().to_string())
                                    .unwrap_or_default(),
                                aws_src.source_version().unwrap_or("").to_string(),
                            ),
                            Err(_) => (String::new(), String::new()),
                        }
                    } else if sr.is_custom_log_source() {
                        match sr.as_custom_log_source() {
                            Ok(c) => (
                                c.source_name().unwrap_or("").to_string(),
                                c.source_version().unwrap_or("").to_string(),
                            ),
                            Err(_) => (String::new(), String::new()),
                        }
                    } else {
                        (String::new(), String::new())
                    };
                    rows.push(vec![
                        "LogSource".to_string(),
                        name,
                        format!("account={account} region={src_region}"),
                        String::new(),
                        version,
                    ]);
                }
            }
        }

        // Subscribers (paginated).
        let mut sub_paginator = self.client.list_subscribers().into_paginator().send();
        while let Some(page) = sub_paginator.next().await {
            let resp = match page {
                Ok(r) => r,
                Err(e) => {
                    let msg = format!("{e:#}");
                    if is_benign(&msg) {
                        break;
                    }
                    eprintln!("  WARN: SecurityLake list_subscribers: {msg}");
                    break;
                }
            };
            for sub in resp.subscribers() {
                let arn = sub.subscriber_arn().to_string();
                let name = sub.subscriber_name().to_string();
                let access = sub
                    .access_types()
                    .iter()
                    .map(|a| a.as_str().to_string())
                    .collect::<Vec<_>>()
                    .join(", ");
                rows.push(vec![
                    "Subscriber".to_string(),
                    arn,
                    name,
                    access,
                    String::new(),
                ]);
            }
        }

        Ok(rows)
    }
}
