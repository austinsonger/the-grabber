use anyhow::{Context, Result};
use async_trait::async_trait;
use aws_sdk_dynamodb::Client as DynamoClient;

use crate::evidence::CsvCollector;

pub struct DynamoDbCollector {
    client: DynamoClient,
}

impl DynamoDbCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self { client: DynamoClient::new(config) }
    }
}

#[async_trait]
impl CsvCollector for DynamoDbCollector {
    fn name(&self) -> &str { "DynamoDB Tables" }
    fn filename_prefix(&self) -> &str { "DynamoDB" }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Table ARN", "Table Name",
            "Encryption Status", "Encryption Type", "KMS Key ARN", "Region",
        ]
    }

    async fn collect_rows(&self, _account_id: &str, region: &str) -> Result<Vec<Vec<String>>> {
        let mut rows = Vec::new();

        // List all table names (paginated).
        let mut last_name: Option<String> = None;
        let mut table_names: Vec<String> = Vec::new();

        loop {
            let mut req = self.client.list_tables();
            if let Some(ref n) = last_name {
                req = req.exclusive_start_table_name(n);
            }
            let resp = req.send().await.context("DynamoDB list_tables")?;

            for name in resp.table_names() {
                table_names.push(name.to_string());
            }

            last_name = resp.last_evaluated_table_name().map(|s| s.to_string());
            if last_name.is_none() { break; }
        }

        // Describe each table for encryption details.
        for table_name in &table_names {
            let resp = match self.client
                .describe_table()
                .table_name(table_name)
                .send()
                .await
            {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("  WARN: DynamoDB describe_table {table_name}: {e:#}");
                    continue;
                }
            };

            let table = match resp.table() {
                Some(t) => t,
                None    => continue,
            };

            let arn  = table.table_arn().unwrap_or("").to_string();
            let name = table.table_name().unwrap_or("").to_string();

            let (enc_status, enc_type, kms_key) = match table.sse_description() {
                Some(sse) => (
                    sse.status().map(|s| s.as_str().to_string()).unwrap_or_default(),
                    sse.sse_type().map(|s| s.as_str().to_string()).unwrap_or_default(),
                    sse.kms_master_key_arn().unwrap_or("").to_string(),
                ),
                None => ("DISABLED".to_string(), "".to_string(), "".to_string()),
            };

            rows.push(vec![arn, name, enc_status, enc_type, kms_key, region.to_string()]);
        }

        Ok(rows)
    }
}
