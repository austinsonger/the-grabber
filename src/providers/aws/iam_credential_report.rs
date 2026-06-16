use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use aws_sdk_iam::types::ReportStateType;
use aws_sdk_iam::Client as IamClient;
use std::time::Duration;

use crate::evidence::CsvCollector;

pub struct IamCredentialReportCollector {
    client: IamClient,
}

impl IamCredentialReportCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self {
            client: IamClient::new(config),
        }
    }
}

#[async_trait]
impl CsvCollector for IamCredentialReportCollector {
    fn name(&self) -> &str {
        "IAM Credential Report"
    }
    fn filename_prefix(&self) -> &str {
        "IAM_Credential_Report"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "User",
            "ARN",
            "User Creation Time",
            "Password Enabled",
            "Password Last Used",
            "Password Last Changed",
            "Password Next Rotation",
            "MFA Active",
            "Access Key 1 Active",
            "Access Key 1 Last Rotated",
            "Access Key 1 Last Used Date",
            "Access Key 1 Last Used Service",
            "Access Key 2 Active",
            "Access Key 2 Last Rotated",
            "Access Key 2 Last Used Date",
            "Cert 1 Active",
            "Cert 2 Active",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        // 1. Trigger generation; poll until COMPLETE (max ~30s).
        for attempt in 0..15 {
            let gen = self
                .client
                .generate_credential_report()
                .send()
                .await
                .context("IAM generate_credential_report")?;
            match gen.state() {
                Some(ReportStateType::Complete) => break,
                Some(_) => {
                    tokio::time::sleep(Duration::from_secs(2)).await;
                }
                None => {
                    tokio::time::sleep(Duration::from_secs(2)).await;
                }
            }
            if attempt == 14 {
                return Err(anyhow!(
                    "IAM credential report did not reach COMPLETE within timeout"
                ));
            }
        }

        // 2. Fetch the report.
        let resp = self
            .client
            .get_credential_report()
            .send()
            .await
            .context("IAM get_credential_report")?;

        let blob = resp
            .content()
            .ok_or_else(|| anyhow!("credential report missing content"))?;
        let csv_text =
            std::str::from_utf8(blob.as_ref()).context("credential report not valid UTF-8")?;

        // 3. Parse CSV.
        let mut reader = csv::ReaderBuilder::new()
            .has_headers(true)
            .from_reader(csv_text.as_bytes());

        let header_record = reader
            .headers()
            .context("reading credential report header")?
            .clone();

        // Build a name->index map for the AWS-emitted columns.
        let idx = |name: &str| -> Option<usize> { header_record.iter().position(|h| h == name) };

        let cols = [
            "user",
            "arn",
            "user_creation_time",
            "password_enabled",
            "password_last_used",
            "password_last_changed",
            "password_next_rotation",
            "mfa_active",
            "access_key_1_active",
            "access_key_1_last_rotated",
            "access_key_1_last_used_date",
            "access_key_1_last_used_service",
            "access_key_2_active",
            "access_key_2_last_rotated",
            "access_key_2_last_used_date",
            "cert_1_active",
            "cert_2_active",
        ];
        let indices: Vec<Option<usize>> = cols.iter().map(|c| idx(c)).collect();

        let mut rows = Vec::new();
        for record in reader.records() {
            let record = record.context("reading credential report row")?;
            let row: Vec<String> = indices
                .iter()
                .map(|maybe_i| {
                    maybe_i
                        .and_then(|i| record.get(i))
                        .unwrap_or("")
                        .to_string()
                })
                .collect();
            rows.push(row);
        }

        Ok(rows)
    }
}
