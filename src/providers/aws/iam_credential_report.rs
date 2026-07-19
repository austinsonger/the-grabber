//! `iam:GenerateCredentialReport` + `iam:GetCredentialReport` — parses the
//! CSV credential report AWS produces per-account and surfaces per-user
//! password/access-key rotation and expiration data for FedRAMP AC-02(02).

use anyhow::{Context, Result};
use async_trait::async_trait;
use aws_sdk_iam::Client as IamClient;

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
        "IAM Credential Report — Password/Key Expiration"
    }
    fn filename_prefix(&self) -> &str {
        "IAM_Credential_Report_Expiration"
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
            "Access Key 2 Active",
            "Access Key 2 Last Rotated",
            "Access Key 2 Last Used Date",
            "Cert 1 Active",
            "Cert 1 Last Rotated",
            "Cert 2 Active",
            "Cert 2 Last Rotated",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        // Trigger generation; ignore "already in progress" states.
        let _ = self
            .client
            .generate_credential_report()
            .send()
            .await
            .context("iam:GenerateCredentialReport")?;

        // Poll until report is available (max ~20s).
        let mut rows_out: Vec<Vec<String>> = Vec::new();
        let mut body: Option<Vec<u8>> = None;
        for _ in 0..10 {
            match self.client.get_credential_report().send().await {
                Ok(r) => {
                    if let Some(b) = r.content() {
                        body = Some(b.as_ref().to_vec());
                        break;
                    }
                }
                Err(_) => {
                    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                }
            }
        }
        let bytes = body.context("iam:GetCredentialReport returned no content after retries")?;
        let text = String::from_utf8(bytes).context("credential report is not UTF-8")?;

        // The report is CSV; header row + one row per user.
        let mut rdr = csv::Reader::from_reader(text.as_bytes());
        let headers = rdr
            .headers()
            .context("read credential report header")?
            .clone();
        let idx = |name: &str| headers.iter().position(|h| h == name);
        let cols: Vec<Option<usize>> = [
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
            "access_key_2_active",
            "access_key_2_last_rotated",
            "access_key_2_last_used_date",
            "cert_1_active",
            "cert_1_last_rotated",
            "cert_2_active",
            "cert_2_last_rotated",
        ]
        .iter()
        .map(|k| idx(k))
        .collect();

        for rec in rdr.records() {
            let rec = rec.context("read credential report row")?;
            let row: Vec<String> = cols
                .iter()
                .map(|opt| opt.and_then(|i| rec.get(i)).unwrap_or("").to_string())
                .collect();
            rows_out.push(row);
        }
        Ok(rows_out)
    }
}
