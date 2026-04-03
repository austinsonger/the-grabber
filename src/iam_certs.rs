use anyhow::{Context, Result};
use async_trait::async_trait;
use aws_sdk_iam::Client as IamClient;

use crate::evidence::CsvCollector;

pub struct IamCertCollector {
    client: IamClient,
}

impl IamCertCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self { client: IamClient::new(config) }
    }
}

#[async_trait]
impl CsvCollector for IamCertCollector {
    fn name(&self) -> &str { "IAM Certificates" }
    fn filename_prefix(&self) -> &str { "IAM_Certificates" }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Name", "ARN",
            "Issuer", "Subject",
            "Subject Alternative Names",
            "Public Key Algorithm", "Signature Algorithm",
            "Key Usage", "Extended Key Usage",
            "Hierarchy", "Issued On", "Expires", "Region",
        ]
    }

    async fn collect_rows(&self, _account_id: &str, region: &str, _dates: Option<(i64, i64)>) -> Result<Vec<Vec<String>>> {
        let mut rows = Vec::new();
        let mut marker: Option<String> = None;

        loop {
            let mut req = self.client.list_server_certificates();
            if let Some(ref m) = marker {
                req = req.marker(m);
            }
            let resp = req.send().await.context("IAM list_server_certificates")?;

            for meta in resp.server_certificate_metadata_list() {
                let name      = meta.server_certificate_name().to_string();
                let arn       = meta.arn().to_string();
                let path      = meta.path().to_string();
                let issued_on = meta.upload_date()
                    .map(|d| fmt_aws_dt(d))
                    .unwrap_or_default();
                let expires   = meta.expiration()
                    .map(|d| fmt_aws_dt(d))
                    .unwrap_or_default();

                // Detailed X.509 fields (Issuer, Subject, SANs, algorithms, usage)
                // are not directly available via the IAM metadata API.
                // They would require downloading and parsing the PEM certificate body.
                rows.push(vec![
                    name, arn,
                    "".to_string(), // Issuer
                    "".to_string(), // Subject
                    "".to_string(), // SANs
                    "".to_string(), // Public Key Algorithm
                    "".to_string(), // Signature Algorithm
                    "".to_string(), // Key Usage
                    "".to_string(), // Extended Key Usage
                    path,           // Hierarchy
                    issued_on,
                    expires,
                    region.to_string(),
                ]);
            }

            marker = if resp.is_truncated() {
                resp.marker().map(|s| s.to_string())
            } else {
                None
            };
            if marker.is_none() { break; }
        }

        Ok(rows)
    }
}

fn fmt_aws_dt(dt: &aws_sdk_iam::primitives::DateTime) -> String {
    chrono::DateTime::<chrono::Utc>::from_timestamp(dt.secs(), dt.subsec_nanos())
        .map(|c| c.to_rfc3339())
        .unwrap_or_default()
}
