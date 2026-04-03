use anyhow::{Context, Result};
use async_trait::async_trait;
use aws_sdk_acm::Client as AcmClient;

use crate::evidence::CsvCollector;

pub struct AcmCertCollector {
    client: AcmClient,
}

impl AcmCertCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self { client: AcmClient::new(config) }
    }
}

#[async_trait]
impl CsvCollector for AcmCertCollector {
    fn name(&self) -> &str { "Certificate Manager Certificates" }
    fn filename_prefix(&self) -> &str { "Certificate_Manager_Certificates" }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Certificate ARN", "Domain Name", "Expires",
            "In Use By", "Issued On", "Issuer",
            "Key Algorithm", "Renewal Eligibility",
            "Signature Algorithm", "Status", "Cert Type",
        ]
    }

    async fn collect_rows(&self, _account_id: &str, _region: &str, _dates: Option<(i64, i64)>) -> Result<Vec<Vec<String>>> {
        let mut rows = Vec::new();
        let mut next_token: Option<String> = None;

        // List all cert ARNs first.
        let mut cert_arns: Vec<String> = Vec::new();
        loop {
            let mut req = self.client.list_certificates();
            if let Some(ref t) = next_token {
                req = req.next_token(t);
            }
            let resp = req.send().await.context("ACM list_certificates")?;

            for summary in resp.certificate_summary_list() {
                if let Some(arn) = summary.certificate_arn() {
                    cert_arns.push(arn.to_string());
                }
            }

            next_token = resp.next_token().map(|s| s.to_string());
            if next_token.is_none() { break; }
        }

        // Describe each certificate for full details.
        for cert_arn in &cert_arns {
            let resp = match self.client
                .describe_certificate()
                .certificate_arn(cert_arn)
                .send()
                .await
            {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("  WARN: ACM describe_certificate {cert_arn}: {e:#}");
                    continue;
                }
            };

            let cert = match resp.certificate() {
                Some(c) => c,
                None    => continue,
            };

            let arn         = cert.certificate_arn().unwrap_or("").to_string();
            let domain      = cert.domain_name().unwrap_or("").to_string();
            let expires     = cert.not_after()
                .map(|d| fmt_aws_dt(d))
                .unwrap_or_default();
            let in_use_by   = cert.in_use_by().join(", ");
            let issued_on   = cert.issued_at()
                .map(|d| fmt_aws_dt(d))
                .unwrap_or_default();
            let issuer      = cert.issuer().unwrap_or("").to_string();
            let key_algo    = cert.key_algorithm()
                .map(|a| a.as_str().to_string())
                .unwrap_or_default();
            let renewal     = cert.renewal_eligibility()
                .map(|r| r.as_str().to_string())
                .unwrap_or_default();
            let sig_algo    = cert.signature_algorithm().unwrap_or("").to_string();
            let status      = cert.status()
                .map(|s| s.as_str().to_string())
                .unwrap_or_default();
            let cert_type   = cert.r#type()
                .map(|t| t.as_str().to_string())
                .unwrap_or_default();

            rows.push(vec![
                arn, domain, expires, in_use_by, issued_on, issuer,
                key_algo, renewal, sig_algo, status, cert_type,
            ]);
        }

        Ok(rows)
    }
}

fn fmt_aws_dt(dt: &aws_sdk_acm::primitives::DateTime) -> String {
    chrono::DateTime::<chrono::Utc>::from_timestamp(dt.secs(), dt.subsec_nanos())
        .map(|c| c.to_rfc3339())
        .unwrap_or_default()
}
