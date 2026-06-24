use anyhow::{Context, Result};
use async_trait::async_trait;
use aws_sdk_acmpca::Client as PcaClient;

use crate::evidence::CsvCollector;

pub struct AcmPrivateCaCollector {
    client: PcaClient,
}

impl AcmPrivateCaCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self {
            client: PcaClient::new(config),
        }
    }
}

#[async_trait]
impl CsvCollector for AcmPrivateCaCollector {
    fn name(&self) -> &str {
        "ACM Private CA"
    }
    fn filename_prefix(&self) -> &str {
        "ACM_PCA_Config"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "CA ARN",
            "Type",
            "Status",
            "Key Algorithm",
            "Signing Algorithm",
            "Subject CN",
            "Created",
            "Not Before",
            "Not After",
            "CRL Enabled",
            "CRL S3 Bucket",
            "CRL Expiration Days",
            "OCSP Enabled",
            "OCSP Custom CName",
            "Usage Mode",
            "Permissions Count",
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
            let mut req = self.client.list_certificate_authorities();
            if let Some(ref t) = next_token {
                req = req.next_token(t);
            }
            let resp = req
                .send()
                .await
                .context("acm-pca list_certificate_authorities")?;

            for ca in resp.certificate_authorities() {
                let arn = ca.arn().unwrap_or("").to_string();
                let ca_type = ca
                    .r#type()
                    .map(|t| t.as_str().to_string())
                    .unwrap_or_default();
                let status = ca
                    .status()
                    .map(|s| s.as_str().to_string())
                    .unwrap_or_default();
                let created = ca.created_at().map(|d| d.to_string()).unwrap_or_default();
                let not_before = ca.not_before().map(|d| d.to_string()).unwrap_or_default();
                let not_after = ca.not_after().map(|d| d.to_string()).unwrap_or_default();
                let usage_mode = ca
                    .usage_mode()
                    .map(|u| u.as_str().to_string())
                    .unwrap_or_default();

                let (key_alg, sign_alg, subject) = match ca.certificate_authority_configuration() {
                    Some(c) => (
                        c.key_algorithm().as_str().to_string(),
                        c.signing_algorithm().as_str().to_string(),
                        c.subject()
                            .and_then(|s| s.common_name())
                            .unwrap_or("")
                            .to_string(),
                    ),
                    None => (String::new(), String::new(), String::new()),
                };

                let (crl_enabled, crl_bucket, crl_days, ocsp_enabled, ocsp_cname) =
                    match ca.revocation_configuration() {
                        Some(rc) => {
                            let (ce, cb, cd) = match rc.crl_configuration() {
                                Some(c) => (
                                    c.enabled().to_string(),
                                    c.s3_bucket_name().unwrap_or("").to_string(),
                                    c.expiration_in_days()
                                        .map(|d| d.to_string())
                                        .unwrap_or_default(),
                                ),
                                None => (String::from("false"), String::new(), String::new()),
                            };
                            let (oe, oc) = match rc.ocsp_configuration() {
                                Some(o) => (
                                    o.enabled().to_string(),
                                    o.ocsp_custom_cname().unwrap_or("").to_string(),
                                ),
                                None => (String::from("false"), String::new()),
                            };
                            (ce, cb, cd, oe, oc)
                        }
                        None => (
                            String::from("false"),
                            String::new(),
                            String::new(),
                            String::from("false"),
                            String::new(),
                        ),
                    };

                let perms_count = match self
                    .client
                    .list_permissions()
                    .certificate_authority_arn(&arn)
                    .send()
                    .await
                {
                    Ok(p) => p.permissions().len().to_string(),
                    Err(e) => {
                        eprintln!("  WARN: acm-pca list_permissions({arn}): {e:#}");
                        String::new()
                    }
                };

                rows.push(vec![
                    arn,
                    ca_type,
                    status,
                    key_alg,
                    sign_alg,
                    subject,
                    created,
                    not_before,
                    not_after,
                    crl_enabled,
                    crl_bucket,
                    crl_days,
                    ocsp_enabled,
                    ocsp_cname,
                    usage_mode,
                    perms_count,
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
