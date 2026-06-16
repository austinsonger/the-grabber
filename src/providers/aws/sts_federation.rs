use anyhow::Result;
use async_trait::async_trait;
use aws_sdk_iam::Client as IamClient;

use crate::evidence::CsvCollector;

// ══════════════════════════════════════════════════════════════════════════════
// STS Federation Sources — SAML 2.0 and OIDC identity providers configured
// for AWS STS federation.
// ══════════════════════════════════════════════════════════════════════════════

pub struct StsFederationCollector {
    client: IamClient,
}

impl StsFederationCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self {
            client: IamClient::new(config),
        }
    }
}

fn fmt_dt(dt: &aws_sdk_iam::primitives::DateTime) -> String {
    chrono::DateTime::<chrono::Utc>::from_timestamp(dt.secs(), dt.subsec_nanos())
        .map(|c| c.to_rfc3339())
        .unwrap_or_default()
}

#[async_trait]
impl CsvCollector for StsFederationCollector {
    fn name(&self) -> &str {
        "STS Federation Sources"
    }
    fn filename_prefix(&self) -> &str {
        "STS_Federation_Sources"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Provider Type",
            "Provider ARN",
            "URL or Issuer",
            "Audiences/Clients",
            "Thumbprints",
            "Valid Until",
            "Created Date",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let mut rows: Vec<Vec<String>> = Vec::new();

        // 1. SAML providers.
        match self.client.list_saml_providers().send().await {
            Ok(resp) => {
                for entry in resp.saml_provider_list() {
                    let arn = match entry.arn() {
                        Some(a) => a.to_string(),
                        None => continue,
                    };
                    let (issuer, valid_until, created) = match self
                        .client
                        .get_saml_provider()
                        .saml_provider_arn(&arn)
                        .send()
                        .await
                    {
                        Ok(d) => {
                            let issuer = d
                                .saml_metadata_document()
                                .map(|s| format!("metadata_bytes={}", s.len()))
                                .unwrap_or_default();
                            let vu = d.valid_until().map(fmt_dt).unwrap_or_default();
                            let cd = d.create_date().map(fmt_dt).unwrap_or_default();
                            (issuer, vu, cd)
                        }
                        Err(e) => {
                            eprintln!("  WARN: STS Federation get_saml_provider [{arn}]: {e:#}");
                            (String::new(), String::new(), String::new())
                        }
                    };
                    rows.push(vec![
                        "SAML".to_string(),
                        arn,
                        issuer,
                        String::new(),
                        String::new(),
                        valid_until,
                        created,
                    ]);
                }
            }
            Err(e) => {
                eprintln!("  WARN: STS Federation list_saml_providers: {e:#}");
            }
        }

        // 2. OIDC providers.
        match self.client.list_open_id_connect_providers().send().await {
            Ok(resp) => {
                for entry in resp.open_id_connect_provider_list() {
                    let arn = match entry.arn() {
                        Some(a) => a.to_string(),
                        None => continue,
                    };
                    match self
                        .client
                        .get_open_id_connect_provider()
                        .open_id_connect_provider_arn(&arn)
                        .send()
                        .await
                    {
                        Ok(d) => {
                            let url = d.url().unwrap_or("").to_string();
                            let clients = d.client_id_list().join(";");
                            let thumbs = d.thumbprint_list().join(";");
                            let created = d.create_date().map(fmt_dt).unwrap_or_default();
                            rows.push(vec![
                                "OIDC".to_string(),
                                arn,
                                url,
                                clients,
                                thumbs,
                                String::new(),
                                created,
                            ]);
                        }
                        Err(e) => {
                            eprintln!(
                                "  WARN: STS Federation get_open_id_connect_provider [{arn}]: {e:#}"
                            );
                            rows.push(vec![
                                "OIDC".to_string(),
                                arn,
                                String::new(),
                                String::new(),
                                String::new(),
                                String::new(),
                                String::new(),
                            ]);
                        }
                    }
                }
            }
            Err(e) => {
                eprintln!("  WARN: STS Federation list_open_id_connect_providers: {e:#}");
            }
        }

        Ok(rows)
    }
}
