use anyhow::Result;
use async_trait::async_trait;
use aws_sdk_servicequotas::Client as SqClient;

use crate::evidence::CsvCollector;

const TRACKED_SERVICES: &[&str] = &[
    "ec2",
    "vpc",
    "rds",
    "lambda",
    "iam",
    "kms",
    "s3",
    "elasticloadbalancing",
    "logs",
];

pub struct ServiceQuotasCollector {
    client: SqClient,
}

impl ServiceQuotasCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self {
            client: SqClient::new(config),
        }
    }
}

#[async_trait]
impl CsvCollector for ServiceQuotasCollector {
    fn name(&self) -> &str {
        "Service Quotas"
    }
    fn filename_prefix(&self) -> &str {
        "ServiceQuotas"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Service Code",
            "Quota Code",
            "Quota Name",
            "Value",
            "Unit",
            "Adjustable",
            "Global Quota",
            "Source",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let mut rows = Vec::new();

        for svc in TRACKED_SERVICES {
            let mut next_token: Option<String> = None;
            loop {
                let mut req = self.client.list_service_quotas().service_code(*svc);
                if let Some(ref t) = next_token {
                    req = req.next_token(t);
                }
                let resp = match req.send().await {
                    Ok(r) => r,
                    Err(e) => {
                        eprintln!("  WARN: service-quotas list_service_quotas({svc}): {e:#}");
                        break;
                    }
                };
                for q in resp.quotas() {
                    rows.push(vec![
                        q.service_code().unwrap_or("").to_string(),
                        q.quota_code().unwrap_or("").to_string(),
                        q.quota_name().unwrap_or("").to_string(),
                        q.value().map(|v| v.to_string()).unwrap_or_default(),
                        q.unit().unwrap_or("").to_string(),
                        q.adjustable().to_string(),
                        q.global_quota().to_string(),
                        "applied".into(),
                    ]);
                }
                next_token = resp.next_token().map(|s| s.to_string());
                if next_token.is_none() {
                    break;
                }
            }

            let mut next_token: Option<String> = None;
            loop {
                let mut req = self
                    .client
                    .list_aws_default_service_quotas()
                    .service_code(*svc);
                if let Some(ref t) = next_token {
                    req = req.next_token(t);
                }
                let resp = match req.send().await {
                    Ok(r) => r,
                    Err(e) => {
                        eprintln!(
                            "  WARN: service-quotas list_aws_default_service_quotas({svc}): {e:#}"
                        );
                        break;
                    }
                };
                for q in resp.quotas() {
                    rows.push(vec![
                        q.service_code().unwrap_or("").to_string(),
                        q.quota_code().unwrap_or("").to_string(),
                        q.quota_name().unwrap_or("").to_string(),
                        q.value().map(|v| v.to_string()).unwrap_or_default(),
                        q.unit().unwrap_or("").to_string(),
                        q.adjustable().to_string(),
                        q.global_quota().to_string(),
                        "default".into(),
                    ]);
                }
                next_token = resp.next_token().map(|s| s.to_string());
                if next_token.is_none() {
                    break;
                }
            }
        }

        Ok(rows)
    }
}
