use anyhow::Result;
use async_trait::async_trait;
use aws_sdk_apprunner::Client as ArClient;

use crate::evidence::CsvCollector;

fn is_benign(err: &str) -> bool {
    err.contains("AccessDenied")
        || err.contains("ResourceNotFoundException")
        || err.contains("ValidationException")
        || err.contains("InvalidRequestException")
        || err.contains("not enabled")
        || err.contains("not subscribed")
        || err.contains("UnknownService")
        || err.contains("dispatch failure")
        || err.contains("not supported")
}

pub struct AppRunnerCollector {
    client: ArClient,
}

impl AppRunnerCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self {
            client: ArClient::new(config),
        }
    }
}

#[async_trait]
impl CsvCollector for AppRunnerCollector {
    fn name(&self) -> &str {
        "App Runner Services"
    }
    fn filename_prefix(&self) -> &str {
        "AppRunner_Services"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Service ARN",
            "Name",
            "Status",
            "Source Type",
            "Egress Type",
            "KMS Key",
            "Health Check Protocol",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let mut rows: Vec<Vec<String>> = Vec::new();
        let mut next_token: Option<String> = None;

        let mut summaries: Vec<(String, String, String)> = Vec::new();

        loop {
            let mut req = self.client.list_services();
            if let Some(t) = next_token.as_ref() {
                req = req.next_token(t);
            }
            let resp = match req.send().await {
                Ok(r) => r,
                Err(e) => {
                    let msg = format!("{e:#}");
                    if is_benign(&msg) {
                        return Ok(rows);
                    }
                    eprintln!("  WARN: AppRunner list_services: {e:#}");
                    break;
                }
            };

            for s in resp.service_summary_list() {
                let arn = s.service_arn().unwrap_or("").to_string();
                let name = s.service_name().unwrap_or("").to_string();
                let status = s
                    .status()
                    .map(|st| st.as_str().to_string())
                    .unwrap_or_default();
                summaries.push((arn, name, status));
            }

            next_token = resp.next_token().map(|s| s.to_string());
            if next_token.is_none() {
                break;
            }
        }

        for (arn, name, status) in summaries {
            let desc_resp = match self
                .client
                .describe_service()
                .service_arn(&arn)
                .send()
                .await
            {
                Ok(r) => r,
                Err(e) => {
                    let msg = format!("{e:#}");
                    if !is_benign(&msg) {
                        eprintln!("  WARN: AppRunner describe_service({arn}): {e:#}");
                    }
                    rows.push(vec![
                        arn.clone(),
                        name.clone(),
                        status.clone(),
                        String::new(),
                        String::new(),
                        String::new(),
                        String::new(),
                    ]);
                    continue;
                }
            };

            let svc = match desc_resp.service {
                Some(s) => s,
                None => {
                    rows.push(vec![
                        arn.clone(),
                        name.clone(),
                        status.clone(),
                        String::new(),
                        String::new(),
                        String::new(),
                        String::new(),
                    ]);
                    continue;
                }
            };

            let source_type = match svc.source_configuration() {
                Some(sc) => {
                    if sc.image_repository().is_some() {
                        "ImageRepository".to_string()
                    } else if sc.code_repository().is_some() {
                        "CodeRepository".to_string()
                    } else {
                        "".to_string()
                    }
                }
                None => String::new(),
            };

            let egress_type = svc
                .network_configuration()
                .and_then(|nc| nc.egress_configuration())
                .and_then(|ec| ec.egress_type())
                .map(|e| e.as_str().to_string())
                .unwrap_or_default();

            let kms_key = svc
                .encryption_configuration()
                .map(|ec| ec.kms_key().to_string())
                .unwrap_or_default();

            let hc_proto = svc
                .health_check_configuration()
                .and_then(|hc| hc.protocol())
                .map(|p| p.as_str().to_string())
                .unwrap_or_default();

            rows.push(vec![
                arn,
                name,
                status,
                source_type,
                egress_type,
                kms_key,
                hc_proto,
            ]);
        }

        Ok(rows)
    }
}
