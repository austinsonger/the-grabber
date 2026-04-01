use anyhow::{Context, Result};
use async_trait::async_trait;
use aws_sdk_apigateway::Client as AgClient;

use crate::evidence::CsvCollector;

pub struct ApiGatewayCollector {
    client: AgClient,
}

impl ApiGatewayCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self { client: AgClient::new(config) }
    }
}

#[async_trait]
impl CsvCollector for ApiGatewayCollector {
    fn name(&self) -> &str { "API Gateway" }
    fn filename_prefix(&self) -> &str { "API_Gateway" }
    fn headers(&self) -> &'static [&'static str] {
        &["API Name", "Endpoint Type", "Authorization Type", "Logging Enabled", "Region"]
    }

    async fn collect_rows(&self, _account_id: &str, region: &str) -> Result<Vec<Vec<String>>> {
        let mut rows = Vec::new();
        let mut position: Option<String> = None;

        loop {
            let mut req = self.client.get_rest_apis();
            if let Some(ref p) = position {
                req = req.position(p);
            }
            let resp = req.send().await.context("API Gateway get_rest_apis")?;

            for api in resp.items() {
                let api_id   = api.id().unwrap_or("").to_string();
                let api_name = api.name().unwrap_or("").to_string();

                let endpoint_type = api.endpoint_configuration()
                    .and_then(|ec| ec.types().first())
                    .map(|t| t.as_str().to_string())
                    .unwrap_or_else(|| "EDGE".to_string());

                // Check for authorizers.
                let auth_type = match self.client
                    .get_authorizers()
                    .rest_api_id(&api_id)
                    .send()
                    .await
                {
                    Ok(r) => {
                        let types: Vec<String> = r.items()
                            .iter()
                            .filter_map(|a| a.r#type())
                            .map(|t| t.as_str().to_string())
                            .collect();
                        if types.is_empty() { "NONE".to_string() } else { types.join(", ") }
                    }
                    Err(_) => "NONE".to_string(),
                };

                // Check first stage for access log / execution log settings.
                let logging_enabled = match self.client
                    .get_stages()
                    .rest_api_id(&api_id)
                    .send()
                    .await
                {
                    Ok(r) => {
                        let has_access_log = r.item()
                            .iter()
                            .any(|s| s.access_log_settings()
                                .and_then(|a| a.destination_arn())
                                .is_some());
                        if has_access_log { "Yes" } else { "No" }.to_string()
                    }
                    Err(_) => "".to_string(),
                };

                rows.push(vec![
                    api_name, endpoint_type, auth_type,
                    logging_enabled, region.to_string(),
                ]);
            }

            position = resp.position().map(|s| s.to_string());
            if position.is_none() { break; }
        }

        Ok(rows)
    }
}
