use anyhow::Result;
use async_trait::async_trait;
use aws_sdk_apigateway::Client as V1Client;
use aws_sdk_apigatewayv2::Client as V2Client;

use crate::evidence::CsvCollector;

pub struct ApiGatewayDeepCollector {
    v1: V1Client,
    v2: V2Client,
}

impl ApiGatewayDeepCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self {
            v1: V1Client::new(config),
            v2: V2Client::new(config),
        }
    }
}

#[async_trait]
impl CsvCollector for ApiGatewayDeepCollector {
    fn name(&self) -> &str {
        "API Gateway Deep Config"
    }
    fn filename_prefix(&self) -> &str {
        "APIGateway_Deep"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "API Type",
            "API ID",
            "Stage",
            "Endpoint Type",
            "WAF ACL",
            "Logging Level",
            "Tracing",
            "Has Resource Policy",
            "Disable Execute-API",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let mut rows: Vec<Vec<String>> = Vec::new();

        // ── REST APIs (v1) ───────────────────────────────────────────────
        let mut position: Option<String> = None;
        loop {
            let mut req = self.v1.get_rest_apis();
            if let Some(p) = position.as_ref() {
                req = req.position(p);
            }
            let resp = match req.send().await {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("  WARN: apigw v1 get_rest_apis: {e:#}");
                    break;
                }
            };

            for api in resp.items() {
                let api_id = api.id().unwrap_or("").to_string();
                let _api_name = api.name().unwrap_or("").to_string();

                let endpoint_type = api
                    .endpoint_configuration()
                    .and_then(|ec| ec.types().first())
                    .map(|t| t.as_str().to_string())
                    .unwrap_or_else(|| "EDGE".to_string());

                let has_policy = if api.policy().is_some() { "Yes" } else { "No" }.to_string();
                let disable_exec = api.disable_execute_api_endpoint().to_string();

                // Stages for this REST API (get_stages is not paginated in v1).
                let sresp = match self.v1.get_stages().rest_api_id(&api_id).send().await {
                    Ok(r) => r,
                    Err(e) => {
                        eprintln!("  WARN: apigw v1 get_stages({api_id}): {e:#}");
                        continue;
                    }
                };
                for stage in sresp.item() {
                    let stage_name = stage.stage_name().unwrap_or("").to_string();
                    let waf = stage.web_acl_arn().unwrap_or("").to_string();
                    let tracing = stage.tracing_enabled().to_string();
                    let logging_level = stage
                        .method_settings()
                        .and_then(|m| m.get("*/*"))
                        .and_then(|ms| ms.logging_level())
                        .unwrap_or("")
                        .to_string();

                    rows.push(vec![
                        "REST".to_string(),
                        api_id.clone(),
                        stage_name,
                        endpoint_type.clone(),
                        waf,
                        logging_level,
                        tracing,
                        has_policy.clone(),
                        disable_exec.clone(),
                    ]);
                }
            }

            position = resp.position().map(|s| s.to_string());
            if position.is_none() {
                break;
            }
        }

        // ── HTTP / WEBSOCKET APIs (v2) ───────────────────────────────────
        let mut next_token: Option<String> = None;
        loop {
            let mut req = self.v2.get_apis();
            if let Some(t) = next_token.as_ref() {
                req = req.next_token(t);
            }
            let resp = match req.send().await {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("  WARN: apigw v2 get_apis: {e:#}");
                    break;
                }
            };

            for api in resp.items() {
                let api_id = api.api_id().unwrap_or("").to_string();
                let endpoint_type = api
                    .protocol_type()
                    .map(|p| p.as_str().to_string())
                    .unwrap_or_default();
                let disable_exec = api
                    .disable_execute_api_endpoint()
                    .map(|b| b.to_string())
                    .unwrap_or_default();

                // Stages for this API.
                let mut stage_token: Option<String> = None;
                loop {
                    let mut sreq = self.v2.get_stages().api_id(&api_id);
                    if let Some(t) = stage_token.as_ref() {
                        sreq = sreq.next_token(t);
                    }
                    let sresp = match sreq.send().await {
                        Ok(r) => r,
                        Err(e) => {
                            eprintln!("  WARN: apigw v2 get_stages({api_id}): {e:#}");
                            break;
                        }
                    };
                    for stage in sresp.items() {
                        let stage_name = stage.stage_name().unwrap_or("").to_string();
                        let logging_level = stage
                            .default_route_settings()
                            .and_then(|r| r.logging_level())
                            .map(|l| l.as_str().to_string())
                            .unwrap_or_default();

                        rows.push(vec![
                            "HTTP".to_string(),
                            api_id.clone(),
                            stage_name,
                            endpoint_type.clone(),
                            String::new(), // v2 stages have no WAF acl field directly
                            logging_level,
                            String::new(), // tracing not on v2 stage
                            String::new(), // v2 has no resource policy field on Api
                            disable_exec.clone(),
                        ]);
                    }
                    stage_token = sresp.next_token().map(|s| s.to_string());
                    if stage_token.is_none() {
                        break;
                    }
                }
            }

            next_token = resp.next_token().map(|s| s.to_string());
            if next_token.is_none() {
                break;
            }
        }

        Ok(rows)
    }
}
