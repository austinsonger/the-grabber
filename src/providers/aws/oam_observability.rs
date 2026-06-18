use anyhow::Result;
use async_trait::async_trait;
use aws_sdk_oam::Client as OamClient;

use crate::evidence::CsvCollector;

pub struct OamObservabilityCollector {
    client: OamClient,
}

impl OamObservabilityCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self {
            client: OamClient::new(config),
        }
    }
}

#[async_trait]
impl CsvCollector for OamObservabilityCollector {
    fn name(&self) -> &str {
        "OAM Sinks & Links"
    }
    fn filename_prefix(&self) -> &str {
        "OAM_Sinks_Links"
    }
    fn headers(&self) -> &'static [&'static str] {
        &["Type", "ARN", "Name / Label", "Sink ARN", "Resource Types"]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let mut rows = Vec::new();

        // Sinks
        let mut next_token: Option<String> = None;
        loop {
            let mut req = self.client.list_sinks();
            if let Some(ref t) = next_token {
                req = req.next_token(t);
            }
            let resp = match req.send().await {
                Ok(r) => r,
                Err(e) => {
                    let msg = format!("{e:#}");
                    if msg.contains("AccessDenied")
                        || msg.contains("ResourceNotFound")
                        || msg.contains("not supported")
                        || msg.contains("UnknownService")
                    {
                        return Ok(rows);
                    }
                    eprintln!("  WARN: OAM list_sinks: {msg}");
                    return Ok(rows);
                }
            };

            for item in resp.items() {
                let arn = item.arn().unwrap_or("").to_string();
                let name = item.name().unwrap_or("").to_string();
                rows.push(vec![
                    "Sink".to_string(),
                    arn,
                    name,
                    String::new(),
                    String::new(),
                ]);
            }

            next_token = resp.next_token().map(|s| s.to_string());
            if next_token.is_none() {
                break;
            }
        }

        // Links
        let mut next_token: Option<String> = None;
        loop {
            let mut req = self.client.list_links();
            if let Some(ref t) = next_token {
                req = req.next_token(t);
            }
            let resp = match req.send().await {
                Ok(r) => r,
                Err(e) => {
                    let msg = format!("{e:#}");
                    if msg.contains("AccessDenied")
                        || msg.contains("ResourceNotFound")
                        || msg.contains("not supported")
                        || msg.contains("UnknownService")
                    {
                        return Ok(rows);
                    }
                    eprintln!("  WARN: OAM list_links: {msg}");
                    return Ok(rows);
                }
            };

            for item in resp.items() {
                let arn = item.arn().unwrap_or("").to_string();
                let label = item.label().unwrap_or("").to_string();
                let sink_arn = item.sink_arn().unwrap_or("").to_string();
                let resource_types = item.resource_types().join(", ");
                rows.push(vec![
                    "Link".to_string(),
                    arn,
                    label,
                    sink_arn,
                    resource_types,
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
