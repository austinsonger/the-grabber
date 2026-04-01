use anyhow::{Context, Result};
use async_trait::async_trait;
use aws_sdk_cloudfront::Client as CfClient;

use crate::evidence::CsvCollector;

pub struct CloudFrontCollector {
    client: CfClient,
}

impl CloudFrontCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self { client: CfClient::new(config) }
    }
}

#[async_trait]
impl CsvCollector for CloudFrontCollector {
    fn name(&self) -> &str { "CloudFront Distributions" }
    fn filename_prefix(&self) -> &str { "CloudFront_Distributions" }
    fn headers(&self) -> &'static [&'static str] {
        &["Distribution ID", "Domain Name", "WAF Enabled", "Logging Enabled", "TLS Version"]
    }

    async fn collect_rows(&self, _account_id: &str, _region: &str) -> Result<Vec<Vec<String>>> {
        let mut rows = Vec::new();
        let mut marker: Option<String> = None;

        loop {
            let mut req = self.client.list_distributions();
            if let Some(ref m) = marker {
                req = req.marker(m);
            }
            let resp = req.send().await.context("CloudFront list_distributions")?;

            let dl = match resp.distribution_list() {
                Some(dl) => dl,
                None => break,
            };

            for dist in dl.items() {
                let dist_id    = dist.id().to_string();
                let domain     = dist.domain_name().to_string();
                let waf        = if !dist.web_acl_id().is_empty() { "Yes" } else { "No" }.to_string();
                let tls        = dist.viewer_certificate()
                    .and_then(|vc| vc.minimum_protocol_version().cloned())
                    .map(|v| v.as_str().to_string())
                    .unwrap_or_default();

                // Get logging status from full distribution config.
                let logging = match self.client
                    .get_distribution()
                    .id(&dist_id)
                    .send()
                    .await
                {
                    Ok(r) => r.distribution()
                        .and_then(|d| d.distribution_config())
                        .and_then(|c| c.logging())
                        .map(|l| if l.enabled() { "Enabled" } else { "Disabled" })
                        .unwrap_or("Disabled")
                        .to_string(),
                    Err(_) => "".to_string(),
                };

                rows.push(vec![dist_id, domain, waf, logging, tls]);
            }

            if dl.is_truncated() {
                marker = dl.next_marker().map(|s| s.to_string());
            } else {
                break;
            }
        }

        Ok(rows)
    }
}
