use anyhow::{Context, Result};
use async_trait::async_trait;
use aws_sdk_wafv2::Client as WafClient;
use aws_sdk_wafv2::types::Scope;

use crate::evidence::CsvCollector;

pub struct WafFullConfigCollector {
    client: WafClient,
}

impl WafFullConfigCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self { client: WafClient::new(config) }
    }
}

#[async_trait]
impl CsvCollector for WafFullConfigCollector {
    fn name(&self) -> &str { "WAF Web ACL Configuration" }
    fn filename_prefix(&self) -> &str { "WAF_Config" }
    fn headers(&self) -> &'static [&'static str] {
        &["Web ACL Name", "Web ACL ARN", "Default Action", "Rules Count",
          "Rule Names", "CloudWatch Metric", "Sampled Requests Enabled"]
    }

    async fn collect_rows(&self, _account_id: &str, _region: &str) -> Result<Vec<Vec<String>>> {
        let mut rows = Vec::new();
        let mut next_marker: Option<String> = None;

        loop {
            let mut req = self.client
                .list_web_acls()
                .scope(Scope::Regional)
                .limit(100);
            if let Some(ref m) = next_marker {
                req = req.next_marker(m);
            }
            let resp = req.send().await.context("WAF list_web_acls")?;

            for summary in resp.web_acls() {
                let acl_name = summary.name().unwrap_or("").to_string();
                let acl_id   = summary.id().unwrap_or("").to_string();
                let acl_arn  = summary.arn().unwrap_or("").to_string();

                let detail = match self.client
                    .get_web_acl()
                    .name(&acl_name)
                    .scope(Scope::Regional)
                    .id(&acl_id)
                    .send()
                    .await
                {
                    Ok(r) => r,
                    Err(e) => {
                        eprintln!("  WARN: WAF get_web_acl {acl_name}: {e:#}");
                        continue;
                    }
                };

                let web_acl = match detail.web_acl() {
                    Some(a) => a,
                    None => continue,
                };

                let default_action = if web_acl.default_action().and_then(|a| a.allow()).is_some() {
                    "ALLOW"
                } else {
                    "BLOCK"
                }.to_string();

                let rules_count = web_acl.rules().len().to_string();
                let rule_names: Vec<String> = web_acl.rules().iter()
                    .map(|r| r.name().to_string())
                    .collect();

                let metric = web_acl.visibility_config()
                    .map(|vc| vc.metric_name().to_string())
                    .unwrap_or_default();
                let sampled = web_acl.visibility_config()
                    .map(|vc| vc.sampled_requests_enabled().to_string())
                    .unwrap_or_default();

                rows.push(vec![
                    acl_name,
                    acl_arn,
                    default_action,
                    rules_count,
                    rule_names.join(", "),
                    metric,
                    sampled,
                ]);
            }

            next_marker = resp.next_marker().map(|s| s.to_string());
            if next_marker.is_none() { break; }
        }

        Ok(rows)
    }
}
