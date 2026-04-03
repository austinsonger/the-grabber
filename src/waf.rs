use anyhow::{Context, Result};
use async_trait::async_trait;
use aws_sdk_wafv2::Client as WafClient;
use aws_sdk_wafv2::types::Scope;

use crate::evidence::CsvCollector;

pub struct WafCollector {
    client: WafClient,
}

impl WafCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self { client: WafClient::new(config) }
    }
}

#[async_trait]
impl CsvCollector for WafCollector {
    fn name(&self) -> &str { "WAF Regional Web ACL Rules" }
    fn filename_prefix(&self) -> &str { "WAF_Regional_Web_ACL_Rules" }
    fn headers(&self) -> &'static [&'static str] {
        &["Name", "Web ACL Name", "Managed Rule", "Default Action", "Region"]
    }

    async fn collect_rows(&self, _account_id: &str, region: &str, _dates: Option<(i64, i64)>) -> Result<Vec<Vec<String>>> {
        let mut rows = Vec::new();

        // List all regional web ACLs (paginated via NextMarker).
        let mut next_marker: Option<String> = None;
        let mut acl_summaries: Vec<(String, String)> = Vec::new();

        loop {
            let mut req = self.client
                .list_web_acls()
                .scope(Scope::Regional)
                .limit(100);
            if let Some(ref m) = next_marker {
                req = req.next_marker(m);
            }
            let resp = req.send().await.context("WAFv2 list_web_acls")?;

            for summary in resp.web_acls() {
                acl_summaries.push((
                    summary.name().unwrap_or("").to_string(),
                    summary.id().unwrap_or("").to_string(),
                ));
            }

            next_marker = resp.next_marker().map(|s| s.to_string());
            if next_marker.is_none() { break; }
        }

        // Fetch full details for each ACL to get its rules.
        for (acl_name, acl_id) in &acl_summaries {
            let resp = match self.client
                .get_web_acl()
                .name(acl_name)
                .scope(Scope::Regional)
                .id(acl_id)
                .send()
                .await
            {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("  WARN: could not get WAF WebACL {acl_name}: {e:#}");
                    continue;
                }
            };

            let web_acl = match resp.web_acl() {
                Some(a) => a,
                None => continue,
            };

            let default_action = if web_acl.default_action()
                .and_then(|a| a.allow()).is_some()
            {
                "ALLOW"
            } else {
                "BLOCK"
            }.to_string();

            if web_acl.rules().is_empty() {
                // Web ACL with no rules — still record it.
                rows.push(vec![
                    "(no rules)".to_string(),
                    acl_name.clone(),
                    "".to_string(),
                    default_action.clone(),
                    region.to_string(),
                ]);
            }

            for rule in web_acl.rules() {
                let rule_name = rule.name().to_string();
                let managed_rule = rule.statement()
                    .and_then(|s| s.managed_rule_group_statement())
                    .map(|mrg| {
                        format!("{}/{}", mrg.vendor_name(), mrg.name())
                    })
                    .unwrap_or_else(|| "Custom".to_string());

                rows.push(vec![
                    rule_name,
                    acl_name.clone(),
                    managed_rule,
                    default_action.clone(),
                    region.to_string(),
                ]);
            }
        }

        Ok(rows)
    }
}
