use anyhow::Result;
use async_trait::async_trait;
use aws_sdk_cloudwatch::Client as CwClient;

use crate::evidence::CsvCollector;

// ══════════════════════════════════════════════════════════════════════════════
// CloudWatch Contributor Insights Rules
// ══════════════════════════════════════════════════════════════════════════════

pub struct ContributorInsightsCollector {
    client: CwClient,
}

impl ContributorInsightsCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self {
            client: CwClient::new(config),
        }
    }
}

#[async_trait]
impl CsvCollector for ContributorInsightsCollector {
    fn name(&self) -> &str {
        "CloudWatch Contributor Insights Rules"
    }
    fn filename_prefix(&self) -> &str {
        "CloudWatch_ContributorInsights"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Rule Name",
            "State",
            "Schema",
            "Definition Excerpt",
            "Managed Rule",
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
            let mut req = self.client.describe_insight_rules();
            if let Some(ref t) = next_token {
                req = req.next_token(t);
            }
            let resp = match req.send().await {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("  WARN: CloudWatch describe_insight_rules: {e:#}");
                    break;
                }
            };
            for r in resp.insight_rules() {
                let name = r.name().unwrap_or("").to_string();
                let state = r.state().unwrap_or("").to_string();
                let schema = r.schema().unwrap_or("").to_string();
                let definition = r.definition().unwrap_or("");
                let def_excerpt = if definition.len() > 500 {
                    definition[..500].to_string()
                } else {
                    definition.to_string()
                };
                let managed = r.managed_rule().map(|b| b.to_string()).unwrap_or_default();

                rows.push(vec![name, state, schema, def_excerpt, managed]);
            }
            match resp.next_token() {
                Some(t) if !t.is_empty() => next_token = Some(t.to_string()),
                _ => break,
            }
        }
        Ok(rows)
    }
}
