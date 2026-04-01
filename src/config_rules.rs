use std::collections::HashMap;

use anyhow::{Context, Result};
use async_trait::async_trait;
use aws_sdk_config::Client as ConfigClient;

use crate::evidence::CsvCollector;

pub struct ConfigRulesCollector {
    client: ConfigClient,
}

impl ConfigRulesCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self { client: ConfigClient::new(config) }
    }
}

#[async_trait]
impl CsvCollector for ConfigRulesCollector {
    fn name(&self) -> &str { "AWS Config Rules" }
    fn filename_prefix(&self) -> &str { "AWS_Config_Rules" }
    fn headers(&self) -> &'static [&'static str] {
        &["Rule Name", "Compliance Status", "Resource Type", "Last Evaluated"]
    }

    async fn collect_rows(&self, _account_id: &str, _region: &str) -> Result<Vec<Vec<String>>> {
        let mut rows = Vec::new();

        // Collect all rule names.
        let mut rule_names: Vec<String> = Vec::new();
        let mut resource_types: HashMap<String, String> = HashMap::new();
        let mut next_token: Option<String> = None;

        loop {
            let mut req = self.client.describe_config_rules();
            if let Some(ref t) = next_token {
                req = req.next_token(t);
            }
            let resp = req.send().await.context("Config describe_config_rules")?;

            for rule in resp.config_rules() {
                let name = rule.config_rule_name().unwrap_or("").to_string();
                let types = rule.scope()
                    .map(|s| s.compliance_resource_types().join(", "))
                    .unwrap_or_default();
                resource_types.insert(name.clone(), types);
                rule_names.push(name);
            }

            next_token = resp.next_token().map(|s| s.to_string());
            if next_token.is_none() { break; }
        }

        // Get compliance status — batch in groups of 25.
        let mut compliance_map: HashMap<String, String> = HashMap::new();
        for chunk in rule_names.chunks(25) {
            let mut req = self.client.describe_compliance_by_config_rule();
            for name in chunk {
                req = req.config_rule_names(name);
            }
            if let Ok(resp) = req.send().await {
                for c in resp.compliance_by_config_rules() {
                    let name = c.config_rule_name().unwrap_or("").to_string();
                    let status = c.compliance()
                        .and_then(|c| c.compliance_type())
                        .map(|t| t.as_str().to_string())
                        .unwrap_or_default();
                    compliance_map.insert(name, status);
                }
            }
        }

        // Get last evaluation time — batch in groups of 50.
        let mut eval_map: HashMap<String, String> = HashMap::new();
        for chunk in rule_names.chunks(50) {
            let mut req = self.client.describe_config_rule_evaluation_status();
            for name in chunk {
                req = req.config_rule_names(name);
            }
            if let Ok(resp) = req.send().await {
                for s in resp.config_rules_evaluation_status() {
                    let name = s.config_rule_name().unwrap_or("").to_string();
                    let last_eval = s.last_successful_evaluation_time()
                        .map(|d| {
                            chrono::DateTime::<chrono::Utc>::from_timestamp(d.secs(), d.subsec_nanos())
                                .map(|c| c.to_rfc3339())
                                .unwrap_or_default()
                        })
                        .unwrap_or_default();
                    eval_map.insert(name, last_eval);
                }
            }
        }

        for name in &rule_names {
            let compliance = compliance_map.get(name).cloned().unwrap_or_default();
            let res_type   = resource_types.get(name).cloned().unwrap_or_default();
            let last_eval  = eval_map.get(name).cloned().unwrap_or_default();
            rows.push(vec![name.clone(), compliance, res_type, last_eval]);
        }

        Ok(rows)
    }
}
