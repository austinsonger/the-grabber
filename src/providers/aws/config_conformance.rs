use anyhow::Result;
use async_trait::async_trait;
use aws_sdk_config::Client as ConfigClient;

use crate::evidence::CsvCollector;

pub struct ConfigConformanceCollector {
    client: ConfigClient,
}

impl ConfigConformanceCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self {
            client: ConfigClient::new(config),
        }
    }
}

fn is_benign(err: &str) -> bool {
    err.contains("AccessDenied")
        || err.contains("ResourceNotFoundException")
        || err.contains("NoSuchConfigurationRecorder")
        || err.contains("not enabled")
}

#[async_trait]
impl CsvCollector for ConfigConformanceCollector {
    fn name(&self) -> &str {
        "Config Conformance Packs"
    }
    fn filename_prefix(&self) -> &str {
        "Config_ConformancePacks"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Pack Name",
            "Pack ARN",
            "Created By",
            "Rule Name",
            "Compliance Type",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let mut rows: Vec<Vec<String>> = Vec::new();

        // Collect all conformance packs (paginated).
        let mut packs: Vec<(String, String, String)> = Vec::new();
        let mut next_token: Option<String> = None;
        loop {
            let mut req = self.client.describe_conformance_packs();
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
                    eprintln!("  WARN: Config describe_conformance_packs: {e:#}");
                    break;
                }
            };

            for p in resp.conformance_pack_details() {
                let name = p.conformance_pack_name().to_string();
                let arn = p.conformance_pack_arn().to_string();
                let created_by = p.created_by().unwrap_or("").to_string();
                packs.push((name, arn, created_by));
            }

            next_token = resp.next_token().map(|s| s.to_string());
            if next_token.is_none() {
                break;
            }
        }

        // For each pack, fetch rule-level compliance.
        for (name, arn, created_by) in &packs {
            let mut rule_token: Option<String> = None;
            let mut emitted_any = false;
            loop {
                let mut req = self
                    .client
                    .describe_conformance_pack_compliance()
                    .conformance_pack_name(name);
                if let Some(t) = rule_token.as_ref() {
                    req = req.next_token(t);
                }
                let resp = match req.send().await {
                    Ok(r) => r,
                    Err(e) => {
                        let msg = format!("{e:#}");
                        if !is_benign(&msg) {
                            eprintln!(
                                "  WARN: Config describe_conformance_pack_compliance({name}): {e:#}"
                            );
                        }
                        break;
                    }
                };

                for rule in resp.conformance_pack_rule_compliance_list() {
                    let rule_name = rule.config_rule_name().unwrap_or("").to_string();
                    let compliance = rule
                        .compliance_type()
                        .map(|c| c.as_str().to_string())
                        .unwrap_or_default();
                    rows.push(vec![
                        name.clone(),
                        arn.clone(),
                        created_by.clone(),
                        rule_name,
                        compliance,
                    ]);
                    emitted_any = true;
                }

                rule_token = resp.next_token().map(|s| s.to_string());
                if rule_token.is_none() {
                    break;
                }
            }

            // If a pack has no rule rows, still emit a placeholder row so the pack appears.
            if !emitted_any {
                rows.push(vec![
                    name.clone(),
                    arn.clone(),
                    created_by.clone(),
                    String::new(),
                    String::new(),
                ]);
            }
        }

        Ok(rows)
    }
}
