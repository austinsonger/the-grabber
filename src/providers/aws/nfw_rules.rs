use anyhow::Result;
use async_trait::async_trait;

use aws_sdk_networkfirewall::types::RuleGroupType;
use aws_sdk_networkfirewall::Client as NfwClient;

use crate::evidence::CsvCollector;

pub struct NfwRulesCollector {
    client: NfwClient,
}

impl NfwRulesCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self {
            client: NfwClient::new(config),
        }
    }
}

#[async_trait]
impl CsvCollector for NfwRulesCollector {
    fn name(&self) -> &str {
        "Network Firewall Policies & Rules"
    }
    fn filename_prefix(&self) -> &str {
        "NetworkFirewall_Rules"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Type",
            "Resource Name",
            "Capacity",
            "Stateful Action Default",
            "Rules Excerpt",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let mut rows: Vec<Vec<String>> = Vec::new();

        // ── Firewall Policies ────────────────────────────────────────────
        let mut next_token: Option<String> = None;
        loop {
            let mut req = self.client.list_firewall_policies();
            if let Some(t) = next_token.as_ref() {
                req = req.next_token(t);
            }
            let resp = match req.send().await {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("  WARN: nfw list_firewall_policies: {e:#}");
                    break;
                }
            };

            for meta in resp.firewall_policies() {
                let name = meta.name().unwrap_or("").to_string();
                if name.is_empty() {
                    continue;
                }

                let desc = match self
                    .client
                    .describe_firewall_policy()
                    .firewall_policy_name(&name)
                    .send()
                    .await
                {
                    Ok(r) => r,
                    Err(e) => {
                        eprintln!("  WARN: nfw describe_firewall_policy({name}): {e:#}");
                        continue;
                    }
                };

                let capacity = desc
                    .firewall_policy_response()
                    .and_then(|r| r.consumed_stateful_rule_capacity())
                    .map(|c| c.to_string())
                    .unwrap_or_default();

                let (stateful_default, excerpt) = match desc.firewall_policy() {
                    Some(fp) => {
                        let sf = fp.stateful_default_actions().join(", ");
                        let stateless_refs = fp.stateless_rule_group_references().len();
                        let stateful_refs = fp.stateful_rule_group_references().len();
                        let summary = format!(
                            "stateless_refs={stateless_refs}; stateful_refs={stateful_refs}; stateless_default={}",
                            fp.stateless_default_actions().join("|")
                        );
                        (sf, summary)
                    }
                    None => (String::new(), String::new()),
                };

                rows.push(vec![
                    "Policy".to_string(),
                    name,
                    capacity,
                    stateful_default,
                    excerpt,
                ]);
            }

            next_token = resp.next_token().map(|s| s.to_string());
            if next_token.is_none() {
                break;
            }
        }

        // ── Rule Groups: stateful + stateless ────────────────────────────
        for rg_type in [RuleGroupType::Stateful, RuleGroupType::Stateless] {
            let mut rg_token: Option<String> = None;
            loop {
                let mut req = self.client.list_rule_groups().r#type(rg_type.clone());
                if let Some(t) = rg_token.as_ref() {
                    req = req.next_token(t);
                }
                let resp = match req.send().await {
                    Ok(r) => r,
                    Err(e) => {
                        eprintln!("  WARN: nfw list_rule_groups({}): {e:#}", rg_type.as_str());
                        break;
                    }
                };

                for meta in resp.rule_groups() {
                    let name = meta.name().unwrap_or("").to_string();
                    if name.is_empty() {
                        continue;
                    }

                    let desc = match self
                        .client
                        .describe_rule_group()
                        .rule_group_name(&name)
                        .r#type(rg_type.clone())
                        .send()
                        .await
                    {
                        Ok(r) => r,
                        Err(e) => {
                            eprintln!(
                                "  WARN: nfw describe_rule_group({name}, {}): {e:#}",
                                rg_type.as_str()
                            );
                            continue;
                        }
                    };

                    let capacity = desc
                        .rule_group_response()
                        .and_then(|r| r.capacity())
                        .map(|c| c.to_string())
                        .unwrap_or_default();

                    let excerpt = match desc.rule_group() {
                        Some(rg) => match rg.rules_source() {
                            Some(rs) => {
                                if let Some(s) = rs.rules_string() {
                                    let mut snippet = s.to_string();
                                    if snippet.len() > 500 {
                                        snippet.truncate(500);
                                    }
                                    snippet
                                } else {
                                    let stateless_count = rs
                                        .stateless_rules_and_custom_actions()
                                        .map(|sr| sr.stateless_rules().len())
                                        .unwrap_or(0);
                                    let stateful_count = rs.stateful_rules().len();
                                    format!(
                                        "stateless_rules={stateless_count}; stateful_rules={stateful_count}"
                                    )
                                }
                            }
                            None => String::new(),
                        },
                        None => String::new(),
                    };

                    rows.push(vec![
                        "RuleGroup".to_string(),
                        format!("{} [{}]", name, rg_type.as_str()),
                        capacity,
                        String::new(),
                        excerpt,
                    ]);
                }

                rg_token = resp.next_token().map(|s| s.to_string());
                if rg_token.is_none() {
                    break;
                }
            }
        }

        Ok(rows)
    }
}
