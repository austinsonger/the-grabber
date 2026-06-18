use anyhow::Result;
use async_trait::async_trait;
use aws_sdk_wafv2::types::Scope;
use aws_sdk_wafv2::Client as WafClient;

use crate::evidence::CsvCollector;

// ══════════════════════════════════════════════════════════════════════════════
// WAF Rule Groups Deep Collector
// ══════════════════════════════════════════════════════════════════════════════

pub struct WafRuleGroupsDeepCollector {
    client: WafClient,
}

impl WafRuleGroupsDeepCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self {
            client: WafClient::new(config),
        }
    }
}

fn is_benign(err: &str) -> bool {
    err.contains("AccessDenied")
        || err.contains("AccessDeniedException")
        || err.contains("UnauthorizedOperation")
        || err.contains("not available")
        || err.contains("UnknownEndpoint")
        || err.contains("dispatch failure")
        || err.contains("WAFNonexistentItemException")
}

fn truncate(s: &str, max_chars: usize) -> String {
    let single: String = s
        .chars()
        .map(|c| {
            if c == '\n' || c == '\r' || c == '\t' {
                ' '
            } else {
                c
            }
        })
        .collect();
    if single.chars().count() > max_chars {
        let t: String = single.chars().take(max_chars).collect();
        format!("{t}…")
    } else {
        single
    }
}

#[async_trait]
impl CsvCollector for WafRuleGroupsDeepCollector {
    fn name(&self) -> &str {
        "WAF Rule Groups Deep"
    }
    fn filename_prefix(&self) -> &str {
        "WAF_RuleGroups_Deep"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Rule Group",
            "Type",
            "Rule Name",
            "Priority",
            "Action",
            "Statement Excerpt",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let mut rows: Vec<Vec<String>> = Vec::new();

        // Customer-managed rule groups (paginated).
        let mut next_marker: Option<String> = None;
        loop {
            let mut req = self
                .client
                .list_rule_groups()
                .scope(Scope::Regional)
                .limit(100);
            if let Some(ref m) = next_marker {
                req = req.next_marker(m);
            }
            let resp = match req.send().await {
                Ok(r) => r,
                Err(e) => {
                    let msg = format!("{e:#}");
                    if is_benign(&msg) {
                        return Ok(rows);
                    }
                    eprintln!("  WARN: WAF list_rule_groups: {msg}");
                    break;
                }
            };

            for summary in resp.rule_groups() {
                let rg_name = summary.name().unwrap_or("").to_string();
                let rg_id = summary.id().unwrap_or("").to_string();

                let detail = match self
                    .client
                    .get_rule_group()
                    .name(&rg_name)
                    .scope(Scope::Regional)
                    .id(&rg_id)
                    .send()
                    .await
                {
                    Ok(d) => d,
                    Err(e) => {
                        let msg = format!("{e:#}");
                        if is_benign(&msg) {
                            continue;
                        }
                        eprintln!("  WARN: WAF get_rule_group {rg_name}: {msg}");
                        continue;
                    }
                };

                let rg = match detail.rule_group() {
                    Some(r) => r,
                    None => continue,
                };

                for rule in rg.rules() {
                    let rule_name = rule.name().to_string();
                    let priority = rule.priority().to_string();
                    let action = if let Some(a) = rule.action() {
                        if a.block().is_some() {
                            "Block"
                        } else if a.allow().is_some() {
                            "Allow"
                        } else if a.count().is_some() {
                            "Count"
                        } else if a.captcha().is_some() {
                            "Captcha"
                        } else if a.challenge().is_some() {
                            "Challenge"
                        } else {
                            "Unknown"
                        }
                        .to_string()
                    } else {
                        String::new()
                    };
                    let statement_excerpt = rule
                        .statement()
                        .map(|s| truncate(&format!("{s:?}"), 500))
                        .unwrap_or_default();
                    rows.push(vec![
                        rg_name.clone(),
                        "Rule".to_string(),
                        rule_name,
                        priority,
                        action,
                        statement_excerpt,
                    ]);
                }
            }

            next_marker = resp.next_marker().map(|s| s.to_string());
            if next_marker.is_none() {
                break;
            }
        }

        // Managed rule groups (vendor=AWS), paginated.
        let mut next_marker: Option<String> = None;
        loop {
            let mut req = self
                .client
                .list_available_managed_rule_groups()
                .scope(Scope::Regional)
                .limit(100);
            if let Some(ref m) = next_marker {
                req = req.next_marker(m);
            }
            let resp = match req.send().await {
                Ok(r) => r,
                Err(e) => {
                    let msg = format!("{e:#}");
                    if is_benign(&msg) {
                        return Ok(rows);
                    }
                    eprintln!("  WARN: WAF list_available_managed_rule_groups: {msg}");
                    break;
                }
            };

            for m in resp.managed_rule_groups() {
                let vendor = m.vendor_name().unwrap_or("").to_string();
                if vendor != "AWS" {
                    continue;
                }
                let name = m.name().unwrap_or("").to_string();
                let desc = m.description().unwrap_or("").to_string();
                rows.push(vec![
                    name.clone(),
                    "ManagedRG".to_string(),
                    name,
                    String::new(),
                    vendor,
                    truncate(&desc, 500),
                ]);
            }

            next_marker = resp.next_marker().map(|s| s.to_string());
            if next_marker.is_none() {
                break;
            }
        }

        Ok(rows)
    }
}
