use anyhow::{Context, Result};
use async_trait::async_trait;
use aws_sdk_sns::Client as SnsClient;
use aws_sdk_eventbridge::Client as EbClient;
use serde_json::Value;

use crate::evidence::CsvCollector;

// ══════════════════════════════════════════════════════════════════════════════
// 1. SNS Topic Policies
// ══════════════════════════════════════════════════════════════════════════════

pub struct SnsTopicPoliciesCollector {
    client: SnsClient,
}

impl SnsTopicPoliciesCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self { client: SnsClient::new(config) }
    }
}

#[async_trait]
impl CsvCollector for SnsTopicPoliciesCollector {
    fn name(&self) -> &str { "SNS Topic Policies" }
    fn filename_prefix(&self) -> &str { "SNS_Topic_Config" }
    fn headers(&self) -> &'static [&'static str] {
        &["Topic ARN", "Display Name", "Subscriptions Confirmed", "Subscriptions Pending",
          "KMS Key ID", "Has Policy"]
    }

    async fn collect_rows(&self, _account_id: &str, _region: &str) -> Result<Vec<Vec<String>>> {
        let mut rows = Vec::new();
        let mut next_token: Option<String> = None;

        loop {
            let mut req = self.client.list_topics();
            if let Some(ref t) = next_token {
                req = req.next_token(t);
            }
            let resp = req.send().await.context("SNS list_topics")?;

            for topic in resp.topics() {
                let arn = topic.topic_arn().unwrap_or("").to_string();

                let attrs_map = match self.client
                    .get_topic_attributes()
                    .topic_arn(&arn)
                    .send()
                    .await
                {
                    Ok(r) => r.attributes().cloned().unwrap_or_default(),
                    Err(e) => {
                        eprintln!("  WARN: SNS get_topic_attributes {arn}: {e:#}");
                        continue;
                    }
                };

                let get_attr = |key: &str| -> String {
                    attrs_map.get(key).cloned().unwrap_or_default()
                };

                let display_name       = get_attr("DisplayName");
                let subs_confirmed     = get_attr("SubscriptionsConfirmed");
                let subs_pending       = get_attr("SubscriptionsPending");
                let kms_key            = get_attr("KmsMasterKeyId");
                let has_policy         = if attrs_map.contains_key("Policy") { "Yes" } else { "No" }.to_string();

                rows.push(vec![arn, display_name, subs_confirmed, subs_pending, kms_key, has_policy]);
            }

            next_token = resp.next_token().map(|s| s.to_string());
            if next_token.is_none() { break; }
        }

        Ok(rows)
    }
}

// ══════════════════════════════════════════════════════════════════════════════
// 2. EventBridge Rules
// ══════════════════════════════════════════════════════════════════════════════

pub struct EventBridgeRulesCollector {
    client: EbClient,
}

impl EventBridgeRulesCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self { client: EbClient::new(config) }
    }
}

#[async_trait]
impl CsvCollector for EventBridgeRulesCollector {
    fn name(&self) -> &str { "EventBridge Rules" }
    fn filename_prefix(&self) -> &str { "EventBridge_Rules_Config" }
    fn headers(&self) -> &'static [&'static str] {
        &["Rule Name", "Event Bus", "State", "Schedule / Event Pattern", "Targets"]
    }

    async fn collect_rows(&self, _account_id: &str, _region: &str) -> Result<Vec<Vec<String>>> {
        let mut rows = Vec::new();

        // List event buses first (default + custom)
        let buses = match self.client.list_event_buses().send().await {
            Ok(r) => r.event_buses()
                .iter()
                .filter_map(|b| b.name().map(|s| s.to_string()))
                .collect::<Vec<_>>(),
            Err(_) => vec!["default".to_string()],
        };

        for bus_name in &buses {
            let mut next_token: Option<String> = None;

            loop {
                let mut req = self.client.list_rules().event_bus_name(bus_name);
                if let Some(ref t) = next_token {
                    req = req.next_token(t);
                }
                let resp = match req.send().await {
                    Ok(r) => r,
                    Err(e) => {
                        eprintln!("  WARN: EventBridge list_rules for {bus_name}: {e:#}");
                        break;
                    }
                };

                for rule in resp.rules() {
                    let rule_name = rule.name().unwrap_or("").to_string();
                    let state     = rule.state()
                        .map(|s| s.as_str().to_string())
                        .unwrap_or_default();
                    let pattern   = rule.schedule_expression()
                        .map(|s| format!("schedule:{s}"))
                        .or_else(|| rule.event_pattern().map(|p| p.to_string()))
                        .unwrap_or_default();

                    // Get targets
                    let targets = match self.client
                        .list_targets_by_rule()
                        .rule(&rule_name)
                        .event_bus_name(bus_name)
                        .send()
                        .await
                    {
                        Ok(r) => r.targets()
                            .iter()
                            .map(|t| {
                                let id  = t.id();
                                let arn = t.arn();
                                format!("{id}:{arn}")
                            })
                            .collect::<Vec<_>>()
                            .join("; "),
                        Err(_) => String::new(),
                    };

                    rows.push(vec![rule_name, bus_name.clone(), state, pattern, targets]);
                }

                next_token = resp.next_token().map(|s| s.to_string());
                if next_token.is_none() { break; }
            }
        }

        Ok(rows)
    }
}

// ══════════════════════════════════════════════════════════════════════════════
// 3. EventBridge Change-Event Rules (event-pattern-based only)
// ══════════════════════════════════════════════════════════════════════════════

pub struct ChangeEventRulesCollector {
    client: EbClient,
}

impl ChangeEventRulesCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self { client: EbClient::new(config) }
    }
}

#[async_trait]
impl crate::evidence::CsvCollector for ChangeEventRulesCollector {
    fn name(&self) -> &str { "EventBridge Rules for Changes" }
    fn filename_prefix(&self) -> &str { "Change_Event_Rules" }
    fn headers(&self) -> &'static [&'static str] {
        &["Rule Name", "Event Bus", "State", "Event Pattern", "Targets"]
    }

    async fn collect_rows(&self, _account_id: &str, _region: &str) -> Result<Vec<Vec<String>>> {
        let mut rows = Vec::new();

        let buses = match self.client.list_event_buses().send().await {
            Ok(r) => r.event_buses()
                .iter()
                .filter_map(|b| b.name().map(|s| s.to_string()))
                .collect::<Vec<_>>(),
            Err(_) => vec!["default".to_string()],
        };

        for bus_name in &buses {
            let mut next_token: Option<String> = None;
            loop {
                let mut req = self.client.list_rules().event_bus_name(bus_name);
                if let Some(ref t) = next_token {
                    req = req.next_token(t);
                }
                let resp = match req.send().await {
                    Ok(r) => r,
                    Err(e) => {
                        eprintln!("  WARN: EventBridge list_rules {bus_name}: {e:#}");
                        break;
                    }
                };

                for rule in resp.rules() {
                    // Only include event-pattern-based rules (skip schedule rules)
                    let pattern = match rule.event_pattern() {
                        Some(p) if !p.is_empty() => p.to_string(),
                        _ => continue,
                    };

                    // Parse pattern to check if it looks change-related
                    // Accept all event-pattern rules (audit scope); filter note for operator
                    let rule_name = rule.name().unwrap_or("").to_string();
                    let state     = rule.state()
                        .map(|s| s.as_str().to_string())
                        .unwrap_or_default();

                    // Pretty-print the event pattern if it's valid JSON
                    let pattern_display = serde_json::from_str::<Value>(&pattern)
                        .map(|v| v.to_string())
                        .unwrap_or(pattern);

                    let targets = match self.client
                        .list_targets_by_rule()
                        .rule(&rule_name)
                        .event_bus_name(bus_name)
                        .send()
                        .await
                    {
                        Ok(r) => r.targets()
                            .iter()
                            .map(|t| format!("{}:{}", t.id(), t.arn()))
                            .collect::<Vec<_>>()
                            .join("; "),
                        Err(_) => String::new(),
                    };

                    rows.push(vec![rule_name, bus_name.clone(), state, pattern_display, targets]);
                }

                next_token = resp.next_token().map(|s| s.to_string());
                if next_token.is_none() { break; }
            }
        }

        Ok(rows)
    }
}
