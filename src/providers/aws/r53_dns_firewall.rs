use anyhow::Result;
use async_trait::async_trait;
use aws_sdk_route53resolver::Client as ResolverClient;

use crate::evidence::CsvCollector;

pub struct R53DnsFirewallCollector {
    client: ResolverClient,
}

impl R53DnsFirewallCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self {
            client: ResolverClient::new(config),
        }
    }
}

#[async_trait]
impl CsvCollector for R53DnsFirewallCollector {
    fn name(&self) -> &str {
        "Route53 Resolver DNS Firewall"
    }
    fn filename_prefix(&self) -> &str {
        "Route53_DNSFirewall"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Type",
            "ID",
            "Name",
            "Status / Action",
            "VPC ID",
            "Owner / Priority",
            "Details",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let mut rows = Vec::new();

        // 1. Firewall rule groups (and their rules).
        let mut next_token: Option<String> = None;
        let mut rule_group_ids: Vec<String> = Vec::new();
        loop {
            let mut req = self.client.list_firewall_rule_groups();
            if let Some(ref t) = next_token {
                req = req.next_token(t);
            }
            let resp = match req.send().await {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("  WARN: Route53Resolver list_firewall_rule_groups: {e:#}");
                    break;
                }
            };
            for rg in resp.firewall_rule_groups() {
                let id = rg.id().unwrap_or("").to_string();
                let name = rg.name().unwrap_or("").to_string();
                let owner = rg.owner_id().unwrap_or("").to_string();
                let share = rg
                    .share_status()
                    .map(|s| s.as_str().to_string())
                    .unwrap_or_default();
                rows.push(vec![
                    "RuleGroup".to_string(),
                    id.clone(),
                    name,
                    share,
                    String::new(),
                    owner,
                    String::new(),
                ]);
                if !id.is_empty() {
                    rule_group_ids.push(id);
                }
            }
            next_token = resp.next_token().map(|s| s.to_string());
            if next_token.is_none() {
                break;
            }
        }

        // 2. Rules per rule group.
        for rg_id in &rule_group_ids {
            let mut rule_token: Option<String> = None;
            loop {
                let mut req = self
                    .client
                    .list_firewall_rules()
                    .firewall_rule_group_id(rg_id);
                if let Some(ref t) = rule_token {
                    req = req.next_token(t);
                }
                let resp = match req.send().await {
                    Ok(r) => r,
                    Err(e) => {
                        eprintln!("  WARN: Route53Resolver list_firewall_rules({rg_id}): {e:#}");
                        break;
                    }
                };
                for rule in resp.firewall_rules() {
                    let name = rule.name().unwrap_or("").to_string();
                    let action = rule
                        .action()
                        .map(|a| a.as_str().to_string())
                        .unwrap_or_default();
                    let priority = rule.priority().map(|p| p.to_string()).unwrap_or_default();
                    let domain_list = rule.firewall_domain_list_id().unwrap_or("").to_string();
                    let block_resp = rule
                        .block_response()
                        .map(|b| b.as_str().to_string())
                        .unwrap_or_default();
                    let details = format!("domain_list={domain_list}; block_response={block_resp}");
                    rows.push(vec![
                        "Rule".to_string(),
                        rg_id.clone(),
                        name,
                        action,
                        String::new(),
                        priority,
                        details,
                    ]);
                }
                rule_token = resp.next_token().map(|s| s.to_string());
                if rule_token.is_none() {
                    break;
                }
            }
        }

        // 3. Rule group associations.
        let mut assoc_token: Option<String> = None;
        loop {
            let mut req = self.client.list_firewall_rule_group_associations();
            if let Some(ref t) = assoc_token {
                req = req.next_token(t);
            }
            let resp = match req.send().await {
                Ok(r) => r,
                Err(e) => {
                    eprintln!(
                        "  WARN: Route53Resolver list_firewall_rule_group_associations: {e:#}"
                    );
                    break;
                }
            };
            for a in resp.firewall_rule_group_associations() {
                let id = a.id().unwrap_or("").to_string();
                let rg_id = a.firewall_rule_group_id().unwrap_or("").to_string();
                let vpc_id = a.vpc_id().unwrap_or("").to_string();
                let name = a.name().unwrap_or("").to_string();
                let status = a
                    .status()
                    .map(|s| s.as_str().to_string())
                    .unwrap_or_default();
                let priority = a.priority().map(|p| p.to_string()).unwrap_or_default();
                rows.push(vec![
                    "Association".to_string(),
                    id,
                    name,
                    status,
                    vpc_id,
                    priority,
                    format!("rule_group={rg_id}"),
                ]);
            }
            assoc_token = resp.next_token().map(|s| s.to_string());
            if assoc_token.is_none() {
                break;
            }
        }

        // 4. Query log configs.
        let mut qlc_token: Option<String> = None;
        loop {
            let mut req = self.client.list_resolver_query_log_configs();
            if let Some(ref t) = qlc_token {
                req = req.next_token(t);
            }
            let resp = match req.send().await {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("  WARN: Route53Resolver list_resolver_query_log_configs: {e:#}");
                    break;
                }
            };
            for c in resp.resolver_query_log_configs() {
                let id = c.id().unwrap_or("").to_string();
                let name = c.name().unwrap_or("").to_string();
                let status = c
                    .status()
                    .map(|s| s.as_str().to_string())
                    .unwrap_or_default();
                let owner = c.owner_id().unwrap_or("").to_string();
                let dest = c.destination_arn().unwrap_or("").to_string();
                rows.push(vec![
                    "QueryLogConfig".to_string(),
                    id,
                    name,
                    status,
                    String::new(),
                    owner,
                    format!("destination={dest}"),
                ]);
            }
            qlc_token = resp.next_token().map(|s| s.to_string());
            if qlc_token.is_none() {
                break;
            }
        }

        // 5. DNSSEC configs.
        let mut dnssec_token: Option<String> = None;
        loop {
            let mut req = self.client.list_resolver_dnssec_configs();
            if let Some(ref t) = dnssec_token {
                req = req.next_token(t);
            }
            let resp = match req.send().await {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("  WARN: Route53Resolver list_resolver_dnssec_configs: {e:#}");
                    break;
                }
            };
            for d in resp.resolver_dnssec_configs() {
                let id = d.id().unwrap_or("").to_string();
                let vpc_id = d.resource_id().unwrap_or("").to_string();
                let status = d
                    .validation_status()
                    .map(|s| s.as_str().to_string())
                    .unwrap_or_default();
                let owner = d.owner_id().unwrap_or("").to_string();
                rows.push(vec![
                    "DnssecConfig".to_string(),
                    id,
                    String::new(),
                    status,
                    vpc_id,
                    owner,
                    String::new(),
                ]);
            }
            dnssec_token = resp.next_token().map(|s| s.to_string());
            if dnssec_token.is_none() {
                break;
            }
        }

        Ok(rows)
    }
}
