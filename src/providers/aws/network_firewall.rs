use anyhow::Result;
use async_trait::async_trait;
use aws_sdk_networkfirewall::Client as NfwClient;

use crate::evidence::CsvCollector;

pub struct NetworkFirewallCollector {
    client: NfwClient,
}

impl NetworkFirewallCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self {
            client: NfwClient::new(config),
        }
    }
}

#[async_trait]
impl CsvCollector for NetworkFirewallCollector {
    fn name(&self) -> &str {
        "AWS Network Firewall"
    }
    fn filename_prefix(&self) -> &str {
        "NetworkFirewall_Config"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Firewall Name",
            "Firewall ARN",
            "VPC ID",
            "Subnet IDs",
            "Policy ARN",
            "Policy Name",
            "Stateless Default Actions",
            "Stateless Fragment Actions",
            "Stateful Rule Groups",
            "Delete Protection",
            "Subnet Change Protection",
            "Policy Change Protection",
            "Logging Flow Dest",
            "Logging Alert Dest",
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
            let mut req = self.client.list_firewalls();
            if let Some(ref t) = next_token {
                req = req.next_token(t);
            }
            let resp = match req.send().await {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("  WARN: network-firewall list_firewalls: {e:#}");
                    break;
                }
            };

            for meta in resp.firewalls() {
                let name = meta.firewall_name().unwrap_or("").to_string();
                let arn = meta.firewall_arn().unwrap_or("").to_string();

                let fw_resp = match self
                    .client
                    .describe_firewall()
                    .firewall_arn(&arn)
                    .send()
                    .await
                {
                    Ok(r) => r,
                    Err(e) => {
                        eprintln!("  WARN: network-firewall describe_firewall({arn}): {e:#}");
                        continue;
                    }
                };

                // firewall() returns Option<&Firewall>
                // vpc_id(), firewall_policy_arn() return &str (not Option)
                // delete_protection(), subnet_change_protection(), firewall_policy_change_protection() return bool
                let (vpc_id, subnets, policy_arn, delete_p, subnet_p, policy_p) =
                    match fw_resp.firewall() {
                        Some(f) => (
                            f.vpc_id().to_string(),
                            f.subnet_mappings()
                                .iter()
                                .map(|s| s.subnet_id().to_string())
                                .collect::<Vec<_>>()
                                .join(", "),
                            f.firewall_policy_arn().to_string(),
                            f.delete_protection().to_string(),
                            f.subnet_change_protection().to_string(),
                            f.firewall_policy_change_protection().to_string(),
                        ),
                        None => (
                            String::new(),
                            String::new(),
                            String::new(),
                            String::new(),
                            String::new(),
                            String::new(),
                        ),
                    };

                let (policy_name, stateless_def, stateless_frag, stateful_rgs) = if policy_arn
                    .is_empty()
                {
                    (String::new(), String::new(), String::new(), String::new())
                } else {
                    match self
                        .client
                        .describe_firewall_policy()
                        .firewall_policy_arn(&policy_arn)
                        .send()
                        .await
                    {
                        Ok(p) => {
                            // firewall_policy_response() returns Option<&FirewallPolicyResponse>
                            // firewall_policy_name() and firewall_policy_arn() on response return &str
                            let pname = p
                                .firewall_policy_response()
                                .map(|r| r.firewall_policy_name())
                                .unwrap_or("")
                                .to_string();
                            match p.firewall_policy() {
                                Some(fp) => (
                                    pname,
                                    fp.stateless_default_actions().join(", "),
                                    fp.stateless_fragment_default_actions().join(", "),
                                    fp.stateful_rule_group_references()
                                        .iter()
                                        .map(|r| r.resource_arn().to_string())
                                        .collect::<Vec<_>>()
                                        .join(", "),
                                ),
                                None => (pname, String::new(), String::new(), String::new()),
                            }
                        }
                        Err(e) => {
                            eprintln!(
                                    "  WARN: network-firewall describe_firewall_policy({policy_arn}): {e:#}"
                                );
                            (String::new(), String::new(), String::new(), String::new())
                        }
                    }
                };

                let (flow_dest, alert_dest) = match self
                    .client
                    .describe_logging_configuration()
                    .firewall_arn(&arn)
                    .send()
                    .await
                {
                    Ok(l) => {
                        let mut flow = Vec::new();
                        let mut alert = Vec::new();
                        if let Some(c) = l.logging_configuration() {
                            for cfg in c.log_destination_configs() {
                                // log_type() returns &LogType (not Option)
                                let label = cfg.log_type().as_str().to_string();
                                // log_destination_type() returns &LogDestinationType (not Option)
                                let dest_type = cfg.log_destination_type().as_str().to_string();
                                // log_destination() returns &HashMap<String,String> directly
                                let dest_summary = cfg
                                    .log_destination()
                                    .values()
                                    .cloned()
                                    .collect::<Vec<_>>()
                                    .join("|");
                                let entry = format!("{dest_type}:{dest_summary}");
                                match label.as_str() {
                                    "FLOW" => flow.push(entry),
                                    "ALERT" => alert.push(entry),
                                    _ => {}
                                }
                            }
                        }
                        (flow.join(", "), alert.join(", "))
                    }
                    Err(e) => {
                        eprintln!(
                            "  WARN: network-firewall describe_logging_configuration({arn}): {e:#}"
                        );
                        (String::new(), String::new())
                    }
                };

                rows.push(vec![
                    name,
                    arn,
                    vpc_id,
                    subnets,
                    policy_arn,
                    policy_name,
                    stateless_def,
                    stateless_frag,
                    stateful_rgs,
                    delete_p,
                    subnet_p,
                    policy_p,
                    flow_dest,
                    alert_dest,
                ]);
            }

            next_token = resp.next_token().map(|s| s.to_string());
            if next_token.is_none() {
                break;
            }
        }

        Ok(rows)
    }
}
