//! For every AWS Network Firewall, emits the stream-exception-policy and
//! stateful-default-actions to prove the boundary device fails secure per
//! FedRAMP SC-07(18).

use anyhow::{Context, Result};
use async_trait::async_trait;
use aws_sdk_networkfirewall::Client as NfwClient;

use crate::evidence::CsvCollector;

pub struct NetworkFirewallFailClosedCollector {
    client: NfwClient,
}

impl NetworkFirewallFailClosedCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self {
            client: NfwClient::new(config),
        }
    }
}

#[async_trait]
impl CsvCollector for NetworkFirewallFailClosedCollector {
    fn name(&self) -> &str {
        "Network Firewall Fail-Closed Config"
    }
    fn filename_prefix(&self) -> &str {
        "NetworkFirewall_FailClosed_Config"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Firewall Name",
            "Firewall ARN",
            "Policy ARN",
            "Stream Exception Policy",
            "Stateful Default Actions",
            "Region",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let mut rows: Vec<Vec<String>> = Vec::new();
        let mut next: Option<String> = None;
        loop {
            let mut req = self.client.list_firewalls();
            if let Some(t) = next.as_ref() {
                req = req.next_token(t);
            }
            let resp = req.send().await.context("network-firewall:ListFirewalls")?;
            for f in resp.firewalls() {
                let name = f.firewall_name().unwrap_or("");
                let arn = f.firewall_arn().unwrap_or("");
                let fw = self
                    .client
                    .describe_firewall()
                    .firewall_name(name)
                    .send()
                    .await
                    .with_context(|| format!("network-firewall:DescribeFirewall {name}"))?;
                let policy_arn = fw
                    .firewall()
                    .map(|f| f.firewall_policy_arn().to_string())
                    .unwrap_or_default();
                let pol = self
                    .client
                    .describe_firewall_policy()
                    .firewall_policy_arn(&policy_arn)
                    .send()
                    .await
                    .with_context(|| {
                        format!("network-firewall:DescribeFirewallPolicy {policy_arn}")
                    })?;
                let (stream_pol, stateful_defaults) = pol
                    .firewall_policy()
                    .map(|p| {
                        (
                            p.stateful_engine_options()
                                .and_then(|o| o.stream_exception_policy())
                                .map(|s| s.as_str().to_string())
                                .unwrap_or_default(),
                            p.stateful_default_actions().join("|"),
                        )
                    })
                    .unwrap_or_default();
                rows.push(vec![
                    name.into(),
                    arn.into(),
                    policy_arn,
                    stream_pol,
                    stateful_defaults,
                    region.into(),
                ]);
            }
            next = resp.next_token().map(|s| s.to_string());
            if next.is_none() {
                break;
            }
        }
        Ok(rows)
    }
}
