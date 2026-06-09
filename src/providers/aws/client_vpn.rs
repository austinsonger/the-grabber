use anyhow::{Context, Result};
use async_trait::async_trait;
use aws_sdk_ec2::Client as Ec2Client;

use crate::evidence::CsvCollector;

pub struct AwsClientVpnCollector {
    client: Ec2Client,
}

impl AwsClientVpnCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self {
            client: Ec2Client::new(config),
        }
    }
}

#[async_trait]
impl CsvCollector for AwsClientVpnCollector {
    fn name(&self) -> &str {
        "AWS Client VPN"
    }
    fn filename_prefix(&self) -> &str {
        "ClientVPN_Config"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Endpoint ID",
            "Description",
            "Status",
            "Client CIDR",
            "Server Cert ARN",
            "Authentication Types",
            "Connection Log Enabled",
            "Connection Log Group",
            "Split Tunnel",
            "Transport Protocol",
            "DNS Servers",
            "Self-Service Portal",
            "Session Timeout Hours",
            "Routes",
            "Authorization Rules",
            "Active Connections",
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
            let mut req = self.client.describe_client_vpn_endpoints();
            if let Some(ref t) = next_token {
                req = req.next_token(t);
            }
            let resp = req
                .send()
                .await
                .context("ec2 describe_client_vpn_endpoints")?;

            for ep in resp.client_vpn_endpoints() {
                let id = ep.client_vpn_endpoint_id().unwrap_or("").to_string();
                let desc = ep.description().unwrap_or("").to_string();
                let status = ep
                    .status()
                    .and_then(|s| s.code())
                    .map(|c| c.as_str().to_string())
                    .unwrap_or_default();
                let cidr = ep.client_cidr_block().unwrap_or("").to_string();
                let server_cert = ep.server_certificate_arn().unwrap_or("").to_string();
                let auth_types: Vec<String> = ep
                    .authentication_options()
                    .iter()
                    .map(|a| {
                        a.r#type()
                            .map(|t| t.as_str().to_string())
                            .unwrap_or_default()
                    })
                    .collect();
                let (log_enabled, log_group) = match ep.connection_log_options() {
                    Some(cl) => (
                        cl.enabled().unwrap_or(false).to_string(),
                        cl.cloudwatch_log_group().unwrap_or("").to_string(),
                    ),
                    None => (String::from("false"), String::new()),
                };
                let split_tunnel = ep.split_tunnel().unwrap_or(false).to_string();
                let transport = ep
                    .transport_protocol()
                    .map(|p| p.as_str().to_string())
                    .unwrap_or_default();
                let dns = ep.dns_servers().join(", ");
                let portal = ep
                    .self_service_portal_url()
                    .map(|_| "enabled".to_string())
                    .unwrap_or_else(|| "disabled".to_string());
                let timeout = ep
                    .session_timeout_hours()
                    .map(|h| h.to_string())
                    .unwrap_or_default();

                let routes = match self
                    .client
                    .describe_client_vpn_routes()
                    .client_vpn_endpoint_id(&id)
                    .send()
                    .await
                {
                    Ok(r) => r
                        .routes()
                        .iter()
                        .map(|rt| {
                            let dest = rt.destination_cidr().unwrap_or("");
                            let tgt = rt.target_subnet().unwrap_or("");
                            format!("{dest}->{tgt}")
                        })
                        .collect::<Vec<_>>()
                        .join("; "),
                    Err(e) => {
                        eprintln!("  WARN: ClientVPN describe_client_vpn_routes({id}): {e:#}");
                        String::new()
                    }
                };

                let auth_rules = match self
                    .client
                    .describe_client_vpn_authorization_rules()
                    .client_vpn_endpoint_id(&id)
                    .send()
                    .await
                {
                    Ok(r) => r
                        .authorization_rules()
                        .iter()
                        .map(|ar| {
                            let net = ar.destination_cidr().unwrap_or("");
                            let group = ar.group_id().unwrap_or("ALL");
                            let access = ar
                                .status()
                                .and_then(|s| s.code())
                                .map(|c| c.as_str().to_string())
                                .unwrap_or_default();
                            format!("{net}|{group}|{access}")
                        })
                        .collect::<Vec<_>>()
                        .join("; "),
                    Err(e) => {
                        eprintln!(
                            "  WARN: ClientVPN describe_client_vpn_authorization_rules({id}): {e:#}"
                        );
                        String::new()
                    }
                };

                let conns = match self
                    .client
                    .describe_client_vpn_connections()
                    .client_vpn_endpoint_id(&id)
                    .send()
                    .await
                {
                    Ok(r) => r
                        .connections()
                        .iter()
                        .filter(|c| {
                            c.status()
                                .and_then(|s| s.code())
                                .map(|c| c.as_str() == "active")
                                .unwrap_or(false)
                        })
                        .count()
                        .to_string(),
                    Err(e) => {
                        eprintln!(
                            "  WARN: ClientVPN describe_client_vpn_connections({id}): {e:#}"
                        );
                        String::new()
                    }
                };

                rows.push(vec![
                    id,
                    desc,
                    status,
                    cidr,
                    server_cert,
                    auth_types.join(", "),
                    log_enabled,
                    log_group,
                    split_tunnel,
                    transport,
                    dns,
                    portal,
                    timeout,
                    routes,
                    auth_rules,
                    conns,
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
