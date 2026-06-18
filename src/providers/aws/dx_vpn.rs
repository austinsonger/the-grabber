use anyhow::Result;
use async_trait::async_trait;
use aws_sdk_directconnect::Client as DxClient;
use aws_sdk_ec2::Client as Ec2Client;

use crate::evidence::CsvCollector;

pub struct DxVpnCollector {
    dx: DxClient,
    ec2: Ec2Client,
}

impl DxVpnCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self {
            dx: DxClient::new(config),
            ec2: Ec2Client::new(config),
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
        || err.contains("ValidationException")
}

#[async_trait]
impl CsvCollector for DxVpnCollector {
    fn name(&self) -> &str {
        "Direct Connect & VPN"
    }
    fn filename_prefix(&self) -> &str {
        "DirectConnect_VPN"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Type",
            "ID",
            "State",
            "Bandwidth / VLAN",
            "Location / Tunnel CIDR",
            "Encryption / Customer Addr",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let mut rows: Vec<Vec<String>> = Vec::new();

        // Direct Connect connections.
        match self.dx.describe_connections().send().await {
            Ok(resp) => {
                for c in resp.connections() {
                    let id = c.connection_id().unwrap_or("").to_string();
                    let state = c
                        .connection_state()
                        .map(|s| s.as_str().to_string())
                        .unwrap_or_default();
                    let bandwidth = c.bandwidth().unwrap_or("").to_string();
                    let location = c.location().unwrap_or("").to_string();
                    let encryption = c.encryption_mode().unwrap_or("").to_string();
                    rows.push(vec![
                        "DXConnection".to_string(),
                        id,
                        state,
                        bandwidth,
                        location,
                        encryption,
                    ]);
                }
            }
            Err(e) => {
                let msg = format!("{e:#}");
                if !is_benign(&msg) {
                    eprintln!("  WARN: DirectConnect describe_connections: {msg}");
                }
            }
        }

        // Direct Connect virtual interfaces.
        match self.dx.describe_virtual_interfaces().send().await {
            Ok(resp) => {
                for v in resp.virtual_interfaces() {
                    let id = v.virtual_interface_id().unwrap_or("").to_string();
                    let state = v
                        .virtual_interface_state()
                        .map(|s| s.as_str().to_string())
                        .unwrap_or_default();
                    let vlan = v.vlan().to_string();
                    let cust = v.customer_address().unwrap_or("").to_string();
                    let vif_type = v.virtual_interface_type().unwrap_or("").to_string();
                    rows.push(vec!["DXVIF".to_string(), id, state, vlan, vif_type, cust]);
                }
            }
            Err(e) => {
                let msg = format!("{e:#}");
                if !is_benign(&msg) {
                    eprintln!("  WARN: DirectConnect describe_virtual_interfaces: {msg}");
                }
            }
        }

        // EC2 VPN connections.
        match self.ec2.describe_vpn_connections().send().await {
            Ok(resp) => {
                for v in resp.vpn_connections() {
                    let id = v.vpn_connection_id().unwrap_or("").to_string();
                    let state = v
                        .state()
                        .map(|s| s.as_str().to_string())
                        .unwrap_or_default();
                    let cust_gw = v.customer_gateway_id().unwrap_or("").to_string();
                    let peer = v
                        .transit_gateway_id()
                        .map(|s| format!("tgw={s}"))
                        .or_else(|| v.vpn_gateway_id().map(|s| format!("vgw={s}")))
                        .unwrap_or_default();
                    let tunnels: Vec<String> = v
                        .options()
                        .map(|o| {
                            o.tunnel_options()
                                .iter()
                                .filter_map(|t| t.tunnel_inside_cidr().map(|s| s.to_string()))
                                .collect()
                        })
                        .unwrap_or_default();
                    let tunnel_cidrs = tunnels.join(", ");
                    rows.push(vec![
                        "VPN".to_string(),
                        id,
                        state,
                        peer,
                        tunnel_cidrs,
                        cust_gw,
                    ]);
                }
            }
            Err(e) => {
                let msg = format!("{e:#}");
                if !is_benign(&msg) {
                    eprintln!("  WARN: EC2 describe_vpn_connections: {msg}");
                }
            }
        }

        Ok(rows)
    }
}
