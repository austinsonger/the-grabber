//! Enumerates every AWS internal network interconnection so auditors can see
//! all TGWs, TGW attachments, and VPC peering connections with peer accounts,
//! states, and route-table associations. Satisfies FedRAMP CA-09b.

use anyhow::{Context, Result};
use async_trait::async_trait;
use aws_sdk_ec2::Client as Ec2Client;

use crate::evidence::CsvCollector;

pub struct TransitGatewayPeeringCollector {
    client: Ec2Client,
}

impl TransitGatewayPeeringCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self {
            client: Ec2Client::new(config),
        }
    }
}

#[async_trait]
impl CsvCollector for TransitGatewayPeeringCollector {
    fn name(&self) -> &str {
        "Transit Gateways & VPC Peering"
    }
    fn filename_prefix(&self) -> &str {
        "TransitGateway_VPCPeering_Config"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Kind",
            "ID",
            "Name",
            "State",
            "Owner Account",
            "Peer Account",
            "Peer VPC",
            "Peer Region",
            "Local VPC / Subnets",
            "Association",
            "Default Route Table",
            "Notes",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let mut rows: Vec<Vec<String>> = Vec::new();

        // Transit gateways
        let mut tgw_next: Option<String> = None;
        loop {
            let mut req = self.client.describe_transit_gateways();
            if let Some(t) = tgw_next.as_ref() {
                req = req.next_token(t);
            }
            let resp = req.send().await.context("ec2:DescribeTransitGateways")?;
            for tgw in resp.transit_gateways() {
                let name = tgw
                    .tags()
                    .iter()
                    .find(|t| t.key() == Some("Name"))
                    .and_then(|t| t.value())
                    .unwrap_or("")
                    .to_string();
                rows.push(vec![
                    "TransitGateway".into(),
                    tgw.transit_gateway_id().unwrap_or("").into(),
                    name,
                    tgw.state().map(|s| s.as_str().to_string()).unwrap_or_default(),
                    tgw.owner_id().unwrap_or("").into(),
                    String::new(),
                    String::new(),
                    region.into(),
                    String::new(),
                    String::new(),
                    tgw.options()
                        .and_then(|o| o.default_route_table_association())
                        .map(|s| s.as_str().to_string())
                        .unwrap_or_default(),
                    String::new(),
                ]);
            }
            tgw_next = resp.next_token().map(|s| s.to_string());
            if tgw_next.is_none() {
                break;
            }
        }

        // TGW attachments
        let mut att_next: Option<String> = None;
        loop {
            let mut req = self.client.describe_transit_gateway_attachments();
            if let Some(t) = att_next.as_ref() {
                req = req.next_token(t);
            }
            let resp = req
                .send()
                .await
                .context("ec2:DescribeTransitGatewayAttachments")?;
            for att in resp.transit_gateway_attachments() {
                rows.push(vec![
                    "TGWAttachment".into(),
                    att.transit_gateway_attachment_id().unwrap_or("").into(),
                    String::new(),
                    att.state().map(|s| s.as_str().to_string()).unwrap_or_default(),
                    att.resource_owner_id().unwrap_or("").into(),
                    String::new(),
                    att.resource_id().unwrap_or("").into(),
                    region.into(),
                    att.transit_gateway_id().unwrap_or("").into(),
                    att.association()
                        .and_then(|a| a.state())
                        .map(|s| s.as_str().to_string())
                        .unwrap_or_default(),
                    String::new(),
                    att.resource_type()
                        .map(|s| s.as_str().to_string())
                        .unwrap_or_default(),
                ]);
            }
            att_next = resp.next_token().map(|s| s.to_string());
            if att_next.is_none() {
                break;
            }
        }

        // VPC peerings
        let mut pcx_next: Option<String> = None;
        loop {
            let mut req = self.client.describe_vpc_peering_connections();
            if let Some(t) = pcx_next.as_ref() {
                req = req.next_token(t);
            }
            let resp = req
                .send()
                .await
                .context("ec2:DescribeVpcPeeringConnections")?;
            for pcx in resp.vpc_peering_connections() {
                let acc = pcx.accepter_vpc_info();
                let req = pcx.requester_vpc_info();
                rows.push(vec![
                    "VpcPeering".into(),
                    pcx.vpc_peering_connection_id().unwrap_or("").into(),
                    String::new(),
                    pcx.status()
                        .and_then(|s| s.code())
                        .map(|s| s.as_str().to_string())
                        .unwrap_or_default(),
                    req.and_then(|v| v.owner_id()).unwrap_or("").into(),
                    acc.and_then(|v| v.owner_id()).unwrap_or("").into(),
                    acc.and_then(|v| v.vpc_id()).unwrap_or("").into(),
                    acc.and_then(|v| v.region()).unwrap_or(region).into(),
                    req.and_then(|v| v.vpc_id()).unwrap_or("").into(),
                    String::new(),
                    String::new(),
                    String::new(),
                ]);
            }
            pcx_next = resp.next_token().map(|s| s.to_string());
            if pcx_next.is_none() {
                break;
            }
        }
        Ok(rows)
    }
}
