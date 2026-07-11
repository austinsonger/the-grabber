use anyhow::{Context, Result};
use async_trait::async_trait;
use aws_sdk_ec2::Client as Ec2Client;

use crate::evidence::CsvCollector;

pub struct RouteTableConfigCollector {
    client: Ec2Client,
}

impl RouteTableConfigCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self {
            client: Ec2Client::new(config),
        }
    }
}

#[async_trait]
impl CsvCollector for RouteTableConfigCollector {
    fn name(&self) -> &str {
        "Route Table Configuration"
    }
    fn filename_prefix(&self) -> &str {
        "Route_Table_Config"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Route Table ID",
            "VPC ID",
            "Routes",
            "Associations",
            "Propagating VGWs",
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
            let mut req = self.client.describe_route_tables();
            if let Some(ref t) = next_token {
                req = req.next_token(t);
            }
            let resp = req.send().await.context("EC2 describe_route_tables")?;

            for rt in resp.route_tables() {
                let rt_id = rt.route_table_id().unwrap_or("").to_string();
                let vpc_id = rt.vpc_id().unwrap_or("").to_string();

                let routes: Vec<String> = rt
                    .routes()
                    .iter()
                    .map(|r| {
                        let dest = r
                            .destination_cidr_block()
                            .or(r.destination_ipv6_cidr_block())
                            .or(r.destination_prefix_list_id())
                            .unwrap_or("?");
                        let target = r
                            .gateway_id()
                            .or(r.nat_gateway_id())
                            .or(r.transit_gateway_id())
                            .or(r.vpc_peering_connection_id())
                            .or(r.instance_id())
                            .or(r.network_interface_id())
                            .unwrap_or("local");
                        let state = r.state().map(|s| s.as_str()).unwrap_or("active");
                        format!("{dest}→{target}({state})")
                    })
                    .collect();

                let assocs: Vec<String> = rt
                    .associations()
                    .iter()
                    .map(|a| {
                        if a.main().unwrap_or(false) {
                            "main".to_string()
                        } else {
                            a.subnet_id().unwrap_or("").to_string()
                        }
                    })
                    .collect();

                let vgws: Vec<String> = rt
                    .propagating_vgws()
                    .iter()
                    .filter_map(|v| v.gateway_id().map(|s| s.to_string()))
                    .collect();

                rows.push(vec![
                    rt_id,
                    vpc_id,
                    routes.join("; "),
                    assocs.join(", "),
                    vgws.join(", "),
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
