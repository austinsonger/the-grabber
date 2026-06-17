use anyhow::Result;
use async_trait::async_trait;
use aws_sdk_ec2::types::Filter;
use aws_sdk_ec2::Client as Ec2Client;

use crate::evidence::CsvCollector;

pub struct TgwRoutesCollector {
    client: Ec2Client,
}

impl TgwRoutesCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self {
            client: Ec2Client::new(config),
        }
    }
}

#[async_trait]
impl CsvCollector for TgwRoutesCollector {
    fn name(&self) -> &str {
        "Transit Gateway Route Tables"
    }
    fn filename_prefix(&self) -> &str {
        "TGW_RouteTables"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "TGW ID",
            "Route Table ID",
            "RT State",
            "Default Assoc",
            "Default Prop",
            "Destination CIDR",
            "Route State",
            "Route Type",
            "Target Attachment",
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
            let mut req = self.client.describe_transit_gateway_route_tables();
            if let Some(ref t) = next_token {
                req = req.next_token(t);
            }
            let resp = match req.send().await {
                Ok(r) => r,
                Err(e) => {
                    let msg = format!("{e}");
                    if msg.contains("OperationNotPermitted")
                        || msg.contains("UnauthorizedOperation")
                        || msg.contains("InvalidAction")
                        || msg.contains("not supported")
                    {
                        return Ok(rows);
                    }
                    eprintln!("  WARN: EC2 describe_transit_gateway_route_tables: {e:#}");
                    return Ok(rows);
                }
            };

            for rt in resp.transit_gateway_route_tables() {
                let rt_id = rt
                    .transit_gateway_route_table_id()
                    .unwrap_or("")
                    .to_string();
                let tgw_id = rt.transit_gateway_id().unwrap_or("").to_string();
                let rt_state = rt
                    .state()
                    .map(|s| s.as_str().to_string())
                    .unwrap_or_default();
                let default_assoc = rt
                    .default_association_route_table()
                    .map(|b| if b { "Yes" } else { "No" })
                    .unwrap_or("No")
                    .to_string();
                let default_prop = rt
                    .default_propagation_route_table()
                    .map(|b| if b { "Yes" } else { "No" })
                    .unwrap_or("No")
                    .to_string();

                let state_filter = Filter::builder()
                    .name("state")
                    .values("active")
                    .values("blackhole")
                    .build();

                let routes_resp = match self
                    .client
                    .search_transit_gateway_routes()
                    .transit_gateway_route_table_id(&rt_id)
                    .filters(state_filter)
                    .max_results(1000)
                    .send()
                    .await
                {
                    Ok(r) => r,
                    Err(e) => {
                        eprintln!("  WARN: search_transit_gateway_routes for {rt_id}: {e:#}");
                        rows.push(vec![
                            tgw_id.clone(),
                            rt_id.clone(),
                            rt_state.clone(),
                            default_assoc.clone(),
                            default_prop.clone(),
                            String::new(),
                            String::new(),
                            String::new(),
                            String::new(),
                        ]);
                        continue;
                    }
                };

                let routes = routes_resp.routes();
                if routes.is_empty() {
                    rows.push(vec![
                        tgw_id.clone(),
                        rt_id.clone(),
                        rt_state.clone(),
                        default_assoc.clone(),
                        default_prop.clone(),
                        String::new(),
                        String::new(),
                        String::new(),
                        String::new(),
                    ]);
                    continue;
                }

                for route in routes {
                    let cidr = route.destination_cidr_block().unwrap_or("").to_string();
                    let r_state = route
                        .state()
                        .map(|s| s.as_str().to_string())
                        .unwrap_or_default();
                    let r_type = route
                        .r#type()
                        .map(|t| t.as_str().to_string())
                        .unwrap_or_default();
                    let target = route
                        .transit_gateway_attachments()
                        .first()
                        .and_then(|a| a.resource_id())
                        .unwrap_or("")
                        .to_string();

                    rows.push(vec![
                        tgw_id.clone(),
                        rt_id.clone(),
                        rt_state.clone(),
                        default_assoc.clone(),
                        default_prop.clone(),
                        cidr,
                        r_state,
                        r_type,
                        target,
                    ]);
                }
            }

            next_token = resp.next_token().map(|s| s.to_string());
            if next_token.is_none() {
                break;
            }
        }

        Ok(rows)
    }
}
