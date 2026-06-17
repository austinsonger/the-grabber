use anyhow::{Context, Result};
use async_trait::async_trait;
use aws_sdk_ec2::Client as Ec2Client;

use crate::evidence::CsvCollector;

pub struct PrivateLinkServicesCollector {
    client: Ec2Client,
}

impl PrivateLinkServicesCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self {
            client: Ec2Client::new(config),
        }
    }
}

#[async_trait]
impl CsvCollector for PrivateLinkServicesCollector {
    fn name(&self) -> &str {
        "PrivateLink Endpoint Services"
    }
    fn filename_prefix(&self) -> &str {
        "PrivateLink_Services"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Service ID",
            "Service Name",
            "NLB ARNs",
            "Acceptance Required",
            "Allowed Principals",
            "Availability Zones",
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
            let mut req = self.client.describe_vpc_endpoint_service_configurations();
            if let Some(ref t) = next_token {
                req = req.next_token(t);
            }
            let resp = req
                .send()
                .await
                .context("EC2 describe_vpc_endpoint_service_configurations")?;

            for svc in resp.service_configurations() {
                let svc_id = svc.service_id().unwrap_or("").to_string();
                let svc_name = svc.service_name().unwrap_or("").to_string();
                let nlb_arns = svc.network_load_balancer_arns().join(", ");
                let accept_req = svc
                    .acceptance_required()
                    .map(|b| b.to_string())
                    .unwrap_or_default();
                let azs = svc.availability_zones().join(", ");

                // Gather allowed principals (paginated).
                let mut principals: Vec<String> = Vec::new();
                let mut perm_token: Option<String> = None;
                loop {
                    let mut perm_req = self
                        .client
                        .describe_vpc_endpoint_service_permissions()
                        .service_id(&svc_id);
                    if let Some(ref t) = perm_token {
                        perm_req = perm_req.next_token(t);
                    }
                    match perm_req.send().await {
                        Ok(perm_resp) => {
                            for ap in perm_resp.allowed_principals() {
                                if let Some(p) = ap.principal() {
                                    principals.push(p.to_string());
                                }
                            }
                            perm_token = perm_resp.next_token().map(|s| s.to_string());
                            if perm_token.is_none() {
                                break;
                            }
                        }
                        Err(e) => {
                            eprintln!(
                                "  WARN: EC2 describe_vpc_endpoint_service_permissions({svc_id}): {e:#}"
                            );
                            break;
                        }
                    }
                }

                rows.push(vec![
                    svc_id,
                    svc_name,
                    nlb_arns,
                    accept_req,
                    principals.join(", "),
                    azs,
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
