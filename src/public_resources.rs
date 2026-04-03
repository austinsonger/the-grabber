use anyhow::{Context, Result};
use async_trait::async_trait;
use aws_sdk_ec2::Client as Ec2Client;
use aws_sdk_elasticloadbalancingv2::Client as ElbClient;
use aws_sdk_rds::Client as RdsClient;
use aws_sdk_elasticloadbalancingv2::types::LoadBalancerSchemeEnum;

use crate::evidence::CsvCollector;

pub struct PublicResourceCollector {
    ec2_client: Ec2Client,
    elb_client: ElbClient,
    rds_client: RdsClient,
}

impl PublicResourceCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self {
            ec2_client: Ec2Client::new(config),
            elb_client: ElbClient::new(config),
            rds_client: RdsClient::new(config),
        }
    }
}

#[async_trait]
impl CsvCollector for PublicResourceCollector {
    fn name(&self) -> &str { "Public Resources" }
    fn filename_prefix(&self) -> &str { "Public_Resources" }
    fn headers(&self) -> &'static [&'static str] {
        &["Resource ID", "Resource Type", "Public IP / DNS", "Port Exposure", "Notes"]
    }

    async fn collect_rows(&self, _account_id: &str, _region: &str, _dates: Option<(i64, i64)>) -> Result<Vec<Vec<String>>> {
        let mut rows = Vec::new();

        // ── 1. EC2 instances with public IPs ────────────────────────────────
        let mut next_token: Option<String> = None;
        loop {
            let mut req = self.ec2_client.describe_instances();
            if let Some(ref t) = next_token {
                req = req.next_token(t);
            }
            let resp = match req.send().await {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("  WARN: EC2 describe_instances: {e:#}");
                    break;
                }
            };

            for reservation in resp.reservations() {
                for instance in reservation.instances() {
                    let public_ip = instance.public_ip_address().unwrap_or("");
                    if public_ip.is_empty() { continue; }

                    let instance_id = instance.instance_id().unwrap_or("").to_string();
                    let sg_ids: Vec<String> = instance.security_groups().iter()
                        .filter_map(|sg| sg.group_id())
                        .map(|s| s.to_string())
                        .collect();

                    rows.push(vec![
                        instance_id,
                        "EC2 Instance".to_string(),
                        public_ip.to_string(),
                        String::new(),
                        format!("Security Groups: {}", sg_ids.join(", ")),
                    ]);
                }
            }

            next_token = resp.next_token().map(|s| s.to_string());
            if next_token.is_none() { break; }
        }

        // ── 2. Internet-facing ELBs ──────────────────────────────────────────
        let mut elb_marker: Option<String> = None;
        loop {
            let mut req = self.elb_client.describe_load_balancers();
            if let Some(ref m) = elb_marker {
                req = req.marker(m);
            }
            let resp = match req.send().await {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("  WARN: ELBv2 describe_load_balancers: {e:#}");
                    break;
                }
            };

            for lb in resp.load_balancers() {
                let scheme = lb.scheme();
                if scheme != Some(&LoadBalancerSchemeEnum::InternetFacing) {
                    continue;
                }
                let lb_name = lb.load_balancer_name().unwrap_or("").to_string();
                let lb_arn = lb.load_balancer_arn().unwrap_or("").to_string();
                let dns = lb.dns_name().unwrap_or("").to_string();
                let lb_type = lb.r#type()
                    .map(|t| t.as_str().to_string())
                    .unwrap_or_else(|| "Load Balancer".to_string());

                rows.push(vec![
                    lb_name,
                    lb_type,
                    dns,
                    String::new(),
                    format!("ARN: {lb_arn}"),
                ]);
            }

            elb_marker = resp.next_marker().map(|s| s.to_string());
            if elb_marker.is_none() { break; }
        }

        // ── 3. Publicly accessible RDS instances ─────────────────────────────
        let mut rds_marker: Option<String> = None;
        loop {
            let mut req = self.rds_client.describe_db_instances();
            if let Some(ref m) = rds_marker {
                req = req.marker(m);
            }
            let resp = match req.send().await {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("  WARN: RDS describe_db_instances: {e:#}");
                    break;
                }
            };

            for db in resp.db_instances() {
                if !db.publicly_accessible().unwrap_or(false) { continue; }

                let db_id = db.db_instance_identifier().unwrap_or("").to_string();
                let db_class = db.db_instance_class().unwrap_or("").to_string();
                let endpoint = db.endpoint()
                    .and_then(|e| e.address())
                    .unwrap_or("")
                    .to_string();
                let port = db.endpoint()
                    .and_then(|e| e.port())
                    .map(|p| p.to_string())
                    .unwrap_or_default();

                rows.push(vec![
                    db_id,
                    format!("RDS ({})", db_class),
                    endpoint,
                    port,
                    "Publicly Accessible".to_string(),
                ]);
            }

            rds_marker = resp.marker().map(|s| s.to_string());
            if rds_marker.is_none() { break; }
        }

        Ok(rows)
    }
}
