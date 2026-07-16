//! Consolidates session-timeout settings across load balancers, Client VPN
//! endpoints, and SSM Session Manager for FedRAMP CA-09c evidence of
//! internal-connection auto-termination.

use anyhow::{Context, Result};
use async_trait::async_trait;
use aws_sdk_ec2::Client as Ec2Client;
use aws_sdk_elasticloadbalancingv2::Client as ElbClient;
use aws_sdk_ssm::Client as SsmClient;

use crate::evidence::CsvCollector;

pub struct SessionTimeoutConfigCollector {
    elb: ElbClient,
    ec2: Ec2Client,
    ssm: SsmClient,
}

impl SessionTimeoutConfigCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self {
            elb: ElbClient::new(config),
            ec2: Ec2Client::new(config),
            ssm: SsmClient::new(config),
        }
    }
}

#[async_trait]
impl CsvCollector for SessionTimeoutConfigCollector {
    fn name(&self) -> &str {
        "Session Timeouts (ELB / Client VPN / SSM)"
    }
    fn filename_prefix(&self) -> &str {
        "Session_Timeout_Config"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Source",
            "Resource ID",
            "Resource Name",
            "Setting",
            "Value",
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

        // ELB idle timeout
        let mut marker: Option<String> = None;
        loop {
            let mut req = self.elb.describe_load_balancers();
            if let Some(m) = marker.as_ref() {
                req = req.marker(m);
            }
            let resp = req.send().await.context("elbv2:DescribeLoadBalancers")?;
            for lb in resp.load_balancers() {
                if let Some(arn) = lb.load_balancer_arn() {
                    let attrs = self
                        .elb
                        .describe_load_balancer_attributes()
                        .load_balancer_arn(arn)
                        .send()
                        .await
                        .with_context(|| format!("elbv2:DescribeLoadBalancerAttributes {arn}"))?;
                    for a in attrs.attributes() {
                        if a.key() == Some("idle_timeout.timeout_seconds") {
                            rows.push(vec![
                                "ELB".into(),
                                arn.into(),
                                lb.load_balancer_name().unwrap_or("").into(),
                                "idle_timeout.timeout_seconds".into(),
                                a.value().unwrap_or("").into(),
                                region.into(),
                            ]);
                        }
                    }
                }
            }
            marker = resp.next_marker().map(|s| s.to_string());
            if marker.is_none() {
                break;
            }
        }

        // Client VPN session timeout
        let mut cvpn_next: Option<String> = None;
        loop {
            let mut req = self.ec2.describe_client_vpn_endpoints();
            if let Some(t) = cvpn_next.as_ref() {
                req = req.next_token(t);
            }
            let resp = req.send().await.context("ec2:DescribeClientVpnEndpoints")?;
            for ep in resp.client_vpn_endpoints() {
                rows.push(vec![
                    "ClientVPN".into(),
                    ep.client_vpn_endpoint_id().unwrap_or("").into(),
                    ep.description().unwrap_or("").into(),
                    "session_timeout_hours".into(),
                    ep.session_timeout_hours()
                        .map(|h| h.to_string())
                        .unwrap_or_default(),
                    region.into(),
                ]);
            }
            cvpn_next = resp.next_token().map(|s| s.to_string());
            if cvpn_next.is_none() {
                break;
            }
        }

        // SSM Session Manager preferences (single doc "SSM-SessionManagerRunShell")
        if let Ok(pref) = self
            .ssm
            .get_document()
            .name("SSM-SessionManagerRunShell")
            .send()
            .await
        {
            let content = pref.content().unwrap_or("");
            rows.push(vec![
                "SSM Session Manager".into(),
                "SSM-SessionManagerRunShell".into(),
                "Session Manager Preferences".into(),
                "document_content_length".into(),
                content.len().to_string(),
                region.into(),
            ]);
        }

        Ok(rows)
    }
}
