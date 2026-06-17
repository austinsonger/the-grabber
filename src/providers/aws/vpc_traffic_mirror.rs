use anyhow::Result;
use async_trait::async_trait;
use aws_sdk_ec2::Client as Ec2Client;

use crate::evidence::CsvCollector;

pub struct VpcTrafficMirrorCollector {
    client: Ec2Client,
}

impl VpcTrafficMirrorCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self {
            client: Ec2Client::new(config),
        }
    }
}

#[async_trait]
impl CsvCollector for VpcTrafficMirrorCollector {
    fn name(&self) -> &str {
        "VPC Traffic Mirroring Sessions"
    }
    fn filename_prefix(&self) -> &str {
        "VPC_TrafficMirroring"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Session ID",
            "Network Interface",
            "Target ID",
            "Filter ID",
            "Session Number",
            "VNI",
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
            let mut req = self.client.describe_traffic_mirror_sessions();
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
                    eprintln!("  WARN: EC2 describe_traffic_mirror_sessions: {e:#}");
                    return Ok(rows);
                }
            };

            for session in resp.traffic_mirror_sessions() {
                rows.push(vec![
                    session
                        .traffic_mirror_session_id()
                        .unwrap_or("")
                        .to_string(),
                    session.network_interface_id().unwrap_or("").to_string(),
                    session.traffic_mirror_target_id().unwrap_or("").to_string(),
                    session.traffic_mirror_filter_id().unwrap_or("").to_string(),
                    session
                        .session_number()
                        .map(|n| n.to_string())
                        .unwrap_or_default(),
                    session
                        .virtual_network_id()
                        .map(|n| n.to_string())
                        .unwrap_or_default(),
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
