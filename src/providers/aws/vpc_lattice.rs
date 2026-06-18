use anyhow::Result;
use async_trait::async_trait;
use aws_sdk_vpclattice::Client as LatticeClient;

use crate::evidence::CsvCollector;

// ---------------------------------------------------------------------------
// VPC Lattice — services and service networks with auth-type and auth-policy
// excerpts.
// ---------------------------------------------------------------------------

pub struct VpcLatticeCollector {
    client: LatticeClient,
}

impl VpcLatticeCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self {
            client: LatticeClient::new(config),
        }
    }
}

fn truncate(s: &str, n: usize) -> String {
    if s.len() <= n {
        s.to_string()
    } else {
        s.chars().take(n).collect()
    }
}

fn is_unsupported(msg: &str) -> bool {
    msg.contains("not supported")
        || msg.contains("not available")
        || msg.contains("UnsupportedOperation")
        || msg.contains("could not be found")
        || msg.contains("InvalidEndpoint")
}

#[async_trait]
impl CsvCollector for VpcLatticeCollector {
    fn name(&self) -> &str {
        "VPC Lattice"
    }
    fn filename_prefix(&self) -> &str {
        "VPC_Lattice"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Type",
            "ID",
            "Name",
            "Auth Type",
            "Status",
            "Policy Excerpt",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let mut rows = Vec::new();

        // ── Services ──
        let mut next_token: Option<String> = None;
        loop {
            let mut req = self.client.list_services();
            if let Some(ref t) = next_token {
                req = req.next_token(t);
            }
            let resp = match req.send().await {
                Ok(r) => r,
                Err(e) => {
                    let msg = format!("{e:#}");
                    if is_unsupported(&msg) {
                        return Ok(rows);
                    }
                    eprintln!("  WARN: VPC Lattice list_services: {e:#}");
                    return Ok(rows);
                }
            };

            for svc in resp.items() {
                let id = svc.id().unwrap_or("").to_string();
                let name = svc.name().unwrap_or("").to_string();
                let arn = svc.arn().unwrap_or("").to_string();
                let status = svc
                    .status()
                    .map(|s| s.as_str().to_string())
                    .unwrap_or_default();

                // ServiceSummary does not carry auth_type; fetch via get_service.
                let auth_type = if id.is_empty() {
                    String::new()
                } else {
                    match self
                        .client
                        .get_service()
                        .service_identifier(&id)
                        .send()
                        .await
                    {
                        Ok(g) => g
                            .auth_type()
                            .map(|a| a.as_str().to_string())
                            .unwrap_or_default(),
                        Err(e) => {
                            eprintln!("  WARN: VPC Lattice get_service {id}: {e:#}");
                            String::new()
                        }
                    }
                };

                let policy_excerpt = if arn.is_empty() {
                    String::new()
                } else {
                    match self
                        .client
                        .get_auth_policy()
                        .resource_identifier(&arn)
                        .send()
                        .await
                    {
                        Ok(p) => p.policy().map(|s| truncate(s, 500)).unwrap_or_default(),
                        Err(e) => {
                            let msg = format!("{e:#}");
                            if msg.contains("not found")
                                || msg.contains("NotFound")
                                || msg.contains("ResourceNotFound")
                            {
                                String::new()
                            } else {
                                eprintln!("  WARN: VPC Lattice get_auth_policy {arn}: {e:#}");
                                String::new()
                            }
                        }
                    }
                };

                rows.push(vec![
                    "Service".to_string(),
                    id,
                    name,
                    auth_type,
                    status,
                    policy_excerpt,
                ]);
            }

            next_token = resp.next_token().map(|s| s.to_string());
            if next_token.is_none() {
                break;
            }
        }

        // ── Service Networks ──
        let mut next_token: Option<String> = None;
        loop {
            let mut req = self.client.list_service_networks();
            if let Some(ref t) = next_token {
                req = req.next_token(t);
            }
            let resp = match req.send().await {
                Ok(r) => r,
                Err(e) => {
                    let msg = format!("{e:#}");
                    if is_unsupported(&msg) {
                        return Ok(rows);
                    }
                    eprintln!("  WARN: VPC Lattice list_service_networks: {e:#}");
                    return Ok(rows);
                }
            };

            for net in resp.items() {
                let id = net.id().unwrap_or("").to_string();
                let name = net.name().unwrap_or("").to_string();

                let auth_type = if id.is_empty() {
                    String::new()
                } else {
                    match self
                        .client
                        .get_service_network()
                        .service_network_identifier(&id)
                        .send()
                        .await
                    {
                        Ok(g) => g
                            .auth_type()
                            .map(|a| a.as_str().to_string())
                            .unwrap_or_default(),
                        Err(e) => {
                            eprintln!("  WARN: VPC Lattice get_service_network {id}: {e:#}");
                            String::new()
                        }
                    }
                };

                rows.push(vec![
                    "Network".to_string(),
                    id,
                    name,
                    auth_type,
                    String::new(),
                    String::new(),
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
