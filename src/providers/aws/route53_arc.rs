use anyhow::Result;
use async_trait::async_trait;
use aws_sdk_route53recoverycontrolconfig::Client as ArcConfigClient;
use aws_sdk_route53recoveryreadiness::Client as ArcReadinessClient;

use crate::evidence::CsvCollector;

// ══════════════════════════════════════════════════════════════════════════════
// Route53 Application Recovery Controller (ARC) Collector
// Emits one row per routing control AND one row per readiness check.
// ══════════════════════════════════════════════════════════════════════════════

pub struct Route53ArcCollector {
    config_client: ArcConfigClient,
    readiness_client: ArcReadinessClient,
}

impl Route53ArcCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self {
            config_client: ArcConfigClient::new(config),
            readiness_client: ArcReadinessClient::new(config),
        }
    }
}

fn region_unsupported(msg: &str) -> bool {
    msg.contains("EndpointError")
        || msg.contains("ResourceNotFoundException")
        || msg.contains("not found in this region")
        || msg.contains("dispatch failure")
        || msg.contains("UnknownEndpoint")
        || msg.contains("no such host")
}

#[async_trait]
impl CsvCollector for Route53ArcCollector {
    fn name(&self) -> &str {
        "Route53 ARC Routing Controls & Readiness"
    }
    fn filename_prefix(&self) -> &str {
        "Route53_ARC_Controls"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Type",
            "Cluster/Check ARN",
            "Control Panel / Resource",
            "Name",
            "Status / Routing State",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let mut rows = Vec::new();

        // ── Routing controls ────────────────────────────────────────────────
        let mut cluster_token: Option<String> = None;
        loop {
            let mut req = self.config_client.list_clusters();
            if let Some(ref t) = cluster_token {
                req = req.next_token(t);
            }
            let resp = match req.send().await {
                Ok(r) => r,
                Err(e) => {
                    let msg = format!("{e:#}");
                    if region_unsupported(&msg) {
                        eprintln!("  WARN: Route53 ARC not available in this region: {msg}");
                        return Ok(rows);
                    }
                    eprintln!("  WARN: Route53 ARC list_clusters: {msg}");
                    return Ok(rows);
                }
            };

            for cluster in resp.clusters() {
                let cluster_arn = cluster.cluster_arn().unwrap_or("").to_string();

                let mut cp_token: Option<String> = None;
                loop {
                    let mut cp_req = self.config_client.list_control_panels();
                    if let Some(arn) = cluster.cluster_arn() {
                        cp_req = cp_req.cluster_arn(arn);
                    }
                    if let Some(ref t) = cp_token {
                        cp_req = cp_req.next_token(t);
                    }
                    let cp_resp = match cp_req.send().await {
                        Ok(r) => r,
                        Err(e) => {
                            eprintln!(
                                "  WARN: Route53 ARC list_control_panels for {cluster_arn}: {e:#}"
                            );
                            break;
                        }
                    };

                    for panel in cp_resp.control_panels() {
                        let panel_name = panel.name().unwrap_or("").to_string();
                        let panel_arn = match panel.control_panel_arn() {
                            Some(a) => a.to_string(),
                            None => continue,
                        };

                        let mut rc_token: Option<String> = None;
                        loop {
                            let mut rc_req = self
                                .config_client
                                .list_routing_controls()
                                .control_panel_arn(&panel_arn);
                            if let Some(ref t) = rc_token {
                                rc_req = rc_req.next_token(t);
                            }
                            let rc_resp = match rc_req.send().await {
                                Ok(r) => r,
                                Err(e) => {
                                    eprintln!(
                                        "  WARN: Route53 ARC list_routing_controls for {panel_arn}: {e:#}"
                                    );
                                    break;
                                }
                            };

                            for rc in rc_resp.routing_controls() {
                                let rc_name = rc.name().unwrap_or("").to_string();
                                let rc_status = rc
                                    .status()
                                    .map(|s| s.as_str().to_string())
                                    .unwrap_or_default();
                                rows.push(vec![
                                    "RoutingControl".to_string(),
                                    cluster_arn.clone(),
                                    panel_name.clone(),
                                    rc_name,
                                    rc_status,
                                ]);
                            }

                            rc_token = rc_resp.next_token().map(|s| s.to_string());
                            if rc_token.is_none() {
                                break;
                            }
                        }
                    }

                    cp_token = cp_resp.next_token().map(|s| s.to_string());
                    if cp_token.is_none() {
                        break;
                    }
                }
            }

            cluster_token = resp.next_token().map(|s| s.to_string());
            if cluster_token.is_none() {
                break;
            }
        }

        // ── Readiness checks ────────────────────────────────────────────────
        let mut chk_token: Option<String> = None;
        loop {
            let mut req = self.readiness_client.list_readiness_checks();
            if let Some(ref t) = chk_token {
                req = req.next_token(t);
            }
            let resp = match req.send().await {
                Ok(r) => r,
                Err(e) => {
                    let msg = format!("{e:#}");
                    if region_unsupported(&msg) {
                        eprintln!(
                            "  WARN: Route53 ARC readiness not available in this region: {msg}"
                        );
                        return Ok(rows);
                    }
                    eprintln!("  WARN: Route53 ARC list_readiness_checks: {msg}");
                    return Ok(rows);
                }
            };

            for check in resp.readiness_checks() {
                let name = check.readiness_check_name().unwrap_or("").to_string();
                let arn = check.readiness_check_arn().unwrap_or("").to_string();
                let resource_set = check.resource_set().unwrap_or("").to_string();

                let status = if name.is_empty() {
                    String::new()
                } else {
                    match self
                        .readiness_client
                        .get_readiness_check_status()
                        .readiness_check_name(&name)
                        .send()
                        .await
                    {
                        Ok(s) => s
                            .readiness()
                            .map(|r| r.as_str().to_string())
                            .unwrap_or_default(),
                        Err(e) => {
                            eprintln!(
                                "  WARN: Route53 ARC get_readiness_check_status {name}: {e:#}"
                            );
                            String::new()
                        }
                    }
                };

                rows.push(vec![
                    "ReadinessCheck".to_string(),
                    arn,
                    resource_set,
                    name,
                    status,
                ]);
            }

            chk_token = resp.next_token().map(|s| s.to_string());
            if chk_token.is_none() {
                break;
            }
        }

        Ok(rows)
    }
}
