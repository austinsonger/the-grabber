use anyhow::Result;
use async_trait::async_trait;
use aws_sdk_globalaccelerator::Client as GaClient;

use crate::evidence::CsvCollector;

pub struct GlobalAcceleratorCollector {
    client: GaClient,
}

impl GlobalAcceleratorCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self {
            client: GaClient::new(config),
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
impl CsvCollector for GlobalAcceleratorCollector {
    fn name(&self) -> &str {
        "Global Accelerator"
    }
    fn filename_prefix(&self) -> &str {
        "GlobalAccelerator"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Type",
            "ARN",
            "Name",
            "Status",
            "Protocol / Region",
            "Port Ranges / Traffic Dial",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let mut rows: Vec<Vec<String>> = Vec::new();

        let mut accel_paginator = self.client.list_accelerators().into_paginator().send();
        while let Some(page) = accel_paginator.next().await {
            let resp = match page {
                Ok(r) => r,
                Err(e) => {
                    let msg = format!("{e:#}");
                    if is_benign(&msg) {
                        return Ok(rows);
                    }
                    eprintln!("  WARN: GlobalAccelerator list_accelerators: {msg}");
                    break;
                }
            };
            for a in resp.accelerators() {
                let arn = a.accelerator_arn().unwrap_or("").to_string();
                let name = a.name().unwrap_or("").to_string();
                let enabled = a
                    .enabled()
                    .map(|b| if b { "Enabled" } else { "Disabled" })
                    .unwrap_or("");
                let status = a
                    .status()
                    .map(|s| s.as_str().to_string())
                    .unwrap_or_default();
                let ips: Vec<String> = a
                    .ip_sets()
                    .iter()
                    .flat_map(|s| s.ip_addresses().iter().cloned())
                    .collect();
                rows.push(vec![
                    "Accelerator".to_string(),
                    arn.clone(),
                    name.clone(),
                    format!("{status}/{enabled}"),
                    String::new(),
                    ips.join(", "),
                ]);

                // Listeners under this accelerator.
                let mut l_paginator = self
                    .client
                    .list_listeners()
                    .accelerator_arn(&arn)
                    .into_paginator()
                    .send();
                while let Some(lp) = l_paginator.next().await {
                    let lresp = match lp {
                        Ok(r) => r,
                        Err(e) => {
                            let msg = format!("{e:#}");
                            if is_benign(&msg) {
                                break;
                            }
                            eprintln!("  WARN: GlobalAccelerator list_listeners({arn}): {msg}");
                            break;
                        }
                    };
                    for l in lresp.listeners() {
                        let l_arn = l.listener_arn().unwrap_or("").to_string();
                        let proto = l
                            .protocol()
                            .map(|p| p.as_str().to_string())
                            .unwrap_or_default();
                        let affinity = l
                            .client_affinity()
                            .map(|a| a.as_str().to_string())
                            .unwrap_or_default();
                        let ports: Vec<String> = l
                            .port_ranges()
                            .iter()
                            .map(|p| {
                                format!(
                                    "{}-{}",
                                    p.from_port().unwrap_or(0),
                                    p.to_port().unwrap_or(0)
                                )
                            })
                            .collect();
                        rows.push(vec![
                            "Listener".to_string(),
                            l_arn.clone(),
                            name.clone(),
                            affinity,
                            proto,
                            ports.join(", "),
                        ]);

                        // Endpoint groups under listener.
                        let mut eg_paginator = self
                            .client
                            .list_endpoint_groups()
                            .listener_arn(&l_arn)
                            .into_paginator()
                            .send();
                        while let Some(ep) = eg_paginator.next().await {
                            let eresp = match ep {
                                Ok(r) => r,
                                Err(e) => {
                                    let msg = format!("{e:#}");
                                    if is_benign(&msg) {
                                        break;
                                    }
                                    eprintln!(
                                        "  WARN: GlobalAccelerator list_endpoint_groups({l_arn}): {msg}"
                                    );
                                    break;
                                }
                            };
                            for g in eresp.endpoint_groups() {
                                let g_arn = g.endpoint_group_arn().unwrap_or("").to_string();
                                let region = g.endpoint_group_region().unwrap_or("").to_string();
                                let dial = g
                                    .traffic_dial_percentage()
                                    .map(|f| format!("{f}%"))
                                    .unwrap_or_default();
                                let hc = g
                                    .health_check_protocol()
                                    .map(|p| p.as_str().to_string())
                                    .unwrap_or_default();
                                rows.push(vec![
                                    "EndpointGroup".to_string(),
                                    g_arn,
                                    name.clone(),
                                    hc,
                                    region,
                                    dial,
                                ]);
                            }
                        }
                    }
                }
            }
        }

        Ok(rows)
    }
}
