use anyhow::Result;
use async_trait::async_trait;
use aws_sdk_mgn::types::DescribeSourceServersRequestFilters;
use aws_sdk_mgn::Client as MgnClient;

use crate::evidence::CsvCollector;

// ══════════════════════════════════════════════════════════════════════════════
// MGN Source Servers Collector
// ══════════════════════════════════════════════════════════════════════════════

pub struct MgnSourceServersCollector {
    client: MgnClient,
}

impl MgnSourceServersCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self {
            client: MgnClient::new(config),
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
        || err.contains("UninitializedAccountException")
        || err.contains("Uninitialized")
}

#[async_trait]
impl CsvCollector for MgnSourceServersCollector {
    fn name(&self) -> &str {
        "MGN Source Servers"
    }
    fn filename_prefix(&self) -> &str {
        "MGN_SourceServers"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Source Server ID",
            "Hostname",
            "Replication State",
            "Lag",
            "Lifecycle",
            "Replication Type",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let mut rows: Vec<Vec<String>> = Vec::new();
        let empty_filter = DescribeSourceServersRequestFilters::builder().build();
        let mut paginator = self
            .client
            .describe_source_servers()
            .filters(empty_filter)
            .into_paginator()
            .send();

        while let Some(page) = paginator.next().await {
            let resp = match page {
                Ok(r) => r,
                Err(e) => {
                    let msg = format!("{e:#}");
                    if is_benign(&msg) {
                        return Ok(rows);
                    }
                    eprintln!("  WARN: MGN describe_source_servers: {msg}");
                    return Ok(rows);
                }
            };

            for server in resp.items() {
                let server_id = server.source_server_id().unwrap_or("").to_string();
                let hostname = server
                    .source_properties()
                    .and_then(|p| p.identification_hints())
                    .and_then(|h| h.hostname())
                    .unwrap_or("")
                    .to_string();

                let (state, lag) = if let Some(info) = server.data_replication_info() {
                    let state = info
                        .data_replication_state()
                        .map(|s| s.as_str().to_string())
                        .unwrap_or_default();
                    let lag = info.lag_duration().unwrap_or("").to_string();
                    (state, lag)
                } else {
                    (String::new(), String::new())
                };

                let lifecycle = server
                    .life_cycle()
                    .and_then(|lc| lc.state())
                    .map(|s| s.as_str().to_string())
                    .unwrap_or_default();

                let repl_type = server
                    .replication_type()
                    .map(|t| t.as_str().to_string())
                    .unwrap_or_default();

                rows.push(vec![server_id, hostname, state, lag, lifecycle, repl_type]);
            }
        }

        Ok(rows)
    }
}
