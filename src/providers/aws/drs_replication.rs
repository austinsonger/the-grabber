use anyhow::Result;
use async_trait::async_trait;
use aws_sdk_drs::Client as DrsClient;

use crate::evidence::CsvCollector;

// ══════════════════════════════════════════════════════════════════════════════
// DRS Source Server Replication Collector
// ══════════════════════════════════════════════════════════════════════════════

pub struct DrsReplicationCollector {
    client: DrsClient,
}

impl DrsReplicationCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self {
            client: DrsClient::new(config),
        }
    }
}

#[async_trait]
impl CsvCollector for DrsReplicationCollector {
    fn name(&self) -> &str {
        "DRS Source Server Replication"
    }
    fn filename_prefix(&self) -> &str {
        "DRS_Replication_Status"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Source Server ID",
            "Source Hostname",
            "Replication State",
            "Lag Duration",
            "Last Snapshot",
            "Recovery Instance ID",
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
            let mut req = self.client.describe_source_servers().max_results(50);
            if let Some(ref t) = next_token {
                req = req.next_token(t);
            }
            let resp = match req.send().await {
                Ok(r) => r,
                Err(e) => {
                    let msg = format!("{e:#}");
                    if msg.contains("UninitializedAccountException")
                        || msg.contains("Uninitialized")
                    {
                        eprintln!("  WARN: DRS not initialized in this account/region: {msg}");
                        return Ok(rows);
                    }
                    eprintln!("  WARN: DRS describe_source_servers: {msg}");
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

                let last_snap = server
                    .life_cycle()
                    .and_then(|lc| lc.last_seen_by_service_date_time())
                    .unwrap_or("")
                    .to_string();

                let recovery_id = server.recovery_instance_id().unwrap_or("").to_string();

                rows.push(vec![
                    server_id,
                    hostname,
                    state,
                    lag,
                    last_snap,
                    recovery_id,
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
