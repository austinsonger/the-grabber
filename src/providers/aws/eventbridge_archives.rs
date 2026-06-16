use std::collections::HashMap;

use anyhow::Result;
use async_trait::async_trait;
use aws_sdk_eventbridge::Client as EbClient;

use crate::evidence::CsvCollector;

// ══════════════════════════════════════════════════════════════════════════════
// EventBridge Archives & Replays
// ══════════════════════════════════════════════════════════════════════════════

pub struct EventBridgeArchivesCollector {
    client: EbClient,
}

impl EventBridgeArchivesCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self {
            client: EbClient::new(config),
        }
    }
}

#[async_trait]
impl CsvCollector for EventBridgeArchivesCollector {
    fn name(&self) -> &str {
        "EventBridge Archives & Replays"
    }
    fn filename_prefix(&self) -> &str {
        "EventBridge_Archives_Replays"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Archive Name",
            "Event Source ARN",
            "State",
            "Retention Days",
            "Size (bytes)",
            "Event Count",
            "Recent Replay Count",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let mut rows = Vec::new();

        // Count replays per event source ARN.
        let mut replay_counts: HashMap<String, usize> = HashMap::new();
        let mut next_token: Option<String> = None;
        loop {
            let mut req = self.client.list_replays();
            if let Some(ref t) = next_token {
                req = req.next_token(t);
            }
            let resp = match req.send().await {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("  WARN: EventBridge list_replays: {e:#}");
                    break;
                }
            };
            for r in resp.replays() {
                if let Some(arn) = r.event_source_arn() {
                    *replay_counts.entry(arn.to_string()).or_insert(0) += 1;
                }
            }
            match resp.next_token() {
                Some(t) if !t.is_empty() => next_token = Some(t.to_string()),
                _ => break,
            }
        }

        // Enumerate archives.
        let mut next_token: Option<String> = None;
        loop {
            let mut req = self.client.list_archives();
            if let Some(ref t) = next_token {
                req = req.next_token(t);
            }
            let resp = match req.send().await {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("  WARN: EventBridge list_archives: {e:#}");
                    break;
                }
            };
            for a in resp.archives() {
                let name = a.archive_name().unwrap_or("").to_string();
                let src = a.event_source_arn().unwrap_or("").to_string();
                let state = a
                    .state()
                    .map(|s| s.as_str().to_string())
                    .unwrap_or_default();
                let retention = a
                    .retention_days()
                    .map(|v| v.to_string())
                    .unwrap_or_default();
                let size_bytes = a.size_bytes().to_string();
                let event_count = a.event_count().to_string();
                let replay_count = replay_counts.get(&src).copied().unwrap_or(0).to_string();

                rows.push(vec![
                    name,
                    src,
                    state,
                    retention,
                    size_bytes,
                    event_count,
                    replay_count,
                ]);
            }
            match resp.next_token() {
                Some(t) if !t.is_empty() => next_token = Some(t.to_string()),
                _ => break,
            }
        }

        Ok(rows)
    }
}
