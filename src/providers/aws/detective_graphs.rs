use std::collections::BTreeSet;

use anyhow::Result;
use async_trait::async_trait;
use aws_sdk_detective::Client as DetectiveClient;

use crate::evidence::CsvCollector;

// ══════════════════════════════════════════════════════════════════════════════
// Detective Graphs Configuration
// ══════════════════════════════════════════════════════════════════════════════

pub struct DetectiveGraphsCollector {
    client: DetectiveClient,
}

impl DetectiveGraphsCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self {
            client: DetectiveClient::new(config),
        }
    }
}

fn fmt_dt(dt: &aws_sdk_detective::primitives::DateTime) -> String {
    chrono::DateTime::<chrono::Utc>::from_timestamp(dt.secs(), dt.subsec_nanos())
        .map(|c| c.to_rfc3339())
        .unwrap_or_default()
}

#[async_trait]
impl CsvCollector for DetectiveGraphsCollector {
    fn name(&self) -> &str {
        "Detective Graphs"
    }
    fn filename_prefix(&self) -> &str {
        "Detective_Graphs_Config"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Graph ARN",
            "Created Time",
            "Member Account ID",
            "Member Status",
            "Datasource Packages",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let mut rows = Vec::new();

        // List all graphs (paginated).
        let mut graphs: Vec<(String, String)> = Vec::new();
        let mut next_token: Option<String> = None;
        loop {
            let mut req = self.client.list_graphs();
            if let Some(ref t) = next_token {
                req = req.next_token(t);
            }
            let resp = match req.send().await {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("  WARN: Detective list_graphs: {e:#}");
                    break;
                }
            };
            for g in resp.graph_list() {
                let arn = g.arn().unwrap_or("").to_string();
                let created = g.created_time().map(fmt_dt).unwrap_or_default();
                graphs.push((arn, created));
            }
            match resp.next_token() {
                Some(t) if !t.is_empty() => next_token = Some(t.to_string()),
                _ => break,
            }
        }

        for (graph_arn, created) in graphs {
            // Collect datasource packages for the graph (de-duplicated).
            let mut pkgs: BTreeSet<String> = BTreeSet::new();
            let mut next_token: Option<String> = None;
            loop {
                let mut req = self
                    .client
                    .list_datasource_packages()
                    .graph_arn(graph_arn.clone());
                if let Some(ref t) = next_token {
                    req = req.next_token(t);
                }
                let resp = match req.send().await {
                    Ok(r) => r,
                    Err(e) => {
                        eprintln!("  WARN: Detective list_datasource_packages {graph_arn}: {e:#}");
                        break;
                    }
                };
                if let Some(map) = resp.datasource_packages() {
                    for k in map.keys() {
                        pkgs.insert(k.as_str().to_string());
                    }
                }
                match resp.next_token() {
                    Some(t) if !t.is_empty() => next_token = Some(t.to_string()),
                    _ => break,
                }
            }
            let pkgs_str = pkgs.into_iter().collect::<Vec<_>>().join(", ");

            // List members for the graph.
            let mut any_member = false;
            let mut next_token: Option<String> = None;
            loop {
                let mut req = self.client.list_members().graph_arn(graph_arn.clone());
                if let Some(ref t) = next_token {
                    req = req.next_token(t);
                }
                let resp = match req.send().await {
                    Ok(r) => r,
                    Err(e) => {
                        eprintln!("  WARN: Detective list_members {graph_arn}: {e:#}");
                        break;
                    }
                };
                for m in resp.member_details() {
                    any_member = true;
                    let acct = m.account_id().unwrap_or("").to_string();
                    let status = m
                        .status()
                        .map(|s| s.as_str().to_string())
                        .unwrap_or_default();
                    rows.push(vec![
                        graph_arn.clone(),
                        created.clone(),
                        acct,
                        status,
                        pkgs_str.clone(),
                    ]);
                }
                match resp.next_token() {
                    Some(t) if !t.is_empty() => next_token = Some(t.to_string()),
                    _ => break,
                }
            }

            if !any_member {
                rows.push(vec![
                    graph_arn,
                    created,
                    String::new(),
                    String::new(),
                    pkgs_str,
                ]);
            }
        }

        Ok(rows)
    }
}
