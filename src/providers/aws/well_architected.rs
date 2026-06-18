use anyhow::Result;
use async_trait::async_trait;
use aws_sdk_wellarchitected::types::Risk;
use aws_sdk_wellarchitected::Client as WaClient;

use crate::evidence::CsvCollector;

pub struct WellArchitectedCollector {
    client: WaClient,
}

impl WellArchitectedCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self {
            client: WaClient::new(config),
        }
    }
}

fn is_benign(err: &str) -> bool {
    err.contains("AccessDenied")
        || err.contains("ResourceNotFoundException")
        || err.contains("ValidationException")
        || err.contains("not enabled")
        || err.contains("not subscribed")
        || err.contains("UnknownService")
        || err.contains("dispatch failure")
        || err.contains("could not be found")
}

fn risk_count(map: Option<&std::collections::HashMap<Risk, i32>>, key: &Risk) -> String {
    map.and_then(|m| m.get(key))
        .map(|n| n.to_string())
        .unwrap_or_default()
}

#[async_trait]
impl CsvCollector for WellArchitectedCollector {
    fn name(&self) -> &str {
        "Well-Architected Workloads"
    }
    fn filename_prefix(&self) -> &str {
        "WellArchitected_Workloads"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Type",
            "Workload ID",
            "Name / Lens Alias",
            "High Risks",
            "Medium Risks",
            "Unanswered",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let mut rows: Vec<Vec<String>> = Vec::new();

        // Collect all workload summaries (paginated).
        let mut workloads: Vec<(String, String)> = Vec::new();
        let mut next_token: Option<String> = None;
        loop {
            let mut req = self.client.list_workloads();
            if let Some(t) = next_token.as_ref() {
                req = req.next_token(t);
            }
            let resp = match req.send().await {
                Ok(r) => r,
                Err(e) => {
                    let msg = format!("{e:#}");
                    if is_benign(&msg) {
                        return Ok(rows);
                    }
                    eprintln!("  WARN: WellArchitected list_workloads: {e:#}");
                    break;
                }
            };

            for ws in resp.workload_summaries() {
                let id = ws.workload_id().unwrap_or("").to_string();
                let name = ws.workload_name().unwrap_or("").to_string();
                let high = risk_count(ws.risk_counts(), &Risk::High);
                let medium = risk_count(ws.risk_counts(), &Risk::Medium);
                let unanswered = risk_count(ws.risk_counts(), &Risk::Unanswered);

                rows.push(vec![
                    "Workload".to_string(),
                    id.clone(),
                    name.clone(),
                    high,
                    medium,
                    unanswered,
                ]);
                workloads.push((id, name));
            }

            next_token = resp.next_token().map(|s| s.to_string());
            if next_token.is_none() {
                break;
            }
        }

        // For each workload, fetch lens reviews.
        for (workload_id, _workload_name) in &workloads {
            if workload_id.is_empty() {
                continue;
            }
            let mut lens_token: Option<String> = None;
            loop {
                let mut req = self.client.list_lens_reviews().workload_id(workload_id);
                if let Some(t) = lens_token.as_ref() {
                    req = req.next_token(t);
                }
                let resp = match req.send().await {
                    Ok(r) => r,
                    Err(e) => {
                        let msg = format!("{e:#}");
                        if !is_benign(&msg) {
                            eprintln!(
                                "  WARN: WellArchitected list_lens_reviews({workload_id}): {e:#}"
                            );
                        }
                        break;
                    }
                };

                for lens in resp.lens_review_summaries() {
                    let alias = lens.lens_alias().unwrap_or("").to_string();
                    let high = risk_count(lens.risk_counts(), &Risk::High);
                    let medium = risk_count(lens.risk_counts(), &Risk::Medium);
                    let unanswered = risk_count(lens.risk_counts(), &Risk::Unanswered);

                    rows.push(vec![
                        "LensReview".to_string(),
                        workload_id.clone(),
                        alias,
                        high,
                        medium,
                        unanswered,
                    ]);
                }

                lens_token = resp.next_token().map(|s| s.to_string());
                if lens_token.is_none() {
                    break;
                }
            }
        }

        Ok(rows)
    }
}
