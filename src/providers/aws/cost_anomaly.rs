use anyhow::Result;
use async_trait::async_trait;
use aws_sdk_costexplorer::types::{AnomalyDateInterval, DateInterval};
use aws_sdk_costexplorer::Client as CeClient;

use crate::evidence::CsvCollector;

pub struct CostAnomalyCollector {
    client: CeClient,
}

impl CostAnomalyCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self {
            client: CeClient::new(config),
        }
    }
}

fn is_benign(err: &str) -> bool {
    err.contains("AccessDenied")
        || err.contains("AccessDeniedException")
        || err.contains("UnauthorizedOperation")
        || err.contains("not enabled")
        || err.contains("not subscribed")
        || err.contains("OptInRequired")
        || err.contains("DataUnavailableException")
}

#[async_trait]
impl CsvCollector for CostAnomalyCollector {
    fn name(&self) -> &str {
        "Cost Anomaly Detection"
    }
    fn filename_prefix(&self) -> &str {
        "Cost_Anomaly"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Type",
            "ID / Monitor Name",
            "Detail",
            "Start Date",
            "Impact ($)",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let mut rows = Vec::new();

        // 1. List anomaly monitors (paginated via next_page_token).
        let mut next_token: Option<String> = None;
        loop {
            let mut req = self.client.get_anomaly_monitors();
            if let Some(t) = next_token.as_ref() {
                req = req.next_page_token(t);
            }
            let resp = match req.send().await {
                Ok(r) => r,
                Err(e) => {
                    let msg = format!("{e:#}");
                    if is_benign(&msg) {
                        eprintln!("  WARN: Cost Explorer not enabled: skipping anomaly monitors");
                        return Ok(rows);
                    }
                    eprintln!("  WARN: CostExplorer get_anomaly_monitors: {e:#}");
                    break;
                }
            };

            for m in resp.anomaly_monitors() {
                let name = m.monitor_name().to_string();
                let arn = m.monitor_arn().unwrap_or("").to_string();
                let m_type = m.monitor_type().as_str().to_string();
                let creation = m.creation_date().unwrap_or("").to_string();
                rows.push(vec![
                    "Monitor".to_string(),
                    name,
                    format!("Type: {m_type} | ARN: {arn}"),
                    creation,
                    String::new(),
                ]);
            }

            next_token = resp.next_page_token().map(|s| s.to_string());
            if next_token.is_none() {
                break;
            }
        }

        // 2. List anomalies in last 90 days.
        let end_date = chrono::Utc::now().date_naive();
        let start_date = end_date - chrono::Duration::days(90);
        let interval = match AnomalyDateInterval::builder()
            .start_date(start_date.format("%Y-%m-%d").to_string())
            .end_date(end_date.format("%Y-%m-%d").to_string())
            .build()
        {
            Ok(i) => i,
            Err(e) => {
                eprintln!("  WARN: CostExplorer building date interval: {e:#}");
                return Ok(rows);
            }
        };
        let _ = DateInterval::builder(); // keep import warm if unused above

        let mut next_token: Option<String> = None;
        loop {
            let mut req = self.client.get_anomalies().date_interval(interval.clone());
            if let Some(t) = next_token.as_ref() {
                req = req.next_page_token(t);
            }
            let resp = match req.send().await {
                Ok(r) => r,
                Err(e) => {
                    let msg = format!("{e:#}");
                    if is_benign(&msg) {
                        return Ok(rows);
                    }
                    eprintln!("  WARN: CostExplorer get_anomalies: {e:#}");
                    break;
                }
            };

            for a in resp.anomalies() {
                let id = a.anomaly_id().to_string();
                let monitor_arn = a.monitor_arn().to_string();
                let start = a.anomaly_start_date().unwrap_or("").to_string();
                let end = a.anomaly_end_date().unwrap_or("").to_string();
                let impact = a
                    .impact()
                    .map(|i| format!("{:.2}", i.total_impact()))
                    .unwrap_or_default();
                rows.push(vec![
                    "Anomaly".to_string(),
                    id,
                    format!("Monitor: {monitor_arn} | End: {end}"),
                    start,
                    impact,
                ]);
            }

            next_token = resp.next_page_token().map(|s| s.to_string());
            if next_token.is_none() {
                break;
            }
        }

        Ok(rows)
    }
}
