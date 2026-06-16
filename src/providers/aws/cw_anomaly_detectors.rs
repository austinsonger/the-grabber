use anyhow::Result;
use async_trait::async_trait;
use aws_sdk_cloudwatch::Client as CwClient;

use crate::evidence::CsvCollector;

// ══════════════════════════════════════════════════════════════════════════════
// CloudWatch Anomaly Detectors
// ══════════════════════════════════════════════════════════════════════════════

pub struct CloudWatchAnomalyDetectorsCollector {
    client: CwClient,
}

impl CloudWatchAnomalyDetectorsCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self {
            client: CwClient::new(config),
        }
    }
}

#[async_trait]
impl CsvCollector for CloudWatchAnomalyDetectorsCollector {
    fn name(&self) -> &str {
        "CloudWatch Anomaly Detectors"
    }
    fn filename_prefix(&self) -> &str {
        "CloudWatch_AnomalyDetectors"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Detector Type",
            "Metric Namespace",
            "Metric Name",
            "Dimensions",
            "Stat",
            "State",
            "Configuration Excerpt",
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
            let mut req = self.client.describe_anomaly_detectors();
            if let Some(ref t) = next_token {
                req = req.next_token(t);
            }
            let resp = match req.send().await {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("  WARN: CloudWatch describe_anomaly_detectors: {e:#}");
                    break;
                }
            };

            for d in resp.anomaly_detectors() {
                let (detector_type, namespace, metric_name, dims, stat, excerpt) = if let Some(s) =
                    d.single_metric_anomaly_detector()
                {
                    let ns = s.namespace().unwrap_or("").to_string();
                    let mn = s.metric_name().unwrap_or("").to_string();
                    let dims = s
                        .dimensions()
                        .iter()
                        .map(|x| format!("{}={}", x.name().unwrap_or(""), x.value().unwrap_or("")))
                        .collect::<Vec<_>>()
                        .join(";");
                    let st = s.stat().unwrap_or("").to_string();
                    ("SingleMetric".to_string(), ns, mn, dims, st, String::new())
                } else if let Some(_m) = d.metric_math_anomaly_detector() {
                    let excerpt = "metric-math expression".to_string();
                    (
                        "MetricMath".to_string(),
                        String::new(),
                        String::new(),
                        String::new(),
                        String::new(),
                        excerpt,
                    )
                } else if let Some(c) = d.metric_characteristics() {
                    let excerpt = format!(
                        "periodic_spikes={}",
                        c.periodic_spikes()
                            .map(|b| b.to_string())
                            .unwrap_or_default()
                    );
                    (
                        "MetricCharacteristics".to_string(),
                        String::new(),
                        String::new(),
                        String::new(),
                        String::new(),
                        excerpt,
                    )
                } else {
                    // Legacy top-level fields (deprecated)
                    let ns = d.namespace().unwrap_or("").to_string();
                    let mn = d.metric_name().unwrap_or("").to_string();
                    let dims = d
                        .dimensions()
                        .iter()
                        .map(|x| format!("{}={}", x.name().unwrap_or(""), x.value().unwrap_or("")))
                        .collect::<Vec<_>>()
                        .join(";");
                    let st = d.stat().unwrap_or("").to_string();
                    ("SingleMetric".to_string(), ns, mn, dims, st, String::new())
                };

                let state = d
                    .state_value()
                    .map(|s| s.as_str().to_string())
                    .unwrap_or_default();

                rows.push(vec![
                    detector_type,
                    namespace,
                    metric_name,
                    dims,
                    stat,
                    state,
                    excerpt,
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
