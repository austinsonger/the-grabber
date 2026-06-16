use anyhow::Result;
use async_trait::async_trait;
use aws_sdk_cloudtrail::types::EventCategory;
use aws_sdk_cloudtrail::Client as CtClient;

use crate::evidence::CsvCollector;

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

fn fmt_dt(dt: &aws_sdk_cloudtrail::primitives::DateTime) -> String {
    chrono::DateTime::<chrono::Utc>::from_timestamp(dt.secs(), 0)
        .map(|c| c.to_rfc3339())
        .unwrap_or_default()
}

// ══════════════════════════════════════════════════════════════════════════════
// CloudTrail Insights Events
// ══════════════════════════════════════════════════════════════════════════════

pub struct CloudTrailInsightsCollector {
    client: CtClient,
}

impl CloudTrailInsightsCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self {
            client: CtClient::new(config),
        }
    }
}

#[async_trait]
impl CsvCollector for CloudTrailInsightsCollector {
    fn name(&self) -> &str {
        "CloudTrail Insights"
    }
    fn filename_prefix(&self) -> &str {
        "CloudTrail_Insights"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Trail Name",
            "Insight Type",
            "Event Time",
            "Insight State",
            "Source",
            "Baseline Average",
            "Insight Value",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let mut rows = Vec::new();
        let (start_secs, end_secs) = dates.unwrap_or_else(|| {
            let end = now_secs();
            (end - 90 * 24 * 3600, end)
        });
        let start_dt = aws_sdk_cloudtrail::primitives::DateTime::from_secs(start_secs);
        let end_dt = aws_sdk_cloudtrail::primitives::DateTime::from_secs(end_secs);

        // Enumerate trails via list_trails pagination.
        let mut trail_names: Vec<String> = Vec::new();
        let mut trails_paginator = self.client.list_trails().into_paginator().send();
        while let Some(page) = trails_paginator.next().await {
            let resp = match page {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("  WARN: CloudTrail list_trails: {e:#}");
                    break;
                }
            };
            for t in resp.trails() {
                if let Some(name) = t.name() {
                    trail_names.push(name.to_string());
                }
            }
        }

        for trail_name in &trail_names {
            // Determine whether insights are enabled on this trail.
            let selectors_resp = match self
                .client
                .get_insight_selectors()
                .trail_name(trail_name)
                .send()
                .await
            {
                Ok(r) => r,
                Err(e) => {
                    // InsightNotEnabledException, trail not found, or access denied — skip.
                    let msg = format!("{e:#}");
                    if !msg.contains("InsightNotEnabled") {
                        eprintln!("  WARN: CloudTrail get_insight_selectors [{trail_name}]: {msg}");
                    }
                    continue;
                }
            };

            if selectors_resp.insight_selectors().is_empty() {
                continue;
            }

            // Look up insight events for the window.
            let mut paginator = self
                .client
                .lookup_events()
                .event_category(EventCategory::Insight)
                .start_time(start_dt)
                .end_time(end_dt)
                .into_paginator()
                .send();

            while let Some(page) = paginator.next().await {
                let resp = match page {
                    Ok(r) => r,
                    Err(e) => {
                        eprintln!(
                            "  WARN: CloudTrail lookup_events [insight, {trail_name}]: {e:#}"
                        );
                        break;
                    }
                };
                for event in resp.events() {
                    let raw: serde_json::Value = event
                        .cloud_trail_event()
                        .and_then(|s| serde_json::from_str(s).ok())
                        .unwrap_or_default();
                    let event_time = event.event_time().map(fmt_dt).unwrap_or_default();
                    let event_source = raw
                        .get("eventSource")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();

                    let insight_details = raw.get("insightDetails").cloned().unwrap_or_default();
                    let insight_type = insight_details
                        .get("insightType")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();
                    let insight_state = insight_details
                        .get("state")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();
                    let insight_ctx = insight_details
                        .get("insightContext")
                        .cloned()
                        .unwrap_or_default();
                    let baseline = insight_ctx
                        .get("statistics")
                        .and_then(|s| s.get("baseline"))
                        .and_then(|b| b.get("average"))
                        .map(|v| v.to_string())
                        .unwrap_or_else(|| {
                            insight_ctx
                                .get("baselineAverage")
                                .map(|v| v.to_string())
                                .unwrap_or_default()
                        });
                    let value = insight_ctx
                        .get("statistics")
                        .and_then(|s| s.get("insight"))
                        .and_then(|i| i.get("average"))
                        .map(|v| v.to_string())
                        .unwrap_or_else(|| {
                            insight_ctx
                                .get("insightValue")
                                .map(|v| v.to_string())
                                .unwrap_or_default()
                        });

                    rows.push(vec![
                        trail_name.clone(),
                        insight_type,
                        event_time,
                        insight_state,
                        event_source,
                        baseline,
                        value,
                    ]);
                }
            }
        }

        Ok(rows)
    }
}
