use anyhow::Result;
use async_trait::async_trait;
use aws_sdk_health::primitives::DateTime as AwsDateTime;
use aws_sdk_health::types::{DateTimeRange, EventFilter, EventTypeCategory};
use aws_sdk_health::Client as HealthClient;

use crate::evidence::CsvCollector;

pub struct AwsHealthCollector {
    client: HealthClient,
}

impl AwsHealthCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self {
            client: HealthClient::new(config),
        }
    }
}

#[async_trait]
impl CsvCollector for AwsHealthCollector {
    fn name(&self) -> &str {
        "AWS Health Events"
    }
    fn filename_prefix(&self) -> &str {
        "AWS_Health_Events"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Event ARN",
            "Service",
            "Event Type Code",
            "Region",
            "Start Time",
            "End Time",
            "Status",
            "Category",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let mut rows = Vec::new();

        let now_secs = chrono::Utc::now().timestamp();
        let from_secs = now_secs - 90 * 24 * 60 * 60;
        let start_range = DateTimeRange::builder()
            .from(AwsDateTime::from_secs(from_secs))
            .build();

        let filter = EventFilter::builder()
            .event_type_categories(EventTypeCategory::Issue)
            .event_type_categories(EventTypeCategory::ScheduledChange)
            .event_type_categories(EventTypeCategory::AccountNotification)
            .start_times(start_range)
            .build();

        let mut next_token: Option<String> = None;
        loop {
            let mut req = self.client.describe_events().filter(filter.clone());
            if let Some(t) = next_token.as_ref() {
                req = req.next_token(t);
            }
            let resp = match req.send().await {
                Ok(r) => r,
                Err(e) => {
                    let msg = format!("{e:#}");
                    if msg.contains("SubscriptionRequiredException") {
                        rows.push(vec![
                            String::new(),
                            "Support tier insufficient".to_string(),
                            String::new(),
                            String::new(),
                            String::new(),
                            String::new(),
                            String::new(),
                            String::new(),
                        ]);
                        return Ok(rows);
                    }
                    eprintln!("  WARN: Health describe_events: {e:#}");
                    return Ok(rows);
                }
            };

            for ev in resp.events() {
                let arn = ev.arn().unwrap_or("").to_string();
                let service = ev.service().unwrap_or("").to_string();
                let etc = ev.event_type_code().unwrap_or("").to_string();
                let region = ev.region().unwrap_or("").to_string();
                let start_time = ev.start_time().map(|t| t.to_string()).unwrap_or_default();
                let end_time = ev.end_time().map(|t| t.to_string()).unwrap_or_default();
                let status = ev
                    .status_code()
                    .map(|s| s.as_str().to_string())
                    .unwrap_or_default();
                let category = ev
                    .event_type_category()
                    .map(|c| c.as_str().to_string())
                    .unwrap_or_default();

                rows.push(vec![
                    arn, service, etc, region, start_time, end_time, status, category,
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
