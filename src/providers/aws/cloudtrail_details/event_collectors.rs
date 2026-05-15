use anyhow::{Context, Result};
use async_trait::async_trait;
use aws_sdk_cloudtrail::Client as CtClient;

use crate::evidence::CsvCollector;

// ══════════════════════════════════════════════════════════════════════════════
// 4. Change Events Collector
// ══════════════════════════════════════════════════════════════════════════════

pub struct CloudTrailChangeEventsCollector {
    client: CtClient,
}

impl CloudTrailChangeEventsCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self {
            client: CtClient::new(config),
        }
    }
}

#[async_trait]
impl CsvCollector for CloudTrailChangeEventsCollector {
    fn name(&self) -> &str {
        "CloudTrail Change Events"
    }
    fn filename_prefix(&self) -> &str {
        "CloudTrail_ChangeEvents"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Event Name",
            "Event Source",
            "Resource Type",
            "Resource Name",
            "User Identity",
            "Timestamp",
            "Source IP",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        use aws_sdk_cloudtrail::types::{LookupAttribute, LookupAttributeKey};

        let mut rows = Vec::new();
        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        let (start_secs, end_secs) = dates.unwrap_or((now_secs - 7 * 24 * 3600, now_secs));
        let start_dt = aws_sdk_cloudtrail::primitives::DateTime::from_secs(start_secs);
        let end_dt = aws_sdk_cloudtrail::primitives::DateTime::from_secs(end_secs);

        let lookup_attr = LookupAttribute::builder()
            .attribute_key(LookupAttributeKey::ReadOnly)
            .attribute_value("false")
            .build()
            .context("build LookupAttribute")?;

        let mut next_token: Option<String> = None;
        let mut page_count = 0;

        loop {
            if page_count >= 10 {
                break;
            }

            let mut req = self
                .client
                .lookup_events()
                .lookup_attributes(lookup_attr.clone())
                .start_time(start_dt)
                .end_time(end_dt)
                .max_results(50);
            if let Some(ref t) = next_token {
                req = req.next_token(t);
            }

            let resp = match req.send().await {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("  WARN: CloudTrail lookup_events: {e:#}");
                    break;
                }
            };

            for event in resp.events() {
                let event_name = event.event_name().unwrap_or("").to_string();
                let event_source = event.event_source().unwrap_or("").to_string();

                let (resource_type, resource_name) = event
                    .resources()
                    .first()
                    .map(|r| {
                        (
                            r.resource_type().unwrap_or("").to_string(),
                            r.resource_name().unwrap_or("").to_string(),
                        )
                    })
                    .unwrap_or_default();

                let username = event.username().unwrap_or("").to_string();

                let timestamp = event.event_time().map(super::fmt_dt).unwrap_or_default();

                // Extract sourceIPAddress from raw CloudTrail JSON
                let source_ip = event
                    .cloud_trail_event()
                    .and_then(|raw| serde_json::from_str::<serde_json::Value>(raw).ok())
                    .and_then(|v| {
                        v.get("sourceIPAddress")
                            .and_then(|ip| ip.as_str())
                            .map(|s| s.to_string())
                    })
                    .unwrap_or_default();

                rows.push(vec![
                    event_name,
                    event_source,
                    resource_type,
                    resource_name,
                    username,
                    timestamp,
                    source_ip,
                ]);
            }

            next_token = resp.next_token().map(|s| s.to_string());
            page_count += 1;

            if next_token.is_none() {
                break;
            }

            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        }

        Ok(rows)
    }
}

// ══════════════════════════════════════════════════════════════════════════════
// 5. S3 Data Events Collector
// ══════════════════════════════════════════════════════════════════════════════

pub struct S3DataEventsCollector {
    client: CtClient,
}

impl S3DataEventsCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self {
            client: CtClient::new(config),
        }
    }
}

#[async_trait]
impl CsvCollector for S3DataEventsCollector {
    fn name(&self) -> &str {
        "CloudTrail S3 Data Events"
    }
    fn filename_prefix(&self) -> &str {
        "CloudTrail_S3DataEvents"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Trail Name",
            "S3 Bucket/Prefix",
            "Read Events",
            "Write Events",
            "Advanced Selector",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let mut rows = Vec::new();

        let trails_resp = self
            .client
            .describe_trails()
            .include_shadow_trails(false)
            .send()
            .await
            .context("CloudTrail describe_trails")?;

        for trail in trails_resp.trail_list() {
            let trail_name = trail.name().unwrap_or("").to_string();

            let sel_resp = match self
                .client
                .get_event_selectors()
                .trail_name(&trail_name)
                .send()
                .await
            {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("  WARN: CloudTrail get_event_selectors for {trail_name}: {e:#}");
                    continue;
                }
            };

            // Classic event selectors
            for es in sel_resp.event_selectors() {
                let rw_type = es
                    .read_write_type()
                    .map(|t| t.as_str().to_string())
                    .unwrap_or_else(|| "All".to_string());

                for dr in es.data_resources() {
                    if dr.r#type() == Some("AWS::S3::Object") {
                        for val in dr.values() {
                            let read_events =
                                matches!(rw_type.as_str(), "ReadOnly" | "All").to_string();
                            let write_events =
                                matches!(rw_type.as_str(), "WriteOnly" | "All").to_string();
                            rows.push(vec![
                                trail_name.clone(),
                                val.to_string(),
                                read_events,
                                write_events,
                                "No".to_string(),
                            ]);
                        }
                    }
                }
            }

            // Advanced event selectors
            for aes in sel_resp.advanced_event_selectors() {
                let name = aes.name().unwrap_or("").to_string();
                // Check if this selector covers S3 data events
                let has_s3 = aes.field_selectors().iter().any(|fs| {
                    fs.field() == "resources.type"
                        && fs.equals().iter().any(|v| v == "AWS::S3::Object")
                });
                if has_s3 {
                    rows.push(vec![
                        trail_name.clone(),
                        "S3 (Advanced Selector)".to_string(),
                        "true".to_string(),
                        "true".to_string(),
                        name,
                    ]);
                }
            }
        }

        Ok(rows)
    }
}
