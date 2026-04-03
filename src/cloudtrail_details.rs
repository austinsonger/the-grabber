use anyhow::{Context, Result};
use async_trait::async_trait;
use aws_sdk_cloudtrail::Client as CtClient;
use aws_sdk_s3::Client as S3Client;

use crate::evidence::CsvCollector;

// ─── helpers ──────────────────────────────────────────────────────────────────

fn fmt_dt(dt: &aws_sdk_cloudtrail::primitives::DateTime) -> String {
    chrono::DateTime::<chrono::Utc>::from_timestamp(dt.secs(), 0)
        .map(|c| c.to_rfc3339())
        .unwrap_or_default()
}

// ══════════════════════════════════════════════════════════════════════════════
// 1. Event Selectors
// ══════════════════════════════════════════════════════════════════════════════

pub struct CloudTrailEventSelectorsCollector {
    client: CtClient,
}

impl CloudTrailEventSelectorsCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self { client: CtClient::new(config) }
    }
}

#[async_trait]
impl CsvCollector for CloudTrailEventSelectorsCollector {
    fn name(&self) -> &str { "CloudTrail Event Selectors" }
    fn filename_prefix(&self) -> &str { "CloudTrail_EventSelectors" }
    fn headers(&self) -> &'static [&'static str] {
        &["Trail Name", "Trail ARN", "Management Events", "Read Write Type", "Data Events Enabled", "Data Resource Types"]
    }

    async fn collect_rows(&self, _account_id: &str, _region: &str, _dates: Option<(i64, i64)>) -> Result<Vec<Vec<String>>> {
        let mut rows = Vec::new();

        let trails_resp = self.client
            .describe_trails()
            .include_shadow_trails(false)
            .send()
            .await
            .context("CloudTrail describe_trails")?;

        for trail in trails_resp.trail_list() {
            let trail_name = trail.name().unwrap_or("").to_string();
            let trail_arn = trail.trail_arn().unwrap_or("").to_string();

            let sel_resp = match self.client
                .get_event_selectors()
                .trail_name(&trail_name)
                .send()
                .await
            {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("  WARN: CloudTrail get_event_selectors for {trail_name}: {e:#}");
                    rows.push(vec![trail_name, trail_arn, String::new(), String::new(), String::new(), String::new()]);
                    continue;
                }
            };

            let event_selectors = sel_resp.event_selectors();
            let advanced = sel_resp.advanced_event_selectors();

            if !event_selectors.is_empty() {
                for es in event_selectors {
                    let mgmt = es.include_management_events().unwrap_or(false).to_string();
                    let rw_type = es.read_write_type()
                        .map(|t| t.as_str().to_string())
                        .unwrap_or_default();
                    let data_resources = es.data_resources();
                    let data_enabled = (!data_resources.is_empty()).to_string();
                    let data_types: Vec<String> = data_resources.iter()
                        .filter_map(|dr| dr.r#type())
                        .map(|t| t.to_string())
                        .collect::<std::collections::HashSet<_>>()
                        .into_iter()
                        .collect();
                    rows.push(vec![
                        trail_name.clone(),
                        trail_arn.clone(),
                        mgmt,
                        rw_type,
                        data_enabled,
                        data_types.join(", "),
                    ]);
                }
            } else if !advanced.is_empty() {
                let types: Vec<String> = advanced.iter().map(|a| a.name().unwrap_or("").to_string()).collect();
                rows.push(vec![
                    trail_name,
                    trail_arn,
                    "true".to_string(),
                    "All".to_string(),
                    "Advanced".to_string(),
                    types.join(", "),
                ]);
            } else {
                rows.push(vec![trail_name, trail_arn, String::new(), String::new(), "false".to_string(), String::new()]);
            }
        }

        Ok(rows)
    }
}

// ══════════════════════════════════════════════════════════════════════════════
// 2. Log Validation
// ══════════════════════════════════════════════════════════════════════════════

pub struct CloudTrailLogValidationCollector {
    client: CtClient,
}

impl CloudTrailLogValidationCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self { client: CtClient::new(config) }
    }
}

#[async_trait]
impl CsvCollector for CloudTrailLogValidationCollector {
    fn name(&self) -> &str { "CloudTrail Log Validation" }
    fn filename_prefix(&self) -> &str { "CloudTrail_LogValidation" }
    fn headers(&self) -> &'static [&'static str] {
        &["Trail Name", "S3 Bucket", "Log Validation Enabled", "Is Logging", "Latest Delivery", "Latest Digest"]
    }

    async fn collect_rows(&self, _account_id: &str, _region: &str, _dates: Option<(i64, i64)>) -> Result<Vec<Vec<String>>> {
        let mut rows = Vec::new();

        let trails_resp = self.client
            .describe_trails()
            .include_shadow_trails(false)
            .send()
            .await
            .context("CloudTrail describe_trails")?;

        for trail in trails_resp.trail_list() {
            let trail_name = trail.name().unwrap_or("").to_string();
            let s3_bucket = trail.s3_bucket_name().unwrap_or("").to_string();
            let log_validation = trail.log_file_validation_enabled().unwrap_or(false).to_string();

            let (is_logging, latest_delivery, latest_digest) = match self.client
                .get_trail_status()
                .name(&trail_name)
                .send()
                .await
            {
                Ok(status) => {
                    let logging = status.is_logging().unwrap_or(false).to_string();
                    let delivery = status.latest_delivery_time().map(fmt_dt).unwrap_or_default();
                    let digest = status.latest_digest_delivery_time().map(fmt_dt).unwrap_or_default();
                    (logging, delivery, digest)
                }
                Err(e) => {
                    eprintln!("  WARN: CloudTrail get_trail_status for {trail_name}: {e:#}");
                    (String::new(), String::new(), String::new())
                }
            };

            rows.push(vec![
                trail_name,
                s3_bucket,
                log_validation,
                is_logging,
                latest_delivery,
                latest_digest,
            ]);
        }

        Ok(rows)
    }
}

// ══════════════════════════════════════════════════════════════════════════════
// 3. S3 Policy Collector
// ══════════════════════════════════════════════════════════════════════════════

pub struct CloudTrailS3PolicyCollector {
    ct_client: CtClient,
    s3_client: S3Client,
}

impl CloudTrailS3PolicyCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self {
            ct_client: CtClient::new(config),
            s3_client: S3Client::new(config),
        }
    }
}

#[async_trait]
impl CsvCollector for CloudTrailS3PolicyCollector {
    fn name(&self) -> &str { "CloudTrail S3 Bucket Policies" }
    fn filename_prefix(&self) -> &str { "CloudTrail_S3Policy" }
    fn headers(&self) -> &'static [&'static str] {
        &["Trail Name", "S3 Bucket", "Public Access Block", "Encryption Type", "Access Logging Enabled", "Policy Has Public Allow"]
    }

    async fn collect_rows(&self, _account_id: &str, _region: &str, _dates: Option<(i64, i64)>) -> Result<Vec<Vec<String>>> {
        let mut rows = Vec::new();
        let mut seen_buckets: std::collections::HashSet<String> = std::collections::HashSet::new();

        let trails_resp = self.ct_client
            .describe_trails()
            .include_shadow_trails(false)
            .send()
            .await
            .context("CloudTrail describe_trails")?;

        for trail in trails_resp.trail_list() {
            let trail_name = trail.name().unwrap_or("").to_string();
            let bucket = match trail.s3_bucket_name() {
                Some(b) => b.to_string(),
                None => continue,
            };

            if !seen_buckets.insert(bucket.clone()) {
                continue; // deduplicate
            }

            // Public access block
            let public_access = match self.s3_client
                .get_public_access_block()
                .bucket(&bucket)
                .send()
                .await
            {
                Ok(resp) => {
                    let cfg = resp.public_access_block_configuration();
                    let all_blocked = cfg.map(|c| {
                        c.block_public_acls().unwrap_or(false)
                            && c.ignore_public_acls().unwrap_or(false)
                            && c.block_public_policy().unwrap_or(false)
                            && c.restrict_public_buckets().unwrap_or(false)
                    }).unwrap_or(false);
                    let some_blocked = cfg.map(|c| {
                        c.block_public_acls().unwrap_or(false)
                            || c.ignore_public_acls().unwrap_or(false)
                            || c.block_public_policy().unwrap_or(false)
                            || c.restrict_public_buckets().unwrap_or(false)
                    }).unwrap_or(false);
                    if all_blocked { "All Blocked" } else if some_blocked { "Partial" } else { "None" }.to_string()
                }
                Err(_) => "Not Configured".to_string(),
            };

            // Encryption
            let encryption = match self.s3_client
                .get_bucket_encryption()
                .bucket(&bucket)
                .send()
                .await
            {
                Ok(resp) => {
                    resp.server_side_encryption_configuration()
                        .and_then(|c| c.rules().first())
                        .and_then(|r| r.apply_server_side_encryption_by_default())
                        .map(|d| d.sse_algorithm().as_str().to_string())
                        .unwrap_or_else(|| "None".to_string())
                }
                Err(_) => "None".to_string(),
            };

            // Access logging
            let logging_enabled = match self.s3_client
                .get_bucket_logging()
                .bucket(&bucket)
                .send()
                .await
            {
                Ok(resp) => {
                    if resp.logging_enabled().is_some() { "Enabled" } else { "Disabled" }.to_string()
                }
                Err(_) => "Unknown".to_string(),
            };

            // Bucket policy public allow
            let policy_public = match self.s3_client
                .get_bucket_policy()
                .bucket(&bucket)
                .send()
                .await
            {
                Ok(resp) => {
                    let policy = resp.policy().unwrap_or("");
                    if policy.contains("\"Principal\":\"*\"") || policy.contains("\"Principal\":{\"AWS\":\"*\"}") {
                        "Yes"
                    } else {
                        "No"
                    }.to_string()
                }
                Err(_) => "No".to_string(),
            };

            rows.push(vec![
                trail_name,
                bucket,
                public_access,
                encryption,
                logging_enabled,
                policy_public,
            ]);
        }

        Ok(rows)
    }
}

// ══════════════════════════════════════════════════════════════════════════════
// 4. Change Events Collector
// ══════════════════════════════════════════════════════════════════════════════

pub struct CloudTrailChangeEventsCollector {
    client: CtClient,
}

impl CloudTrailChangeEventsCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self { client: CtClient::new(config) }
    }
}

#[async_trait]
impl CsvCollector for CloudTrailChangeEventsCollector {
    fn name(&self) -> &str { "CloudTrail Change Events" }
    fn filename_prefix(&self) -> &str { "CloudTrail_ChangeEvents" }
    fn headers(&self) -> &'static [&'static str] {
        &["Event Name", "Event Source", "Resource Type", "Resource Name", "User Identity", "Timestamp", "Source IP"]
    }

    async fn collect_rows(&self, _account_id: &str, _region: &str, dates: Option<(i64, i64)>) -> Result<Vec<Vec<String>>> {
        use aws_sdk_cloudtrail::types::{LookupAttribute, LookupAttributeKey};

        let mut rows = Vec::new();
        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        let (start_secs, end_secs) = dates.unwrap_or((now_secs - 7 * 24 * 3600, now_secs));
        let start_dt = aws_sdk_cloudtrail::primitives::DateTime::from_secs(start_secs);
        let end_dt   = aws_sdk_cloudtrail::primitives::DateTime::from_secs(end_secs);

        let lookup_attr = LookupAttribute::builder()
            .attribute_key(LookupAttributeKey::ReadOnly)
            .attribute_value("false")
            .build()
            .context("build LookupAttribute")?;

        let mut next_token: Option<String> = None;
        let mut page_count = 0;

        loop {
            if page_count >= 10 { break; }

            let mut req = self.client
                .lookup_events()
                .lookup_attributes(lookup_attr.clone())
                .start_time(start_dt.clone())
                .end_time(end_dt.clone())
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

                let (resource_type, resource_name) = event.resources()
                    .first()
                    .map(|r| (
                        r.resource_type().unwrap_or("").to_string(),
                        r.resource_name().unwrap_or("").to_string(),
                    ))
                    .unwrap_or_default();

                let username = event.username().unwrap_or("").to_string();

                let timestamp = event.event_time().map(fmt_dt).unwrap_or_default();

                // Extract sourceIPAddress from raw CloudTrail JSON
                let source_ip = event.cloud_trail_event()
                    .and_then(|raw| serde_json::from_str::<serde_json::Value>(raw).ok())
                    .and_then(|v| v.get("sourceIPAddress").and_then(|ip| ip.as_str()).map(|s| s.to_string()))
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

            if next_token.is_none() { break; }

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
        Self { client: CtClient::new(config) }
    }
}

#[async_trait]
impl CsvCollector for S3DataEventsCollector {
    fn name(&self) -> &str { "CloudTrail S3 Data Events" }
    fn filename_prefix(&self) -> &str { "CloudTrail_S3DataEvents" }
    fn headers(&self) -> &'static [&'static str] {
        &["Trail Name", "S3 Bucket/Prefix", "Read Events", "Write Events", "Advanced Selector"]
    }

    async fn collect_rows(&self, _account_id: &str, _region: &str, _dates: Option<(i64, i64)>) -> Result<Vec<Vec<String>>> {
        let mut rows = Vec::new();

        let trails_resp = self.client
            .describe_trails()
            .include_shadow_trails(false)
            .send()
            .await
            .context("CloudTrail describe_trails")?;

        for trail in trails_resp.trail_list() {
            let trail_name = trail.name().unwrap_or("").to_string();

            let sel_resp = match self.client
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
                let rw_type = es.read_write_type()
                    .map(|t| t.as_str().to_string())
                    .unwrap_or_else(|| "All".to_string());

                for dr in es.data_resources() {
                    if dr.r#type() == Some("AWS::S3::Object") {
                        for val in dr.values() {
                            let read_events = matches!(rw_type.as_str(), "ReadOnly" | "All").to_string();
                            let write_events = matches!(rw_type.as_str(), "WriteOnly" | "All").to_string();
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
