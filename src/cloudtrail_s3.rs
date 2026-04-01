use std::io::Read;

use anyhow::{Context, Result};
use async_trait::async_trait;
use aws_sdk_s3::Client as S3Client;
use chrono::{DateTime, Datelike, Duration, NaiveDate, Utc};
use flate2::read::GzDecoder;

use crate::evidence::{CollectParams, EvidenceCollector, EvidenceRecord, EvidenceSource};

// ---------------------------------------------------------------------------
// Events we care about.  Add any new event names here.
// ---------------------------------------------------------------------------
const WATCHED_EVENTS: &[(&str, &str)] = &[
    ("rds.amazonaws.com",    "CreateDBClusterSnapshot"),
    ("rds.amazonaws.com",    "CreateDBSnapshot"),
    ("backup.amazonaws.com", "StartBackupJob"),
    ("backup.amazonaws.com", "BackupJobCompleted"),
];

// Maximum concurrent S3 object downloads.
const MAX_CONCURRENT_DOWNLOADS: usize = 10;

// ---------------------------------------------------------------------------
// Config passed in from main
// ---------------------------------------------------------------------------

pub struct CloudTrailS3Config {
    /// S3 bucket that holds the CloudTrail logs.
    pub bucket: String,
    /// Key prefix before "AWSLogs/" (e.g. "management"). Empty string if none.
    pub prefix: String,
    /// Account IDs whose logs to read.  Collector will attempt both the plain
    /// path and the org-trail path (with an org-id layer) automatically.
    pub account_ids: Vec<String>,
    /// Regions to scan.  Defaults to the region passed on the CLI.
    pub regions: Vec<String>,
}

// ---------------------------------------------------------------------------
// Collector
// ---------------------------------------------------------------------------

pub struct CloudTrailS3Collector {
    client: S3Client,
    config: CloudTrailS3Config,
}

impl CloudTrailS3Collector {
    pub fn new(s3_config: &aws_config::SdkConfig, config: CloudTrailS3Config) -> Self {
        Self {
            client: S3Client::new(s3_config),
            config,
        }
    }
}

#[async_trait]
impl EvidenceCollector for CloudTrailS3Collector {
    fn name(&self) -> &str {
        "CloudTrail S3 Logs"
    }

    fn filename_prefix(&self) -> &str {
        "CloudTrail_S3_historical_log_exports"
    }

    async fn collect(&self, params: &CollectParams) -> Result<Vec<EvidenceRecord>> {
        // Enumerate every (account, region, day) prefix for the date range.
        let prefixes = self.build_prefixes(params);
        eprintln!(
            "  Scanning {} day-prefixes across {} account(s) / {} region(s)...",
            prefixes.len() / (self.config.account_ids.len() * self.config.regions.len()),
            self.config.account_ids.len(),
            self.config.regions.len(),
        );

        // Collect all S3 keys from all prefixes.
        let mut all_keys: Vec<String> = Vec::new();
        for prefix in &prefixes {
            match self.list_keys(prefix).await {
                Ok(keys) => all_keys.extend(keys),
                Err(e) => eprintln!("  WARN: could not list {prefix}: {e:#}"),
            }
        }

        eprintln!("  Found {} log file(s) to download.", all_keys.len());
        if all_keys.is_empty() {
            return Ok(vec![]);
        }

        // Download and parse files with bounded concurrency.
        let semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_DOWNLOADS));
        let mut join_set = tokio::task::JoinSet::new();

        for key in all_keys {
            let client = self.client.clone();
            let bucket = self.config.bucket.clone();
            let sem = semaphore.clone();
            let filter = params.filter.clone();
            let include_raw = params.include_raw;

            join_set.spawn(async move {
                let _permit = sem.acquire().await.unwrap();
                download_and_parse(&client, &bucket, &key, filter.as_deref(), include_raw).await
            });
        }

        let mut records = Vec::new();
        while let Some(result) = join_set.join_next().await {
            match result {
                Ok(Ok(mut r)) => records.append(&mut r),
                Ok(Err(e)) => eprintln!("  WARN: failed to parse a log file: {e:#}"),
                Err(e) => eprintln!("  WARN: task panicked: {e}"),
            }
        }

        Ok(records)
    }
}

impl CloudTrailS3Collector {
    /// Build the S3 key prefixes to scan, one per (account, region, day).
    ///
    /// CloudTrail S3 layout (standard trail):
    ///   {prefix}/AWSLogs/{account-id}/CloudTrail/{region}/{yyyy}/{mm}/{dd}/
    ///
    /// Org trail adds an org-id layer which we don't know ahead of time, so
    /// we list `{prefix}/AWSLogs/` and detect the structure dynamically in
    /// `list_keys` by trying both layouts.
    fn build_prefixes(&self, params: &CollectParams) -> Vec<String> {
        let mut prefixes = Vec::new();
        let base = if self.config.prefix.is_empty() {
            "AWSLogs".to_string()
        } else {
            format!("{}/AWSLogs", self.config.prefix.trim_end_matches('/'))
        };

        let mut day = params.start_time.date_naive();
        let end_day = params.end_time.date_naive();

        while day <= end_day {
            for account_id in &self.config.account_ids {
                for region in &self.config.regions {
                    prefixes.push(format!(
                        "{base}/{account_id}/CloudTrail/{region}/{}/{:02}/{:02}/",
                        day.format("%Y"),
                        day.month(),
                        day.day(),
                    ));
                }
            }
            day = day.succ_opt().unwrap_or(end_day);
            if day > end_day {
                break;
            }
        }

        prefixes
    }

    async fn list_keys(&self, prefix: &str) -> Result<Vec<String>> {
        let mut keys = Vec::new();
        let mut continuation: Option<String> = None;

        loop {
            let mut req = self
                .client
                .list_objects_v2()
                .bucket(&self.config.bucket)
                .prefix(prefix);

            if let Some(ref token) = continuation {
                req = req.continuation_token(token);
            }

            let resp = req.send().await
                .with_context(|| format!("s3:ListObjectsV2 on prefix {prefix}"))?;

            for obj in resp.contents() {
                if let Some(key) = obj.key() {
                    if key.ends_with(".json.gz") {
                        keys.push(key.to_string());
                    }
                }
            }

            if resp.is_truncated() == Some(true) {
                continuation = resp.next_continuation_token().map(|s| s.to_string());
            } else {
                break;
            }
        }

        Ok(keys)
    }
}

// ---------------------------------------------------------------------------
// Download + parse a single .json.gz file
// ---------------------------------------------------------------------------

async fn download_and_parse(
    client: &S3Client,
    bucket: &str,
    key: &str,
    filter: Option<&str>,
    include_raw: bool,
) -> Result<Vec<EvidenceRecord>> {
    let resp = client
        .get_object()
        .bucket(bucket)
        .key(key)
        .send()
        .await
        .with_context(|| format!("s3:GetObject {key}"))?;

    let compressed = resp
        .body
        .collect()
        .await
        .context("reading S3 object body")?
        .into_bytes();

    // Decompress gzip in a blocking thread so we don't stall the async runtime.
    let json_bytes = tokio::task::spawn_blocking(move || -> Result<Vec<u8>> {
        let mut decoder = GzDecoder::new(compressed.as_ref());
        let mut out = Vec::new();
        decoder.read_to_end(&mut out).context("gzip decompression")?;
        Ok(out)
    })
    .await
    .context("spawn_blocking panicked")??;

    let root: serde_json::Value =
        serde_json::from_slice(&json_bytes).context("JSON parse of CloudTrail log")?;

    let records_arr = match root.get("Records").and_then(|v| v.as_array()) {
        Some(arr) => arr,
        None => return Ok(vec![]),
    };

    let mut out = Vec::new();

    for record in records_arr {
        let event_source = record.get("eventSource").and_then(|v| v.as_str()).unwrap_or("");
        let event_name   = record.get("eventName").and_then(|v| v.as_str()).unwrap_or("");

        // Only keep events we care about.
        if !WATCHED_EVENTS.iter().any(|(src, name)| *src == event_source && *name == event_name) {
            continue;
        }

        let timestamp = record
            .get("eventTime")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        // Extract fields from various locations in the CloudTrail JSON.
        let job_id = try_str(record, &["responseElements", "backupJobId"])
            .or_else(|| try_str(record, &["responseElements", "dbClusterSnapshotIdentifier"]))
            .or_else(|| try_str(record, &["responseElements", "dbSnapshotIdentifier"]));

        let plan_id = try_str(record, &["requestParameters", "backupPlanId"])
            .or_else(|| try_str(record, &["requestParameters", "dbClusterIdentifier"]))
            .or_else(|| try_str(record, &["requestParameters", "dbInstanceIdentifier"]));

        let resource_arn = try_str(record, &["requestParameters", "resourceArn"])
            .or_else(|| try_str(record, &["responseElements", "dbClusterSnapshotArn"]))
            .or_else(|| try_str(record, &["responseElements", "dbSnapshotArn"]));

        let resource_type = if event_source.contains("rds") {
            Some(if event_name.contains("Cluster") {
                "Aurora Cluster".to_string()
            } else {
                "RDS Instance".to_string()
            })
        } else {
            try_str(record, &["requestParameters", "resourceType"])
        };

        let status = try_str(record, &["responseElements", "status"])
            .or_else(|| try_str(record, &["responseElements", "dbClusterSnapshot", "status"]))
            .or_else(|| try_str(record, &["responseElements", "dbSnapshot", "status"]));

        // Optional filter: check if any key field contains the filter string.
        if let Some(f) = filter {
            let haystack = format!(
                "{} {} {} {}",
                job_id.as_deref().unwrap_or(""),
                plan_id.as_deref().unwrap_or(""),
                resource_arn.as_deref().unwrap_or(""),
                timestamp,
            );
            if !haystack.contains(f) {
                continue;
            }
        }

        let raw = if include_raw { Some(record.clone()) } else { None };

        out.push(EvidenceRecord {
            source: EvidenceSource::CloudTrailS3,
            event_name: event_name.to_string(),
            timestamp,
            job_id,
            plan_id,
            resource_arn,
            resource_type,
            status,
            completion_timestamp: None,
            raw,
        });
    }

    Ok(out)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn try_str(val: &serde_json::Value, path: &[&str]) -> Option<String> {
    let mut current = val;
    for key in path {
        current = current.get(key)?;
    }
    current.as_str().map(|s| s.to_string())
}

/// Return each calendar day between start and end (inclusive).
#[allow(dead_code)]
fn days_in_range(start: DateTime<Utc>, end: DateTime<Utc>) -> Vec<NaiveDate> {
    let mut days = Vec::new();
    let mut current = start.date_naive();
    let end_date = end.date_naive();
    while current <= end_date {
        days.push(current);
        current += Duration::days(1);
    }
    days
}
