use anyhow::Result;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Core traits -- implement one of these to add a new evidence collector
// ---------------------------------------------------------------------------

/// Every evidence collector implements this trait.  To add a new source
/// (e.g. GuardDuty, AWS Config, IAM Access Analyzer) you only need to:
///
/// 1. Create a new module with a struct that holds its AWS client.
/// 2. Implement `EvidenceCollector` for that struct.
/// 3. Register it in `main.rs` alongside the existing collectors.
#[async_trait]
pub trait EvidenceCollector: Send + Sync {
    /// Human-readable name shown in the report and TUI (e.g. "AWS Backup").
    fn name(&self) -> &str;

    /// Prefix used to name the output file.
    /// e.g. "AWS_Backup_Job_History_Exports" → AWS_Backup_Job_History_Exports-2026-04-01-120000.json
    fn filename_prefix(&self) -> &str;

    /// Collect evidence for the given time window.
    async fn collect(&self, params: &CollectParams) -> Result<Vec<EvidenceRecord>>;
}

/// Snapshot collectors that produce structured JSON output (no time window needed).
/// Use for data that contains nested/policy documents where JSON is richer than CSV.
#[async_trait]
pub trait JsonCollector: Send + Sync {
    fn name(&self) -> &str;
    fn filename_prefix(&self) -> &str;
    async fn collect_records(&self, account_id: &str, region: &str) -> Result<Vec<serde_json::Value>>;
}

/// Output envelope written to disk for every JsonCollector.
#[derive(Debug, Serialize)]
pub struct JsonInventoryReport {
    pub collected_at: String,
    pub account_id: String,
    pub region: String,
    pub collector: String,
    pub record_count: usize,
    pub records: Vec<serde_json::Value>,
}

/// Inventory / snapshot collectors that produce CSV output.
/// These capture current resource state (no time window needed).
#[async_trait]
pub trait CsvCollector: Send + Sync {
    /// Human-readable name shown in the TUI.
    fn name(&self) -> &str;
    /// Used to build the output filename prefix (after the account-id).
    /// e.g. "VPCs" → `{account_id}_VPCs_2026-04-01-120000.csv`
    fn filename_prefix(&self) -> &str;
    /// Column headers for the CSV.
    fn headers(&self) -> &'static [&'static str];
    /// Collect rows.  `account_id` and `region` are provided for ARN construction.
    /// `dates` is an optional `(start_secs, end_secs)` Unix-timestamp range.
    /// Collectors that retrieve time-windowed data (findings, events, snapshots
    /// with creation timestamps) MUST filter by this range when provided.
    /// Pure point-in-time snapshot collectors that have no date dimension may
    /// ignore it.
    async fn collect_rows(&self, account_id: &str, region: &str, dates: Option<(i64, i64)>) -> Result<Vec<Vec<String>>>;
}

/// Parameters passed to every collector.
#[derive(Debug, Clone, Default)]
pub struct CollectParams {
    pub start_time: DateTime<Utc>,
    pub end_time: DateTime<Utc>,
    /// Optional filter narrowing results (interpretation is collector-specific).
    pub filter: Option<String>,
    /// Whether to include verbose/raw data in the output.
    pub include_raw: bool,
}

// ---------------------------------------------------------------------------
// Output types
// ---------------------------------------------------------------------------

/// One output file per collector.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceReport {
    pub metadata: ReportMetadata,
    pub collector: String,
    pub record_count: usize,
    pub records: Vec<EvidenceRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportMetadata {
    pub collected_at: String,
    pub region: String,
    pub start_date: String,
    pub end_date: String,
    pub filter: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceRecord {
    pub source: EvidenceSource,
    pub event_name: String,
    pub timestamp: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub job_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub plan_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource_arn: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub completion_timestamp: Option<String>,
    /// Raw event payload (e.g. full CloudTrail JSON).  Populated when
    /// `--include-raw` is passed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceSource {
    CloudTrail,
    BackupApi,
    RdsApi,
    CloudTrailS3,
}
