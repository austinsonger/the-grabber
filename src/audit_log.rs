//! Chain-of-custody log and run manifest for every evidence collection.
//!
//! # Chain of Custody  (`CHAIN-OF-CUSTODY-<run_id>.json`)
//! An immutable record written at the end of each collection capturing who ran
//! it, from which machine/IP, with which AWS credentials, and when.  A second
//! file (`CHAIN-OF-CUSTODY.jsonl`) in the same directory is opened in append
//! mode so all runs against an evidence directory accumulate in one NDJSON log.
//!
//! # Run Manifest  (`RUN-MANIFEST-<run_id>.json`)
//! A single index written at the end of collection listing every file produced,
//! the collector that produced it, success/failure/timeout status, record
//! count, file size, and write timestamp.  A summary section totals outcomes
//! across all collectors.

use std::io::Write as _;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use chrono::Utc;
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Collector outcome
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OutcomeStatus {
    /// Collector succeeded and at least one record was written.
    Success,
    /// Collector succeeded but returned zero records (no file written).
    Empty,
    /// Collector returned an error.
    Error,
    /// Collector exceeded the per-collector timeout.
    Timeout,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CollectorOutcome {
    pub collector: String,
    pub status: OutcomeStatus,
    pub record_count: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub filename: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub written_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_message: Option<String>,
}

impl CollectorOutcome {
    pub fn success(collector: &str, count: usize, path: &Path) -> Self {
        let filename = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned());
        let size_bytes = std::fs::metadata(path).map(|m| m.len()).ok();
        Self {
            collector: collector.to_string(),
            status: OutcomeStatus::Success,
            record_count: count,
            filename,
            written_at: Some(Utc::now().to_rfc3339()),
            size_bytes,
            error_message: None,
        }
    }

    pub fn empty(collector: &str) -> Self {
        Self {
            collector: collector.to_string(),
            status: OutcomeStatus::Empty,
            record_count: 0,
            filename: None,
            written_at: None,
            size_bytes: None,
            error_message: None,
        }
    }

    pub fn error(collector: &str, message: String) -> Self {
        Self {
            collector: collector.to_string(),
            status: OutcomeStatus::Error,
            record_count: 0,
            filename: None,
            written_at: None,
            size_bytes: None,
            error_message: Some(message),
        }
    }

    pub fn timeout(collector: &str) -> Self {
        Self {
            collector: collector.to_string(),
            status: OutcomeStatus::Timeout,
            record_count: 0,
            filename: None,
            written_at: None,
            size_bytes: None,
            error_message: Some("timed out".to_string()),
        }
    }
}

// ---------------------------------------------------------------------------
// Run manifest
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, Deserialize)]
pub struct ManifestSummary {
    pub total_collectors: usize,
    pub succeeded: usize,
    pub empty: usize,
    pub failed: usize,
    pub timed_out: usize,
    pub total_files: usize,
    pub total_records: usize,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RunManifest {
    pub run_id: String,
    pub tool: String,
    pub tool_version: String,
    pub generated_at: String,
    pub account_id: String,
    pub region: String,
    pub collection_start: String,
    pub collection_end: String,
    pub collectors: Vec<CollectorOutcome>,
    pub summary: ManifestSummary,
}

impl RunManifest {
    pub fn build(
        run_id: &str,
        account_id: &str,
        region: &str,
        collection_start: &str,
        collection_end: &str,
        outcomes: Vec<CollectorOutcome>,
    ) -> Self {
        let succeeded = outcomes
            .iter()
            .filter(|o| matches!(o.status, OutcomeStatus::Success))
            .count();
        let empty = outcomes
            .iter()
            .filter(|o| matches!(o.status, OutcomeStatus::Empty))
            .count();
        let failed = outcomes
            .iter()
            .filter(|o| matches!(o.status, OutcomeStatus::Error))
            .count();
        let timed_out = outcomes
            .iter()
            .filter(|o| matches!(o.status, OutcomeStatus::Timeout))
            .count();
        let total_files = succeeded; // one file per successful collector
        let total_records = outcomes.iter().map(|o| o.record_count).sum();
        let total_collectors = outcomes.len();

        RunManifest {
            run_id: run_id.to_string(),
            tool: env!("CARGO_PKG_NAME").to_string(),
            tool_version: env!("CARGO_PKG_VERSION").to_string(),
            generated_at: Utc::now().to_rfc3339(),
            account_id: account_id.to_string(),
            region: region.to_string(),
            collection_start: collection_start.to_string(),
            collection_end: collection_end.to_string(),
            summary: ManifestSummary {
                total_collectors,
                succeeded,
                empty,
                failed,
                timed_out,
                total_files,
                total_records,
            },
            collectors: outcomes,
        }
    }
}

/// Write `RUN-MANIFEST-<run_id>.json` to `out_dir`.
/// Returns the path written.
pub fn write_run_manifest(out_dir: &Path, manifest: &RunManifest) -> Result<PathBuf> {
    std::fs::create_dir_all(out_dir)
        .with_context(|| format!("cannot create {}", out_dir.display()))?;
    let filename = format!("RUN-MANIFEST-{}.json", manifest.run_id);
    let path = out_dir.join(&filename);
    let json = serde_json::to_string_pretty(manifest)
        .context("failed to serialise run manifest")?;
    std::fs::write(&path, json.as_bytes())
        .with_context(|| format!("failed to write {}", path.display()))?;
    Ok(path)
}

// ---------------------------------------------------------------------------
// Chain of custody
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, Deserialize)]
pub struct AwsIdentity {
    pub account_id: String,
    pub caller_arn: String,
    pub user_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CustodyEntry {
    pub run_id: String,
    pub tool: String,
    pub tool_version: String,
    /// ISO 8601 timestamp at which collection was initiated.
    pub started_at: String,
    /// ISO 8601 timestamp at which this record was written (end of collection).
    pub completed_at: String,
    /// OS username of the person/process that ran the tool.
    pub operator: String,
    /// Hostname of the machine that ran the tool.
    pub hostname: String,
    /// Best-guess outbound IP address of the machine.
    pub local_ip: String,
    pub aws_identity: AwsIdentity,
    /// AWS named profile used (`"default"` if none was specified).
    pub aws_profile: String,
    /// Primary region targeted by the collection.
    pub aws_region: String,
    /// Evidence collection window.
    pub collection_start: String,
    pub collection_end: String,
    /// Number of collectors that were registered for this run.
    pub collectors_scheduled: usize,
    /// Sanitized argv string (signing key values are redacted).
    pub cli_invocation: String,
}

impl CustodyEntry {
    pub fn new(
        run_id: &str,
        started_at: &str,
        aws_identity: AwsIdentity,
        aws_profile: &str,
        aws_region: &str,
        collection_start: &str,
        collection_end: &str,
        collectors_scheduled: usize,
    ) -> Self {
        CustodyEntry {
            run_id: run_id.to_string(),
            tool: env!("CARGO_PKG_NAME").to_string(),
            tool_version: env!("CARGO_PKG_VERSION").to_string(),
            started_at: started_at.to_string(),
            completed_at: Utc::now().to_rfc3339(),
            operator: get_operator(),
            hostname: get_hostname(),
            local_ip: get_local_ip(),
            aws_identity,
            aws_profile: aws_profile.to_string(),
            aws_region: aws_region.to_string(),
            collection_start: collection_start.to_string(),
            collection_end: collection_end.to_string(),
            collectors_scheduled,
            cli_invocation: sanitized_cli_args(),
        }
    }
}

/// Write `CHAIN-OF-CUSTODY-<run_id>.json` to `out_dir` and append a compact
/// single-line entry to `CHAIN-OF-CUSTODY.jsonl` in the same directory.
///
/// The `.jsonl` file is opened in append mode so every collection run against
/// the same output directory accumulates in one growing audit trail.
///
/// Returns the path of the per-run JSON file.
pub fn write_chain_of_custody(out_dir: &Path, entry: &CustodyEntry) -> Result<PathBuf> {
    std::fs::create_dir_all(out_dir)
        .with_context(|| format!("cannot create {}", out_dir.display()))?;

    // Per-run full JSON.
    let filename = format!("CHAIN-OF-CUSTODY-{}.json", entry.run_id);
    let path = out_dir.join(&filename);
    let pretty = serde_json::to_string_pretty(entry)
        .context("failed to serialise custody entry")?;
    std::fs::write(&path, pretty.as_bytes())
        .with_context(|| format!("failed to write {}", path.display()))?;

    // Append-only JSONL log — never truncated, accumulates across runs.
    let jsonl_path = out_dir.join("CHAIN-OF-CUSTODY.jsonl");
    let compact = serde_json::to_string(entry)
        .context("failed to compact-serialise custody entry")?;
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&jsonl_path)
        .with_context(|| format!("failed to open {}", jsonl_path.display()))?;
    writeln!(f, "{}", compact)
        .with_context(|| format!("failed to append to {}", jsonl_path.display()))?;

    Ok(path)
}

// ---------------------------------------------------------------------------
// Resolve AWS identity via STS
// ---------------------------------------------------------------------------

/// Resolve AWS caller identity via STS.  Returns `None` on error (e.g. no
/// credentials in verify-only or offline modes).
pub async fn resolve_aws_identity(config: &aws_config::SdkConfig) -> Option<AwsIdentity> {
    let sts = aws_sdk_sts::Client::new(config);
    match sts.get_caller_identity().send().await {
        Ok(resp) => Some(AwsIdentity {
            account_id: resp.account().unwrap_or("unknown").to_string(),
            caller_arn: resp.arn().unwrap_or("unknown").to_string(),
            user_id: resp.user_id().unwrap_or("unknown").to_string(),
        }),
        Err(_) => None,
    }
}

// ---------------------------------------------------------------------------
// System info helpers
// ---------------------------------------------------------------------------

fn get_operator() -> String {
    std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .unwrap_or_else(|_| "unknown".to_string())
}

fn get_hostname() -> String {
    #[cfg(unix)]
    {
        let mut buf = vec![0u8; 256];
        let ret = unsafe {
            libc::gethostname(buf.as_mut_ptr() as *mut libc::c_char, buf.len())
        };
        if ret == 0 {
            let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
            return String::from_utf8_lossy(&buf[..end]).into_owned();
        }
    }
    std::env::var("COMPUTERNAME").unwrap_or_else(|_| "unknown".to_string())
}

/// Return the machine's best-guess outbound IP address by connecting a UDP
/// socket to a public address (no packets are actually sent).
fn get_local_ip() -> String {
    use std::net::UdpSocket;
    UdpSocket::bind("0.0.0.0:0")
        .and_then(|s| {
            s.connect("8.8.8.8:80")?;
            s.local_addr()
        })
        .map(|a| a.ip().to_string())
        .unwrap_or_else(|_| "unknown".to_string())
}

/// Collect `std::env::args()` into a single string, redacting any value that
/// looks like a 64-character hex signing key.
fn sanitized_cli_args() -> String {
    let mut args = std::env::args().peekable();
    let mut out: Vec<String> = Vec::new();
    let mut redact_next = false;
    while let Some(arg) = args.next() {
        if redact_next {
            out.push("<redacted>".to_string());
            redact_next = false;
            continue;
        }
        // --signing-key <value>  or  --signing-key=<value>
        if arg == "--signing-key" {
            out.push(arg);
            redact_next = true;
            continue;
        }
        if arg.starts_with("--signing-key=") {
            out.push("--signing-key=<redacted>".to_string());
            continue;
        }
        // Bare 64-hex string (key passed positionally or accidentally).
        if arg.len() == 64 && arg.chars().all(|c| c.is_ascii_hexdigit()) {
            out.push("<redacted>".to_string());
            continue;
        }
        out.push(arg);
    }
    out.join(" ")
}
