//! Append-only audit trail for STIG remediation actions.
//!
//! Mirrors the append-only-JSONL pattern in `audit_log.rs`
//! (`CHAIN-OF-CUSTODY.jsonl`) but is Okta/STIG-specific rather than tied to
//! AWS identity resolution: `Okta_STIG_Remediation_Log.jsonl` accumulates
//! one line per remediation attempt (applied, manually acknowledged, or
//! failed), across every session run against the same evidence directory.

use std::io::Write as _;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use chrono::Utc;
use serde::Serialize;

use crate::audit_log::{get_hostname, get_operator};

#[derive(Debug, Serialize)]
#[allow(dead_code)]
pub struct RemediationLogEntry {
    pub timestamp: String,
    pub operator: String,
    pub hostname: String,
    pub okta_tenant: String,
    pub v_id: String,
    pub title: String,
    pub description: String,
    pub result: String,
    pub detail: String,
}

impl RemediationLogEntry {
    #[allow(dead_code)]
    pub fn new(
        okta_tenant: &str,
        v_id: &str,
        title: &str,
        description: &str,
        result: &str,
        detail: &str,
    ) -> Self {
        Self {
            timestamp: Utc::now().to_rfc3339(),
            operator: get_operator(),
            hostname: get_hostname(),
            okta_tenant: okta_tenant.to_string(),
            v_id: v_id.to_string(),
            title: title.to_string(),
            description: description.to_string(),
            result: result.to_string(),
            detail: detail.to_string(),
        }
    }
}

/// Append one entry to `Okta_STIG_Remediation_Log.jsonl` under `out_dir`.
/// Never truncated — accumulates across every remediation session against
/// this evidence directory.
#[allow(dead_code)]
pub fn append_remediation_log(out_dir: &Path, entry: &RemediationLogEntry) -> Result<PathBuf> {
    std::fs::create_dir_all(out_dir)
        .with_context(|| format!("cannot create {}", out_dir.display()))?;
    let path = out_dir.join("Okta_STIG_Remediation_Log.jsonl");
    let compact =
        serde_json::to_string(entry).context("failed to serialise remediation log entry")?;
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .with_context(|| format!("failed to open {}", path.display()))?;
    writeln!(f, "{compact}").with_context(|| format!("failed to append to {}", path.display()))?;
    Ok(path)
}
