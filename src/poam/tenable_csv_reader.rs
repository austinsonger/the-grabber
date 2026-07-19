use std::collections::HashMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use super::csv_reader::select_latest_csv_by_marker;

const TENABLE_VULNS_MARKER: &str = "_Tenable_Vulnerability_Findings-";
const TENABLE_COMPLIANCE_MARKER: &str = "_Tenable_Compliance_Findings-";

#[derive(Debug, Clone)]
pub(super) struct TenableVulnRow {
    pub(super) stable_key: String,
    pub(super) values: HashMap<String, String>,
}

impl TenableVulnRow {
    pub(super) fn get(&self, header: &str) -> String {
        self.values
            .get(&normalize(header))
            .cloned()
            .unwrap_or_default()
    }
}

#[derive(Debug, Clone)]
pub(super) struct TenableComplianceRow {
    pub(super) stable_key: String,
    pub(super) values: HashMap<String, String>,
}

impl TenableComplianceRow {
    pub(super) fn get(&self, header: &str) -> String {
        self.values
            .get(&normalize(header))
            .cloned()
            .unwrap_or_default()
    }
}

pub(super) fn select_latest_tenable_vulns_csv(dir: &Path) -> Result<(String, PathBuf)> {
    select_latest_csv_by_marker(dir, TENABLE_VULNS_MARKER)
        .with_context(|| format!("no Tenable vulnerability CSV found in {}", dir.display()))
}

pub(super) fn select_latest_tenable_compliance_csv(dir: &Path) -> Result<(String, PathBuf)> {
    select_latest_csv_by_marker(dir, TENABLE_COMPLIANCE_MARKER)
        .with_context(|| format!("no Tenable compliance CSV found in {}", dir.display()))
}

pub(super) fn read_tenable_vulns_csv(path: &Path) -> Result<(Vec<TenableVulnRow>, Vec<String>)> {
    let mut reader = csv::ReaderBuilder::new()
        .flexible(true)
        .from_path(path)
        .with_context(|| format!("cannot open CSV {}", path.display()))?;
    let headers = reader.headers().context("cannot read CSV header")?.clone();
    let normalized_headers: Vec<String> = headers.iter().map(normalize).collect();

    let asset_idx = normalized_headers
        .iter()
        .position(|h| h == &normalize("Asset ID"))
        .context("Tenable vulnerability CSV missing required 'Asset ID' column")?;
    let plugin_idx = normalized_headers
        .iter()
        .position(|h| h == &normalize("Plugin ID"))
        .context("Tenable vulnerability CSV missing required 'Plugin ID' column")?;
    let port_idx = normalized_headers
        .iter()
        .position(|h| h == &normalize("Port"));
    let protocol_idx = normalized_headers
        .iter()
        .position(|h| h == &normalize("Protocol"));

    let mut rows = Vec::new();
    let mut warnings = Vec::new();
    for (row_idx, rec) in reader.records().enumerate() {
        let record = rec.with_context(|| format!("CSV parse error at row {}", row_idx + 2))?;
        let asset_id = record.get(asset_idx).unwrap_or("").trim().to_string();
        let plugin_id = record.get(plugin_idx).unwrap_or("").trim().to_string();
        if asset_id.is_empty() || plugin_id.is_empty() {
            warnings.push(format!(
                "Row {} skipped: missing Asset ID or Plugin ID",
                row_idx + 2
            ));
            continue;
        }
        let port = port_idx
            .and_then(|i| record.get(i))
            .unwrap_or("")
            .trim()
            .to_string();
        let protocol = protocol_idx
            .and_then(|i| record.get(i))
            .unwrap_or("")
            .trim()
            .to_string();
        let stable_key = format!("{asset_id}:{plugin_id}:{port}:{protocol}");

        let mut values = HashMap::new();
        for (i, key) in normalized_headers.iter().enumerate() {
            values.insert(key.clone(), record.get(i).unwrap_or("").to_string());
        }
        rows.push(TenableVulnRow { stable_key, values });
    }

    Ok((rows, warnings))
}

pub(super) fn read_tenable_compliance_csv(
    path: &Path,
) -> Result<(Vec<TenableComplianceRow>, Vec<String>)> {
    let mut reader = csv::ReaderBuilder::new()
        .flexible(true)
        .from_path(path)
        .with_context(|| format!("cannot open CSV {}", path.display()))?;
    let headers = reader.headers().context("cannot read CSV header")?.clone();
    let normalized_headers: Vec<String> = headers.iter().map(normalize).collect();

    let asset_idx = normalized_headers
        .iter()
        .position(|h| h == &normalize("Asset ID"))
        .context("Tenable compliance CSV missing required 'Asset ID' column")?;
    let check_idx = normalized_headers
        .iter()
        .position(|h| h == &normalize("Check ID"));

    let mut rows = Vec::new();
    let mut warnings = Vec::new();
    for (row_idx, rec) in reader.records().enumerate() {
        let record = rec.with_context(|| format!("CSV parse error at row {}", row_idx + 2))?;
        let asset_id = record.get(asset_idx).unwrap_or("").trim().to_string();
        if asset_id.is_empty() {
            warnings.push(format!("Row {} skipped: missing Asset ID", row_idx + 2));
            continue;
        }
        let check_id = check_idx
            .and_then(|i| record.get(i))
            .unwrap_or("")
            .trim()
            .to_string();
        let stable_key = if check_id.is_empty() {
            asset_id.clone()
        } else {
            format!("{asset_id}:{check_id}")
        };

        let mut values = HashMap::new();
        for (i, key) in normalized_headers.iter().enumerate() {
            values.insert(key.clone(), record.get(i).unwrap_or("").to_string());
        }
        rows.push(TenableComplianceRow { stable_key, values });
    }

    Ok((rows, warnings))
}

fn normalize(input: &str) -> String {
    input
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_lowercase())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn select_latest_tenable_vulns_csv_picks_newest() {
        let dir = tempdir().expect("tempdir");
        let older = "Corporate_Security_Tenable_Vulnerability_Findings-2026-04-01-100000.csv";
        let newer = "Corporate_Security_Tenable_Vulnerability_Findings-2026-04-02-100000.csv";
        std::fs::write(dir.path().join(older), "Asset ID,Plugin ID\na1,1\n").expect("write");
        std::fs::write(dir.path().join(newer), "Asset ID,Plugin ID\na1,1\n").expect("write");

        let (name, _) = select_latest_tenable_vulns_csv(dir.path()).expect("select");
        assert_eq!(name, newer);
    }

    #[test]
    fn read_tenable_vulns_csv_builds_stable_key_from_asset_plugin_port_protocol() {
        let dir = tempdir().expect("tempdir");
        let path = dir
            .path()
            .join("Corporate_Security_Tenable_Vulnerability_Findings-2026-04-01-100000.csv");
        std::fs::write(
            &path,
            "Asset ID,Hostname,FQDN,IPv4,IPv6,OS,Device Type,Plugin ID,Plugin Name,Family,Synopsis,Description,Solution,CVEs,CPEs,Has Patch,Severity,Severity ID,Risk Factor,CVSS Base Score,CVSS Vector,CVSS3 Base Score,CVSS3 Vector,VPR Score,Port,Protocol,Service,Scan UUID,Scan Started At,Scan Completed At,State,First Found,Last Found,Last Fixed,Source\n\
             asset-1,host1,host1.example.com,10.0.0.1,,Linux,server,19506,SSL Certificate Cannot Be Trusted,General,synopsis text,description text,solution text,CVE-2026-0001,cpe:/a:openssl,YES,High,3,High,7.5,vector,8.1,vector3,7.2,443,tcp,https,scan-uuid,2026-04-01T00:00:00Z,2026-04-01T01:00:00Z,open,2026-03-01T00:00:00Z,2026-04-01T00:00:00Z,,NESSUS\n",
        ).expect("write");

        let (rows, warnings) = read_tenable_vulns_csv(&path).expect("read");
        assert!(warnings.is_empty());
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].stable_key, "asset-1:19506:443:tcp");
        assert_eq!(
            rows[0].values.get("vprscore").map(String::as_str),
            Some("7.2")
        );
    }

    #[test]
    fn read_tenable_compliance_csv_builds_stable_key_from_asset_and_check() {
        let dir = tempdir().expect("tempdir");
        let path = dir
            .path()
            .join("Corporate_Security_Tenable_Compliance_Findings-2026-04-01-100000.csv");
        std::fs::write(
            &path,
            "Asset ID,Asset Hostname,Asset FQDN,Asset IPv4,Check ID,Check Name,Check Info,Status,Expected Value,Actual Value,Policy Name,Audit File,References,First Seen,Last Seen\n\
             asset-2,host2,host2.example.com,10.0.0.2,check-123,Password complexity,info text,FAILED,8 chars,4 chars,CIS Level 1,cis_audit.xml,,2026-03-01T00:00:00Z,2026-04-01T00:00:00Z\n",
        ).expect("write");

        let (rows, warnings) = read_tenable_compliance_csv(&path).expect("read");
        assert!(warnings.is_empty());
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].stable_key, "asset-2:check-123");
        assert_eq!(
            rows[0].values.get("status").map(String::as_str),
            Some("FAILED")
        );
    }
}
