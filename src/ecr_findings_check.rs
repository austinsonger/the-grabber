//! `--check-ecr-findings`: for every ECR image in the newest inventory, the set
//! of ACTIVE Inspector2 vulnerability IDs must equal the IDs in the newest ECR
//! findings CSV whose `Asset Identifier` lists that asset.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use aws_sdk_inspector2::types::{
    CoverageFilterCriteria, CoverageStringComparison, CoverageStringFilter,
};

use crate::inventory_digests::{latest_file, load_latest};
use crate::providers::aws::inspector_ecr::{active_findings_for_digest, platform_digests};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum CheckResult {
    Ok,
    MissingInCsv,
    ExtraInCsv,
    NoScanData,
}

impl CheckResult {
    pub fn as_str(self) -> &'static str {
        match self {
            CheckResult::Ok => "OK",
            CheckResult::MissingInCsv => "MISSING_IN_CSV",
            CheckResult::ExtraInCsv => "EXTRA_IN_CSV",
            CheckResult::NoScanData => "NO_SCAN_DATA",
        }
    }
}

#[derive(Debug, Clone)]
pub struct AssetCheck {
    pub asset_id: String,
    pub digests: Vec<String>,
    pub scan_status: String,
    pub scan_reason: String,
    pub live: BTreeSet<String>,
    pub csv: BTreeSet<String>,
    pub result: CheckResult,
}

#[derive(Debug)]
pub struct Report {
    pub inventory_path: PathBuf,
    pub findings_path: PathBuf,
    pub assets: Vec<AssetCheck>,
    pub report_path: PathBuf,
}

/// Coverage is (status code, reason) for the scanned digest; `None` = not covered.
pub fn classify(
    live: &BTreeSet<String>,
    csv: &BTreeSet<String>,
    coverage: Option<(&str, &str)>,
) -> CheckResult {
    match coverage {
        Some(("ACTIVE", _)) => {}
        _ => return CheckResult::NoScanData,
    }
    if !live.is_subset(csv) {
        CheckResult::MissingInCsv
    } else if !csv.is_subset(live) {
        CheckResult::ExtraInCsv
    } else {
        CheckResult::Ok
    }
}

/// Vulnerability ID used on both sides: CVE ID, or the title for non-CVE findings.
fn vuln_id(cve: &str, title: &str) -> String {
    if cve.trim().is_empty() {
        title.trim().to_string()
    } else {
        cve.trim().to_string()
    }
}

pub fn csv_ids_by_asset(path: &Path) -> Result<HashMap<String, BTreeSet<String>>> {
    let mut r = csv::ReaderBuilder::new()
        .flexible(true)
        .from_path(path)
        .with_context(|| format!("cannot open {}", path.display()))?;
    let h = r.headers()?.clone();
    let col = |n: &str| {
        h.iter()
            .position(|x| x == n)
            .with_context(|| format!("{} missing '{n}'", path.display()))
    };
    let (cve_i, title_i, asset_i) = (col("CVE ID")?, col("Title")?, col("Asset Identifier")?);
    let mut out: HashMap<String, BTreeSet<String>> = HashMap::new();
    for rec in r.records() {
        let rec = rec?;
        let id = vuln_id(rec.get(cve_i).unwrap_or(""), rec.get(title_i).unwrap_or(""));
        for asset in rec
            .get(asset_i)
            .unwrap_or("")
            .split('\n')
            .map(str::trim)
            .filter(|a| !a.is_empty())
        {
            out.entry(asset.to_string()).or_default().insert(id.clone());
        }
    }
    Ok(out)
}

impl Report {
    pub fn failures(&self) -> usize {
        self.assets
            .iter()
            .filter(|a| a.result != CheckResult::Ok)
            .count()
    }

    pub fn summary_lines(&self) -> Vec<String> {
        let mut counts: BTreeMap<CheckResult, usize> = BTreeMap::new();
        for a in &self.assets {
            *counts.entry(a.result).or_default() += 1;
        }
        let mut lines = vec![
            format!("Inventory: {}", self.inventory_path.display()),
            format!("Findings:  {}", self.findings_path.display()),
            format!(
                "Assets checked: {}   Failures: {}",
                self.assets.len(),
                self.failures()
            ),
        ];
        lines.extend(
            counts
                .into_iter()
                .map(|(r, n)| format!("  {}: {n}", r.as_str())),
        );
        lines.push(format!("Report: {}", self.report_path.display()));
        lines
    }
}

async fn coverage_for(
    insp: &aws_sdk_inspector2::Client,
    resource_id: &str,
) -> Result<Option<(String, String)>> {
    let criteria = CoverageFilterCriteria::builder()
        .resource_id(
            CoverageStringFilter::builder()
                .comparison(CoverageStringComparison::Equals)
                .value(resource_id)
                .build()
                .context("coverage filter")?,
        )
        .build();
    let resp = insp
        .list_coverage()
        .filter_criteria(criteria)
        .send()
        .await
        .with_context(|| format!("inspector2:ListCoverage {resource_id}"))?;
    Ok(resp.covered_resources().first().and_then(|c| {
        c.scan_status().map(|s| {
            (
                s.status_code().as_str().to_string(),
                s.reason().as_str().to_string(),
            )
        })
    }))
}

pub async fn run(
    config: &aws_config::SdkConfig,
    region: &str,
    inventory_dir: &Path,
    evidence_dir: &Path,
) -> Result<Report> {
    let inventory = load_latest(inventory_dir)?;
    let findings_path = latest_file(evidence_dir, "_Inspector2_ECR_Image_Findings-")?;
    let csv_ids = csv_ids_by_asset(&findings_path)?;
    let insp = aws_sdk_inspector2::Client::new(config);
    let ecr = aws_sdk_ecr::Client::new(config);

    let mut assets = Vec::new();
    for image in inventory.images.iter().filter(|i| i.region == region) {
        let digests = platform_digests(&ecr, &image.account, &image.repository, &image.digest)
            .await
            .unwrap_or_else(|_| vec![image.digest.clone()]);
        let mut live = BTreeSet::new();
        let mut worst: Option<(String, String)> = None;
        let mut all_active = true;
        for d in &digests {
            let cov = coverage_for(&insp, &format!("{}/{d}", image.repository_arn)).await?;
            match &cov {
                Some((s, _)) if s == "ACTIVE" => {}
                _ => {
                    all_active = false;
                    worst = cov.clone().or(Some(("NOT_COVERED".into(), String::new())));
                }
            }
            for f in active_findings_for_digest(&insp, &image.account, &image.repository, d).await?
            {
                let cve = f
                    .package_vulnerability_details()
                    .map(|v| v.vulnerability_id())
                    .unwrap_or("");
                live.insert(vuln_id(cve, f.title().unwrap_or("")));
            }
        }
        let (status, reason) = if all_active {
            ("ACTIVE".to_string(), String::new())
        } else {
            worst.unwrap_or_default()
        };
        let csv = csv_ids.get(&image.asset_id).cloned().unwrap_or_default();
        let coverage = if status == "NOT_COVERED" {
            None
        } else {
            Some((status.as_str(), reason.as_str()))
        };
        let result = classify(&live, &csv, coverage);
        assets.push(AssetCheck {
            asset_id: image.asset_id.clone(),
            digests,
            scan_status: status,
            scan_reason: reason,
            live,
            csv,
            result,
        });
    }

    let report_path = findings_path
        .parent()
        .unwrap_or(Path::new("."))
        .join(format!(
            "ECR-Findings-Check-{}.csv",
            chrono::Local::now().format("%Y-%m-%d-%H%M%S")
        ));
    let mut w = csv::Writer::from_path(&report_path)
        .with_context(|| format!("cannot write {}", report_path.display()))?;
    w.write_record([
        "Asset Identifier",
        "Digests",
        "Inspector Scan Status",
        "Inspector Scan Reason",
        "Inspector ACTIVE Count",
        "CSV Count",
        "Missing In CSV",
        "Extra In CSV",
        "Result",
    ])?;
    for a in &assets {
        let missing: Vec<&str> = a.live.difference(&a.csv).map(String::as_str).collect();
        let extra: Vec<&str> = a.csv.difference(&a.live).map(String::as_str).collect();
        w.write_record([
            a.asset_id.clone(),
            a.digests.join("\n"),
            a.scan_status.clone(),
            a.scan_reason.clone(),
            a.live.len().to_string(),
            a.csv.len().to_string(),
            missing.join("\n"),
            extra.join("\n"),
            a.result.as_str().to_string(),
        ])?;
    }
    w.flush()?;
    Ok(Report {
        inventory_path: inventory.path,
        findings_path,
        assets,
        report_path,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set(ids: &[&str]) -> BTreeSet<String> {
        ids.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn classification() {
        assert_eq!(
            classify(
                &set(&["CVE-1"]),
                &set(&["CVE-1"]),
                Some(("ACTIVE", "SUCCESSFUL"))
            ),
            CheckResult::Ok
        );
        assert_eq!(
            classify(&set(&[]), &set(&[]), Some(("ACTIVE", "SUCCESSFUL"))),
            CheckResult::Ok
        );
        assert_eq!(
            classify(
                &set(&["CVE-1", "CVE-2"]),
                &set(&["CVE-1"]),
                Some(("ACTIVE", "SUCCESSFUL"))
            ),
            CheckResult::MissingInCsv
        );
        assert_eq!(
            classify(
                &set(&["CVE-1"]),
                &set(&["CVE-1", "CVE-9"]),
                Some(("ACTIVE", "SUCCESSFUL"))
            ),
            CheckResult::ExtraInCsv
        );
        assert_eq!(
            classify(&set(&[]), &set(&[]), None),
            CheckResult::NoScanData
        );
        assert_eq!(
            classify(
                &set(&[]),
                &set(&[]),
                Some(("INACTIVE", "SCAN_ELIGIBILITY_EXPIRED"))
            ),
            CheckResult::NoScanData
        );
    }

    #[test]
    fn csv_ids_split_asset_identifier_lines() {
        let dir = tempfile::tempdir().expect("tempdir");
        let p = dir.path().join("f.csv");
        let mut w = csv::Writer::from_path(&p).expect("writer");
        w.write_record(["Finding ARN", "Title", "CVE ID", "Asset Identifier"])
            .expect("hdr");
        w.write_record(["arn:1", "t", "CVE-1", "asset-a\nasset-b"])
            .expect("row");
        w.write_record(["arn:2", "Some non-CVE title", "", "asset-b"])
            .expect("row");
        w.flush().expect("flush");
        let m = csv_ids_by_asset(&p).expect("read");
        assert_eq!(m["asset-a"], set(&["CVE-1"]));
        assert_eq!(m["asset-b"], set(&["CVE-1", "Some non-CVE title"]));
    }
}
