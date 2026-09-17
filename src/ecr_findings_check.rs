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
use crate::providers::aws::inspector_ecr::{
    active_findings_for_digest, platform_digests, InspectorEcrImagesCollector,
};

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
    pub skipped_other_region: usize,
    pub not_visible: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Visibility {
    Visible,
    NotVisible,
}

/// An image with no Inspector2 coverage that belongs to another account is not
/// visible from the caller; same-account images always count (NO_SCAN_DATA).
pub fn visibility(coverage_found: bool, image_account: &str, caller_account: &str) -> Visibility {
    if !coverage_found && image_account != caller_account {
        Visibility::NotVisible
    } else {
        Visibility::Visible
    }
}

#[derive(Debug)]
pub struct CollectReport {
    pub findings_path: PathBuf,
    pub findings_rows: usize,
    pub check: Report,
}

impl CollectReport {
    pub fn summary_lines(&self) -> Vec<String> {
        let mut lines = vec![format!(
            "Findings written: {} ({} rows)",
            self.findings_path.display(),
            self.findings_rows
        )];
        lines.extend(self.check.summary_lines());
        lines
    }
}

/// Collect the ECR image findings CSV for the newest inventory into `out_dir`
/// (same name and format as a Collectors run), then verify it.
pub async fn collect_and_check(
    config: &aws_config::SdkConfig,
    account_name: &str,
    region: &str,
    inventory_dir: &Path,
    out_dir: &Path,
) -> Result<CollectReport> {
    use crate::evidence::CsvCollector;
    use crate::runner::output::{evidence_basename, write_csv_bytes_with_manifest_per_row};

    let identity = crate::audit_log::resolve_aws_identity(config)
        .await
        .with_context(|| format!("cannot resolve AWS account ID for {account_name}"))?;
    let collector = InspectorEcrImagesCollector::new(config);
    let rows = collector
        .collect_rows(&identity.account_id, region, None)
        .await
        .with_context(|| format!("collecting ECR findings for {account_name}"))?;
    std::fs::create_dir_all(out_dir)
        .with_context(|| format!("cannot create {}", out_dir.display()))?;
    // Same writer and basename as run_tui_csv_collector (Collectors run).
    let timestamp = chrono::Utc::now().format("%Y-%m-%d-%H%M%S").to_string();
    let basename = evidence_basename(
        &identity.account_id,
        collector.filename_prefix(),
        &timestamp,
        "csv",
    );
    let bytes = write_csv_bytes_with_manifest_per_row(
        collector.headers(),
        &rows,
        &collector.fedramp_mapping(),
        &basename,
        |row| collector.fedramp_mapping_for_row(row),
        collector.emit_fedramp_control_ids_column(),
    )?;
    let findings_path = out_dir.join(&basename);
    std::fs::write(&findings_path, bytes)
        .with_context(|| format!("cannot write {}", findings_path.display()))?;
    let check = match run_with_findings(config, region, inventory_dir, &findings_path).await {
        Ok(c) => c,
        Err(e) => {
            // Don't leave an empty CSV that newest-file lookups would pick up.
            if rows.is_empty() && format!("{e:#}").contains("no inventory ECR images visible") {
                std::fs::remove_file(&findings_path)
                    .with_context(|| format!("cannot remove empty {}", findings_path.display()))?;
            }
            return Err(e);
        }
    };
    Ok(CollectReport {
        findings_path,
        findings_rows: rows.len(),
        check,
    })
}

/// Coverage is (status code, reason) for the scanned digest; `None` = not covered.
/// `index_expanded` is false when the image index couldn't be read into its
/// per-platform digests, so the live findings can't be trusted either way.
pub fn classify(
    live: &BTreeSet<String>,
    csv: &BTreeSet<String>,
    coverage: Option<(&str, &str)>,
    index_expanded: bool,
) -> CheckResult {
    if !index_expanded {
        return CheckResult::NoScanData;
    }
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
            .split(|c| c == ';' || c == '\n')
            .map(str::trim)
            .filter(|a| !a.is_empty())
        {
            out.entry(asset.to_string()).or_default().insert(id.clone());
        }
    }
    Ok(out)
}

/// Non-empty `Inventory File` values in a findings CSV, or empty when the
/// column doesn't exist (older findings files predate that annotation).
pub fn inventory_files_in_csv(path: &Path) -> Result<BTreeSet<String>> {
    let mut r = csv::ReaderBuilder::new()
        .flexible(true)
        .from_path(path)
        .with_context(|| format!("cannot open {}", path.display()))?;
    let h = r.headers()?.clone();
    let Some(col) = h.iter().position(|x| x == "Inventory File") else {
        return Ok(BTreeSet::new());
    };
    let mut out = BTreeSet::new();
    for rec in r.records() {
        let rec = rec?;
        if let Some(v) = rec.get(col) {
            let v = v.trim();
            if !v.is_empty() {
                out.insert(v.to_string());
            }
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
            format!("Skipped (other regions): {}", self.skipped_other_region),
            format!("Not visible from this account: {}", self.not_visible),
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
    let findings_path = latest_file(evidence_dir, "_Inspector2_ECR_Image_Findings-")?;
    run_with_findings(config, region, inventory_dir, &findings_path).await
}

pub async fn run_with_findings(
    config: &aws_config::SdkConfig,
    region: &str,
    inventory_dir: &Path,
    findings_path: &Path,
) -> Result<Report> {
    let findings_path = findings_path.to_path_buf();
    let inventory = load_latest(inventory_dir)?;
    let caller_account = crate::audit_log::resolve_aws_identity(config)
        .await
        .map(|i| i.account_id)
        .context("cannot resolve the caller AWS account (STS GetCallerIdentity)")?;
    let csv_ids = csv_ids_by_asset(&findings_path)?;

    let inventory_file = inventory
        .path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default();
    let csv_inventory_files = inventory_files_in_csv(&findings_path)?;
    if !csv_inventory_files.is_empty() && !csv_inventory_files.contains(&inventory_file) {
        anyhow::bail!(
            "findings were collected against {}, but the newest inventory is {}; re-run ECR findings collection",
            csv_inventory_files.iter().cloned().collect::<Vec<_>>().join(", "),
            inventory_file
        );
    }

    let insp = aws_sdk_inspector2::Client::new(config);
    let ecr = aws_sdk_ecr::Client::new(config);

    let mut assets = Vec::new();
    let mut skipped_other_region = 0usize;
    let mut not_visible = 0usize;
    for image in &inventory.images {
        if image.region != region {
            skipped_other_region += 1;
            continue;
        }
        let (digests, index_expanded) =
            match platform_digests(&ecr, &image.account, &image.repository, &image.digest).await {
                Ok(d) => (d, true),
                Err(e) => {
                    // An unreadable index in another account: no coverage can be
                    // established from here.
                    if visibility(false, &image.account, &caller_account) == Visibility::NotVisible
                    {
                        not_visible += 1;
                        continue;
                    }
                    // Still query findings on the un-expanded digest, for operator
                    // evidence, but the index couldn't be read so the asset is
                    // NoScanData regardless of what those findings or coverage say.
                    let mut live = BTreeSet::new();
                    for f in active_findings_for_digest(
                        &insp,
                        &image.account,
                        &image.repository,
                        &image.digest,
                    )
                    .await
                    .unwrap_or_default()
                    {
                        let cve = f
                            .package_vulnerability_details()
                            .map(|v| v.vulnerability_id())
                            .unwrap_or("");
                        live.insert(vuln_id(cve, f.title().unwrap_or("")));
                    }
                    let csv = csv_ids.get(&image.asset_id).cloned().unwrap_or_default();
                    let result = classify(&live, &csv, None, false);
                    assets.push(AssetCheck {
                        asset_id: image.asset_id.clone(),
                        digests: vec![image.digest.clone()],
                        scan_status: "INDEX_NOT_EXPANDED".to_string(),
                        scan_reason: format!("{e:#}"),
                        live,
                        csv,
                        result,
                    });
                    continue;
                }
            };
        let mut live = BTreeSet::new();
        let mut worst: Option<(String, String)> = None;
        let mut all_active = true;
        let mut coverage_found = false;
        for d in &digests {
            let cov = coverage_for(&insp, &format!("{}/{d}", image.repository_arn)).await?;
            coverage_found |= cov.is_some();
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
        if visibility(coverage_found, &image.account, &caller_account) == Visibility::NotVisible {
            not_visible += 1;
            continue;
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
        let result = classify(&live, &csv, coverage, index_expanded);
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

    if assets.is_empty() && not_visible > 0 {
        anyhow::bail!("no inventory ECR images visible from account {caller_account} in {region}");
    }
    if assets.is_empty() {
        anyhow::bail!("no inventory ECR images in region {region}; checked nothing");
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
            a.digests.join("; "),
            a.scan_status.clone(),
            a.scan_reason.clone(),
            a.live.len().to_string(),
            a.csv.len().to_string(),
            missing.join("; "),
            extra.join("; "),
            a.result.as_str().to_string(),
        ])?;
    }
    w.flush()?;
    Ok(Report {
        inventory_path: inventory.path,
        findings_path,
        assets,
        report_path,
        skipped_other_region,
        not_visible,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set(ids: &[&str]) -> BTreeSet<String> {
        ids.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn visibility_rules() {
        assert_eq!(visibility(false, "111", "222"), Visibility::NotVisible);
        assert_eq!(visibility(false, "111", "111"), Visibility::Visible);
        assert_eq!(visibility(true, "111", "222"), Visibility::Visible);
        assert_eq!(visibility(true, "111", "111"), Visibility::Visible);
    }

    #[test]
    fn classification() {
        assert_eq!(
            classify(
                &set(&["CVE-1"]),
                &set(&["CVE-1"]),
                Some(("ACTIVE", "SUCCESSFUL")),
                true
            ),
            CheckResult::Ok
        );
        assert_eq!(
            classify(&set(&[]), &set(&[]), Some(("ACTIVE", "SUCCESSFUL")), true),
            CheckResult::Ok
        );
        assert_eq!(
            classify(
                &set(&["CVE-1", "CVE-2"]),
                &set(&["CVE-1"]),
                Some(("ACTIVE", "SUCCESSFUL")),
                true
            ),
            CheckResult::MissingInCsv
        );
        assert_eq!(
            classify(
                &set(&["CVE-1"]),
                &set(&["CVE-1", "CVE-9"]),
                Some(("ACTIVE", "SUCCESSFUL")),
                true
            ),
            CheckResult::ExtraInCsv
        );
        assert_eq!(
            classify(&set(&[]), &set(&[]), None, true),
            CheckResult::NoScanData
        );
        assert_eq!(
            classify(
                &set(&[]),
                &set(&[]),
                Some(("INACTIVE", "SCAN_ELIGIBILITY_EXPIRED")),
                true
            ),
            CheckResult::NoScanData
        );
        // Index not expanded overrides an otherwise-ACTIVE, equal-set result.
        assert_eq!(
            classify(
                &set(&["CVE-1"]),
                &set(&["CVE-1"]),
                Some(("ACTIVE", "SUCCESSFUL")),
                false
            ),
            CheckResult::NoScanData
        );
    }

    #[test]
    fn inventory_files_in_csv_reads_the_column_when_present() {
        let dir = tempfile::tempdir().expect("tempdir");
        let p = dir.path().join("f.csv");
        let mut w = csv::Writer::from_path(&p).expect("writer");
        w.write_record(["Finding ARN", "Asset Identifier", "Inventory File"])
            .expect("hdr");
        w.write_record(["arn:1", "asset-a", "AWS_Inventory-2026-09-16-000000.csv"])
            .expect("row");
        w.write_record(["arn:2", "asset-b", ""]).expect("row");
        w.write_record(["arn:3", "asset-c", "AWS_Inventory-2026-09-15-000000.csv"])
            .expect("row");
        w.flush().expect("flush");
        let files = inventory_files_in_csv(&p).expect("read");
        assert_eq!(
            files,
            set(&[
                "AWS_Inventory-2026-09-16-000000.csv",
                "AWS_Inventory-2026-09-15-000000.csv"
            ])
        );
    }

    #[test]
    fn inventory_files_in_csv_empty_when_column_missing() {
        let dir = tempfile::tempdir().expect("tempdir");
        let p = dir.path().join("f.csv");
        let mut w = csv::Writer::from_path(&p).expect("writer");
        w.write_record(["Finding ARN", "Asset Identifier"])
            .expect("hdr");
        w.write_record(["arn:1", "asset-a"]).expect("row");
        w.flush().expect("flush");
        let files = inventory_files_in_csv(&p).expect("read");
        assert!(files.is_empty());
    }

    #[test]
    fn csv_ids_split_asset_identifier_lines() {
        let dir = tempfile::tempdir().expect("tempdir");
        let p = dir.path().join("f.csv");
        let mut w = csv::Writer::from_path(&p).expect("writer");
        w.write_record(["Finding ARN", "Title", "CVE ID", "Asset Identifier"])
            .expect("hdr");
        w.write_record(["arn:1", "t", "CVE-1", "asset-a; asset-b"])
            .expect("row");
        w.write_record(["arn:2", "Some non-CVE title", "", "asset-b"])
            .expect("row");
        w.flush().expect("flush");
        let m = csv_ids_by_asset(&p).expect("read");
        assert_eq!(m["asset-a"], set(&["CVE-1"]));
        assert_eq!(m["asset-b"], set(&["CVE-1", "Some non-CVE title"]));
    }
}
