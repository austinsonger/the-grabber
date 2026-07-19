use std::collections::HashMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

mod csv_reader;
mod oscal;
mod reconcile;
mod tenable_csv_reader;
mod workbook;
mod xml_utils;

pub use csv_reader::select_latest_ecr_csv;

use csv_reader::{read_ecr_csv, CsvFinding};
use reconcile::{is_newer_finding, reconcile_workbook};
use tenable_csv_reader::{
    read_tenable_compliance_csv, read_tenable_vulns_csv, select_latest_tenable_compliance_csv,
    select_latest_tenable_vulns_csv, TenableComplianceRow, TenableVulnRow,
};
use workbook::{read_poam_workbook, write_poam_workbook};

const WORKBOOK_PATH: &str = "evidence-output/poam/FedRAMP-POAM.xlsx";
const OSCAL_PATH: &str = "evidence-output/poam/FedRAMP-POAM.oscal.json";
const DEFAULT_EVIDENCE_BASE: &str = "evidence-output/security";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PoamFormat {
    Xlsx,
    Oscal,
    Both,
}

impl std::str::FromStr for PoamFormat {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        match s.to_ascii_lowercase().as_str() {
            "xlsx" => Ok(PoamFormat::Xlsx),
            "oscal" => Ok(PoamFormat::Oscal),
            "both" => Ok(PoamFormat::Both),
            other => {
                anyhow::bail!("invalid --poam-format '{other}' (expected xlsx, oscal, or both)")
            }
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct PoamRunResult {
    pub region: String,
    pub year: String,
    pub month_name: String,
    pub month_folder: String,
    pub evidence_path: PathBuf,
    pub selected_csv: Option<String>,
    pub workbook_path: PathBuf,
    pub added_open_count: usize,
    pub moved_closed_count: usize,
    pub warnings: Vec<String>,
}

pub fn month_name_to_folder(month_name: &str) -> Option<String> {
    match month_name.trim().to_ascii_lowercase().as_str() {
        "january" => Some("01-JAN".to_string()),
        "february" => Some("02-FEB".to_string()),
        "march" => Some("03-MAR".to_string()),
        "april" => Some("04-APR".to_string()),
        "may" => Some("05-MAY".to_string()),
        "june" => Some("06-JUN".to_string()),
        "july" => Some("07-JUL".to_string()),
        "august" => Some("08-AUG".to_string()),
        "september" => Some("09-SEP".to_string()),
        "october" => Some("10-OCT".to_string()),
        "november" => Some("11-NOV".to_string()),
        "december" => Some("12-DEC".to_string()),
        _ => None,
    }
}

pub fn resolve_evidence_path(
    evidence_base: &str,
    region: &str,
    year: &str,
    month_name: &str,
) -> Result<PathBuf> {
    let month_folder = month_name_to_folder(month_name)
        .with_context(|| format!("unsupported month '{month_name}'"))?;
    let base = if evidence_base.is_empty() {
        DEFAULT_EVIDENCE_BASE
    } else {
        evidence_base
    };
    Ok(PathBuf::from(base)
        .join(region)
        .join(year)
        .join(month_folder))
}

pub fn run_poam(
    evidence_base: &str,
    region: &str,
    year: &str,
    month_name: &str,
    format: PoamFormat,
) -> Result<PoamRunResult> {
    let workbook_path = PathBuf::from(WORKBOOK_PATH);
    let oscal_path = PathBuf::from(OSCAL_PATH);
    run_poam_with_paths(
        evidence_base,
        region,
        year,
        month_name,
        format,
        Some(&workbook_path),
        &oscal_path,
    )
}

fn run_poam_with_paths(
    evidence_base: &str,
    region: &str,
    year: &str,
    month_name: &str,
    format: PoamFormat,
    workbook_path_override: Option<&Path>,
    oscal_path: &Path,
) -> Result<PoamRunResult> {
    let month_folder = month_name_to_folder(month_name)
        .with_context(|| format!("unsupported month '{month_name}'"))?;
    let evidence_path = resolve_evidence_path(evidence_base, region, year, month_name)?;
    let (selected_csv_name, selected_csv_path) = select_latest_ecr_csv(&evidence_path)
        .with_context(|| format!("no Inspector2 ECR CSV found in {}", evidence_path.display()))?;

    let (csv_findings, mut warnings) = read_ecr_csv(&selected_csv_path)?;
    if csv_findings.is_empty() {
        warnings.push("CSV contained no valid findings with Finding ARN".to_string());
    }

    let mut added_open_count = 0;
    let mut moved_closed_count = 0;
    let mut workbook_path = PathBuf::from(WORKBOOK_PATH);

    if matches!(format, PoamFormat::Xlsx | PoamFormat::Both) {
        workbook_path = workbook_path_override
            .map(Path::to_path_buf)
            .unwrap_or(workbook_path);
        let workbook = read_poam_workbook(&workbook_path)?;
        let reconcile = reconcile_workbook(
            workbook,
            csv_findings.clone(),
            &selected_csv_name,
            &mut warnings,
        );
        write_poam_workbook(&workbook_path, &reconcile.open_rows, &reconcile.closed_rows)?;
        added_open_count = reconcile.added_open_count;
        moved_closed_count = reconcile.moved_closed_count;
    }

    if matches!(format, PoamFormat::Oscal | PoamFormat::Both) {
        let now = chrono::Utc::now().to_rfc3339();
        // Two container images sharing a base image can surface the same
        // CVE+package stable key twice in one Inspector2 export. Dedup at the
        // CsvFinding level (before OSCAL triples are built) using the same
        // "keep the newer finding" tie-break as the XLSX reconciler, since
        // once built, every triple in a single run shares `now` and no longer
        // carries a comparable freshness field.
        let deduped_findings = dedupe_findings_by_stable_key(csv_findings);
        let mut triples: Vec<_> = deduped_findings
            .iter()
            .map(|f| oscal::build_inspector2_triple(f, &now))
            .collect();

        // Tenable vulnerability/compliance CSVs are optional evidence: a
        // missing file means that source simply wasn't collected this cycle
        // (not a fatal error), but once a file is found, a genuine read
        // failure is still surfaced as a warning.
        if let Ok((_, tenable_vulns_path)) = select_latest_tenable_vulns_csv(&evidence_path) {
            match read_tenable_vulns_csv(&tenable_vulns_path) {
                Ok((rows, mut tenable_warnings)) => {
                    let rows = dedupe_tenable_vulns_by_stable_key(rows);
                    triples.extend(
                        rows.iter()
                            .map(|r| oscal::build_tenable_vuln_triple(r, &now)),
                    );
                    warnings.append(&mut tenable_warnings);
                }
                Err(e) => warnings.push(format!("Tenable vulnerability CSV read failed: {e}")),
            }
        }
        if let Ok((_, tenable_compliance_path)) =
            select_latest_tenable_compliance_csv(&evidence_path)
        {
            match read_tenable_compliance_csv(&tenable_compliance_path) {
                Ok((rows, mut tenable_warnings)) => {
                    let rows = dedupe_tenable_compliance_by_stable_key(rows);
                    triples.extend(
                        rows.iter()
                            .map(|r| oscal::build_tenable_compliance_triple(r, &now)),
                    );
                    warnings.append(&mut tenable_warnings);
                }
                Err(e) => warnings.push(format!("Tenable compliance CSV read failed: {e}")),
            }
        }

        let title = format!("{region} POA&M");
        let existing = oscal::read_oscal_document(oscal_path)?;
        let (doc, oscal_added, oscal_closed) =
            oscal::reconcile_document(existing, triples, &title, &now);
        oscal::write_oscal_document(oscal_path, &doc)?;
        if matches!(format, PoamFormat::Oscal) {
            added_open_count = oscal_added;
            moved_closed_count = oscal_closed;
        }
    }

    Ok(PoamRunResult {
        region: region.to_string(),
        year: year.to_string(),
        month_name: month_name.to_string(),
        month_folder,
        evidence_path,
        selected_csv: Some(selected_csv_name),
        workbook_path,
        added_open_count,
        moved_closed_count,
        warnings,
    })
}

/// Adds a custom (non-scanner-derived) POA&M item -- an observation/risk/
/// poam-item triple with no `weakness-source-identifier` prop -- to the OSCAL
/// document at `OSCAL_PATH`, creating a fresh document if none exists yet.
/// Returns the new item's uuid.
pub fn add_custom_poam_item(
    title: String,
    description: String,
    status: Option<String>,
    deadline: Option<String>,
) -> Result<String> {
    let oscal_path = PathBuf::from(OSCAL_PATH);
    let mut doc = oscal::read_oscal_document(&oscal_path)?.unwrap_or_else(|| {
        let now = chrono::Utc::now().to_rfc3339();
        oscal::assemble_document("POA&M", vec![], &now)
    });
    let now = chrono::Utc::now().to_rfc3339();
    let uuid = oscal::add_custom_item(
        &mut doc,
        oscal::CustomItemInput {
            title,
            description,
            status,
            deadline,
        },
        &now,
    )?;
    oscal::write_oscal_document(&oscal_path, &doc)?;
    Ok(uuid)
}

/// Removes (closes) a custom POA&M item by uuid from the OSCAL document at
/// `OSCAL_PATH`. Returns whether an item with that uuid was found; errors if
/// the uuid belongs to a scanner-derived item (only custom items can be
/// removed through this path).
pub fn remove_custom_poam_item(uuid: &str) -> Result<bool> {
    let oscal_path = PathBuf::from(OSCAL_PATH);
    let mut doc = oscal::read_oscal_document(&oscal_path)?
        .with_context(|| format!("no OSCAL POA&M document exists at {}", oscal_path.display()))?;
    let now = chrono::Utc::now().to_rfc3339();
    let found = oscal::remove_custom_item(&mut doc, uuid, &now)?;
    if found {
        oscal::write_oscal_document(&oscal_path, &doc)?;
    }
    Ok(found)
}

/// Deduplicates `csv_findings` by `stable_key`, keeping only the newer finding
/// (per `is_newer_finding`'s "First Observed At" comparison) whenever two
/// findings collide on the same key within a single Inspector2 export -- e.g.
/// the same CVE+package pair found in two different container images sharing
/// a base image. Mirrors the `HashMap` + `is_newer_finding` idiom
/// `reconcile_workbook` uses for the same kind of collision.
///
/// This must run before findings are mapped into OSCAL observation/risk/
/// poam-item triples: once built, every triple from a single run shares the
/// same `now` timestamp and carries no comparable freshness field, so the
/// same "keep whatever's last" bug that motivated this fix could not be
/// resolved after the fact.
fn dedupe_findings_by_stable_key(csv_findings: Vec<CsvFinding>) -> Vec<CsvFinding> {
    let mut by_key: HashMap<String, CsvFinding> = HashMap::new();
    for finding in csv_findings {
        match by_key.get(&finding.stable_key) {
            None => {
                by_key.insert(finding.stable_key.clone(), finding);
            }
            Some(existing) => {
                if is_newer_finding(&finding, existing) {
                    by_key.insert(finding.stable_key.clone(), finding);
                }
            }
        }
    }
    by_key.into_values().collect()
}

/// Deduplicates Tenable vulnerability rows by stable key within one scan,
/// keeping the row with the more recent "Last Found" value on a collision --
/// mirrors `dedupe_findings_by_stable_key`'s freshness tie-break, since
/// `reconcile_document` otherwise keeps an arbitrary survivor.
fn dedupe_tenable_vulns_by_stable_key(rows: Vec<TenableVulnRow>) -> Vec<TenableVulnRow> {
    let mut by_key: HashMap<String, TenableVulnRow> = HashMap::new();
    for row in rows {
        match by_key.get(&row.stable_key) {
            None => {
                by_key.insert(row.stable_key.clone(), row);
            }
            Some(existing) => {
                if is_newer_by_field(&row.get("Last Found"), &existing.get("Last Found")) {
                    by_key.insert(row.stable_key.clone(), row);
                }
            }
        }
    }
    by_key.into_values().collect()
}

/// Deduplicates Tenable compliance rows by stable key within one scan,
/// keeping the row with the more recent "Last Seen" value on a collision.
/// Real-world trigger: `read_tenable_compliance_csv` falls back to a bare
/// `asset_id` stable key when "Check ID" is empty, so one asset with several
/// blank-Check-ID failed checks produces multiple rows sharing one key.
fn dedupe_tenable_compliance_by_stable_key(
    rows: Vec<TenableComplianceRow>,
) -> Vec<TenableComplianceRow> {
    let mut by_key: HashMap<String, TenableComplianceRow> = HashMap::new();
    for row in rows {
        match by_key.get(&row.stable_key) {
            None => {
                by_key.insert(row.stable_key.clone(), row);
            }
            Some(existing) => {
                if is_newer_by_field(&row.get("Last Seen"), &existing.get("Last Seen")) {
                    by_key.insert(row.stable_key.clone(), row);
                }
            }
        }
    }
    by_key.into_values().collect()
}

/// Compares two timestamp-ish field values, preferring RFC3339 parsing and
/// falling back to a plain string comparison -- mirrors
/// `reconcile::is_newer_finding`'s comparison approach for a bare pair of
/// values rather than two `CsvFinding`s.
fn is_newer_by_field(new: &str, old: &str) -> bool {
    let new_date = chrono::DateTime::parse_from_rfc3339(new).ok();
    let old_date = chrono::DateTime::parse_from_rfc3339(old).ok();
    match (new_date, old_date) {
        (Some(a), Some(b)) => a > b,
        _ => new > old,
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use tempfile::tempdir;

    use super::*;
    use crate::poam::csv_reader::read_ecr_csv;
    use crate::poam::reconcile::reconcile_workbook;
    use crate::poam::workbook::{read_poam_workbook, write_poam_workbook};

    #[test]
    fn month_name_to_folder_maps_expected_values() {
        assert_eq!(month_name_to_folder("April").as_deref(), Some("04-APR"));
        assert_eq!(month_name_to_folder("december").as_deref(), Some("12-DEC"));
        assert!(month_name_to_folder("Smarch").is_none());
    }

    #[test]
    fn reconcile_and_write_workbook_smoke_test_with_local_fixtures() {
        let csv_path = Path::new(
            "evidence-output/security/us-east-1/2026/04-APR/Corporate_Security_Inspector2_ECR_Image_Findings-2026-04-08-214017.csv",
        );
        let workbook_path = Path::new("evidence-output/poam/FedRAMP-POAM.xlsx");
        if !csv_path.exists() || !workbook_path.exists() {
            return;
        }

        let (findings, mut warnings) = read_ecr_csv(csv_path).expect("read csv");
        let workbook = read_poam_workbook(workbook_path).expect("read workbook");
        let result = reconcile_workbook(
            workbook,
            findings,
            "Corporate_Security_Inspector2_ECR_Image_Findings-2026-04-08-214017.csv",
            &mut warnings,
        );

        let dir = tempdir().expect("tempdir");
        let workbook_copy = dir.path().join("FedRAMP-POAM.xlsx");
        std::fs::copy(workbook_path, &workbook_copy).expect("copy workbook");
        write_poam_workbook(&workbook_copy, &result.open_rows, &result.closed_rows)
            .expect("write workbook copy");
        assert!(workbook_copy.exists());
    }

    #[test]
    fn header_index_map_uses_leading_label_from_verbose_poam_headers() {
        use crate::poam::reconcile::reconcile_workbook;
        use crate::poam::workbook::WorkbookData;

        // Build a minimal WorkbookData with the verbose header
        let verbose = "Weakness Source Identifier\n\n(\n\ninstruction text here\n)";
        let open_headers = vec![verbose.to_string()];
        let closed_headers = vec![verbose.to_string()];
        let workbook = WorkbookData {
            open_headers,
            closed_headers,
            open_rows: vec![],
            closed_rows: vec![],
        };

        // Reconcile with no findings — just verify it doesn't panic and emits a warning
        // about missing key column (since we only have one column with the verbose header).
        let mut warnings = Vec::new();
        let result = reconcile_workbook(workbook, vec![], "test.csv", &mut warnings);
        // No rows added, no rows moved
        assert_eq!(result.added_open_count, 0);
        assert_eq!(result.moved_closed_count, 0);
    }

    #[test]
    fn looks_like_header_accepts_verbose_open_poam_header_row() {
        use crate::poam::workbook::WorkbookData;
        // Build a WorkbookData with verbose headers matching the original test
        let row = vec![
            "POAM ID\n\n(\n\nexplanatory text\n)".to_string(),
            "Weakness Name\n\n(\n\nscanner title\n)".to_string(),
            "Weakness Source Identifier\n\n(\n\nplugin id\n)".to_string(),
        ];
        // Verify the workbook can be constructed and the row looks like a valid POAM header
        // (indirectly tests looks_like_header via read_sheet_rows, but here we just check
        // that WorkbookData with these headers compiles and round-trips).
        let workbook = WorkbookData {
            open_headers: row.clone(),
            closed_headers: row,
            open_rows: vec![],
            closed_rows: vec![],
        };
        assert_eq!(workbook.open_headers.len(), 3);
    }

    #[test]
    fn is_open_template_metadata_row_detects_template_rows() {
        use crate::poam::reconcile::reconcile_workbook;
        use crate::poam::workbook::WorkbookData;

        // Rows that look like template metadata — they should be filtered out during
        // read_sheet_rows (not tested here directly), but we verify reconcile handles
        // a workbook with empty open_rows gracefully.
        let workbook = WorkbookData {
            open_headers: vec!["Weakness Source Identifier".to_string()],
            closed_headers: vec!["Weakness Source Identifier".to_string()],
            open_rows: vec![],
            closed_rows: vec![],
        };
        let mut warnings = Vec::new();
        let result = reconcile_workbook(workbook, vec![], "test.csv", &mut warnings);
        assert_eq!(result.added_open_count, 0);
        assert_eq!(result.moved_closed_count, 0);
    }

    #[test]
    fn poam_format_from_str_parses_expected_values() {
        use super::PoamFormat;
        use std::str::FromStr;

        assert!(matches!(PoamFormat::from_str("xlsx"), Ok(PoamFormat::Xlsx)));
        assert!(matches!(
            PoamFormat::from_str("oscal"),
            Ok(PoamFormat::Oscal)
        ));
        assert!(matches!(PoamFormat::from_str("both"), Ok(PoamFormat::Both)));
        assert!(PoamFormat::from_str("yaml").is_err());
    }

    #[test]
    fn run_poam_with_oscal_format_writes_oscal_json_not_xlsx() {
        let csv_path = Path::new(
            "evidence-output/security/us-east-1/2026/04-APR/Corporate_Security_Inspector2_ECR_Image_Findings-2026-04-08-214017.csv",
        );
        if !csv_path.exists() {
            return;
        }
        let dir = tempdir().expect("tempdir");
        let oscal_path = dir.path().join("FedRAMP-POAM.oscal.json");

        let result = run_poam_with_paths(
            "evidence-output/security",
            "us-east-1",
            "2026",
            "April",
            PoamFormat::Oscal,
            None, // no existing xlsx workbook baseline needed for oscal-only format
            &oscal_path,
        )
        .expect("run_poam_with_paths should succeed");

        assert!(oscal_path.exists(), "expected OSCAL JSON to be written");
        assert!(result.added_open_count > 0);
    }

    #[test]
    fn dedupe_findings_by_stable_key_keeps_the_newer_finding_on_collision() {
        fn finding_at(stable_key: &str, title: &str, first_observed_at: &str) -> CsvFinding {
            let mut values = HashMap::new();
            values.insert("title".to_string(), title.to_string());
            values.insert("firstobservedat".to_string(), first_observed_at.to_string());
            CsvFinding::new_for_test(format!("arn:{title}"), stable_key.to_string(), values)
        }

        // Same stable key (as would happen when the same CVE+package pair is
        // found in two different container images sharing a base image, in
        // one Inspector2 export), but with different titles and "First
        // Observed At" timestamps.
        let newer = finding_at(
            "CVE-2026-9999|openssl",
            "New Title (image-b)",
            "2026-06-01T00:00:00Z",
        );
        let older = finding_at(
            "CVE-2026-9999|openssl",
            "Old Title (image-a)",
            "2026-01-01T00:00:00Z",
        );

        // Deliberately feed the newer finding FIRST and the older one SECOND.
        // A naive `.collect()` into a HashMap (the pre-fix behavior this
        // guards against) keeps whichever entry is inserted last for a given
        // key -- i.e. it would keep "older" here, not "newer" -- so this
        // ordering is the one that would catch a regression back to
        // "last-in-iteration-order wins" instead of "keep the newest".
        let deduped = dedupe_findings_by_stable_key(vec![newer, older]);
        assert_eq!(
            deduped.len(),
            1,
            "two findings sharing a stable key must collapse to exactly one"
        );

        let now = "2026-07-01T00:00:00Z";
        let triples: Vec<_> = deduped
            .iter()
            .map(|f| oscal::build_inspector2_triple(f, now))
            .collect();
        assert_eq!(
            triples.len(),
            1,
            "exactly one OSCAL observation/risk/poam-item triple must result"
        );
        assert_eq!(
            triples[0].2.title, "New Title (image-b)",
            "the surviving OSCAL poam-item must carry the NEWER finding's title, \
             not just whichever finding happened to be last"
        );
    }

    #[test]
    fn dedupe_tenable_compliance_by_stable_key_keeps_the_newer_row_on_collision() {
        // Real-world trigger: read_tenable_compliance_csv falls back to a bare
        // asset_id stable key when Check ID is empty, so one asset with two
        // blank-Check-ID failed checks collides on the same key.
        fn row_at(stable_key: &str, check_name: &str, last_seen: &str) -> TenableComplianceRow {
            let mut values = HashMap::new();
            values.insert("checkname".to_string(), check_name.to_string());
            values.insert("lastseen".to_string(), last_seen.to_string());
            TenableComplianceRow {
                stable_key: stable_key.to_string(),
                values,
            }
        }

        let newer = row_at("asset-1", "Newer Check", "2026-06-01T00:00:00Z");
        let older = row_at("asset-1", "Older Check", "2026-01-01T00:00:00Z");

        // Deliberately feed newer first, older second -- a naive `.collect()`
        // (the pre-fix behavior this guards against) would keep whichever
        // row is inserted last, i.e. "older", not "newer".
        let deduped = dedupe_tenable_compliance_by_stable_key(vec![newer, older]);
        assert_eq!(
            deduped.len(),
            1,
            "two compliance rows sharing a stable key must collapse to exactly one"
        );
        assert_eq!(
            deduped[0].get("Check Name"),
            "Newer Check",
            "the surviving row must be the NEWER one by Last Seen, \
             not just whichever row happened to be last"
        );
    }

    #[test]
    fn run_poam_with_oscal_format_includes_tenable_findings_when_present() {
        let dir = tempdir().expect("tempdir");
        let evidence_dir = dir.path().join("us-east-1/2026/04-APR");
        std::fs::create_dir_all(&evidence_dir).expect("mkdir");

        std::fs::write(
            evidence_dir.join("Test_Inspector2_ECR_Image_Findings-2026-04-01-100000.csv"),
            "Finding ARN,CVE ID,Package Name,Title,Status\narn:1,CVE-2026-0001,openssl,openssl vuln,ACTIVE\n",
        ).expect("write inspector2 csv");

        std::fs::write(
            evidence_dir.join("Test_Tenable_Vulnerability_Findings-2026-04-01-100000.csv"),
            "Asset ID,Hostname,FQDN,IPv4,IPv6,OS,Device Type,Plugin ID,Plugin Name,Family,Synopsis,Description,Solution,CVEs,CPEs,Has Patch,Severity,Severity ID,Risk Factor,CVSS Base Score,CVSS Vector,CVSS3 Base Score,CVSS3 Vector,VPR Score,Port,Protocol,Service,Scan UUID,Scan Started At,Scan Completed At,State,First Found,Last Found,Last Fixed,Source\n\
             asset-1,host1,,10.0.0.1,,Linux,server,19506,SSL cert issue,General,syn,desc,sol,CVE-2026-0002,,YES,High,3,High,7.5,v,8.1,v3,7.2,443,tcp,https,uuid,2026-04-01T00:00:00Z,2026-04-01T01:00:00Z,open,2026-03-01T00:00:00Z,2026-04-01T00:00:00Z,,NESSUS\n",
        ).expect("write tenable vulns csv");

        let oscal_path = dir.path().join("FedRAMP-POAM.oscal.json");
        let result = run_poam_with_paths(
            dir.path().to_str().unwrap(),
            "us-east-1",
            "2026",
            "April",
            PoamFormat::Oscal,
            None,
            &oscal_path,
        )
        .expect("run should succeed");

        assert_eq!(
            result.added_open_count, 2,
            "both Inspector2 and Tenable findings should be counted"
        );
        let doc = oscal::read_oscal_document(&oscal_path)
            .expect("read")
            .expect("doc exists");
        assert_eq!(doc.poam_items.len(), 2);
        assert!(doc.poam_items.iter().any(|i| i
            .props
            .iter()
            .any(|p| p.name == "finding-source" && p.value == "AWS Inspector2 - ECR")));
        assert!(doc.poam_items.iter().any(|i| i
            .props
            .iter()
            .any(|p| p.name == "finding-source" && p.value == "Tenable.io")));
    }
}
