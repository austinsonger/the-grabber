use std::collections::{HashMap, HashSet};
use std::io::{Cursor, Read, Write};
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use calamine::{open_workbook, Reader, Xlsx};
use chrono::{Duration, NaiveDate};
use zip::{write::SimpleFileOptions, ZipArchive, ZipWriter};

const OPEN_SHEET: &str = "Open POA&M Items";
const CLOSED_SHEET: &str = "Closed POA&M Items";
const OPEN_HEADER_ROW: u32 = 5;
const CLOSED_HEADER_ROW: u32 = 2;
const ECR_PREFIX: &str = "Corporate_Security_Inspector2_ECR_Findings-";
const WORKBOOK_PATH: &str = "evidence-output/poam/FedRAMP-POAM.xlsx";

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

#[derive(Debug, Clone)]
struct CsvFinding {
    arn: String,
    values: HashMap<String, String>, // normalized header -> value
}

impl CsvFinding {
    fn get(&self, header: &str) -> String {
        self.values
            .get(&normalize(header))
            .cloned()
            .unwrap_or_default()
    }
}

#[derive(Debug)]
struct WorkbookData {
    open_headers: Vec<String>,
    closed_headers: Vec<String>,
    open_rows: Vec<Vec<String>>,
    closed_rows: Vec<Vec<String>>,
}

#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd)]
struct CsvKey {
    year: u32,
    month: u32,
    day: u32,
    sequence: u64,
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

pub fn resolve_evidence_path(region: &str, year: &str, month_name: &str) -> Result<PathBuf> {
    let month_folder = month_name_to_folder(month_name)
        .with_context(|| format!("unsupported month '{month_name}'"))?;
    Ok(PathBuf::from("evidence-output")
        .join("security")
        .join(region)
        .join(year)
        .join(month_folder))
}

pub fn run_poam(region: &str, year: &str, month_name: &str) -> Result<PoamRunResult> {
    let month_folder = month_name_to_folder(month_name)
        .with_context(|| format!("unsupported month '{month_name}'"))?;
    let evidence_path = resolve_evidence_path(region, year, month_name)?;
    let (selected_csv_name, selected_csv_path) = select_latest_ecr_csv(&evidence_path)
        .with_context(|| format!("no Inspector2 ECR CSV found in {}", evidence_path.display()))?;

    let (csv_findings, mut warnings) = read_ecr_csv(&selected_csv_path)?;
    if csv_findings.is_empty() {
        warnings.push("CSV contained no valid findings with Finding ARN".to_string());
    }

    let workbook_path = PathBuf::from(WORKBOOK_PATH);
    let workbook = read_poam_workbook(&workbook_path)?;
    let reconcile = reconcile_workbook(workbook, csv_findings, &selected_csv_name, &mut warnings);

    write_poam_workbook(&workbook_path, &reconcile.open_rows, &reconcile.closed_rows)?;

    Ok(PoamRunResult {
        region: region.to_string(),
        year: year.to_string(),
        month_name: month_name.to_string(),
        month_folder,
        evidence_path,
        selected_csv: Some(selected_csv_name),
        workbook_path,
        added_open_count: reconcile.added_open_count,
        moved_closed_count: reconcile.moved_closed_count,
        warnings,
    })
}

#[derive(Debug)]
struct ReconcileResult {
    open_rows: Vec<Vec<String>>,
    closed_rows: Vec<Vec<String>>,
    added_open_count: usize,
    moved_closed_count: usize,
}

fn reconcile_workbook(
    workbook: WorkbookData,
    csv_findings: Vec<CsvFinding>,
    selected_csv_name: &str,
    warnings: &mut Vec<String>,
) -> ReconcileResult {
    let open_map = header_index_map(&workbook.open_headers);
    let closed_map = header_index_map(&workbook.closed_headers);
    let open_key_idx = header_idx(
        &open_map,
        &[
            "Weakness Source Identifier",
            "Weakness Source ID",
            "Source Identifier",
        ],
    );
    let closed_key_idx = header_idx(
        &closed_map,
        &[
            "Weakness Source Identifier",
            "Weakness Source ID",
            "Source Identifier",
        ],
    );

    let mut current_by_arn: HashMap<String, CsvFinding> = HashMap::new();
    for finding in csv_findings {
        match current_by_arn.get(&finding.arn) {
            None => {
                current_by_arn.insert(finding.arn.clone(), finding);
            }
            Some(existing) => {
                if is_newer_finding(&finding, existing) {
                    current_by_arn.insert(finding.arn.clone(), finding);
                }
            }
        }
    }

    let current_arns: HashSet<String> = current_by_arn.keys().cloned().collect();
    let mut closed_set: HashSet<String> = HashSet::new();
    if let Some(idx) = closed_key_idx {
        for row in &workbook.closed_rows {
            let key = row.get(idx).cloned().unwrap_or_default().trim().to_string();
            if !key.is_empty() {
                closed_set.insert(key);
            }
        }
    }

    let mut kept_open: Vec<Vec<String>> = Vec::new();
    let mut moved_to_closed: Vec<Vec<String>> = Vec::new();
    if let Some(idx) = open_key_idx {
        for row in workbook.open_rows {
            let key = row.get(idx).cloned().unwrap_or_default().trim().to_string();
            if !key.is_empty() && !current_arns.contains(&key) {
                moved_to_closed.push(row);
            } else {
                kept_open.push(row);
            }
        }
    } else {
        warnings.push("Open POA&M Items missing 'Weakness Source Identifier' column".to_string());
        kept_open = workbook.open_rows;
    }

    let mut open_set: HashSet<String> = HashSet::new();
    if let Some(idx) = open_key_idx {
        for row in &kept_open {
            let key = row.get(idx).cloned().unwrap_or_default().trim().to_string();
            if !key.is_empty() {
                open_set.insert(key);
            }
        }
    }

    let mut added_open_count = 0usize;
    let mut arns: Vec<String> = current_arns.into_iter().collect();
    arns.sort();
    for arn in arns {
        if open_set.contains(&arn) {
            continue;
        }
        if closed_set.contains(&arn) {
            warnings.push(format!(
                "Finding ARN already exists in Closed sheet and reappeared: {arn}; treating as new Open item"
            ));
        }
        if let Some(finding) = current_by_arn.get(&arn) {
            let row =
                build_new_open_row(&workbook.open_headers, finding, selected_csv_name, warnings);
            kept_open.push(row);
            open_set.insert(arn);
            added_open_count += 1;
        }
    }

    let moved_closed_count = moved_to_closed.len();
    let mut closed_rows = workbook.closed_rows;
    for row in moved_to_closed {
        let mapped = map_row_between_sheets(&row, &workbook.open_headers, &workbook.closed_headers);
        closed_rows.push(mapped);
    }

    ReconcileResult {
        open_rows: kept_open,
        closed_rows,
        added_open_count,
        moved_closed_count,
    }
}

fn map_row_between_sheets(
    source_row: &[String],
    source_headers: &[String],
    target_headers: &[String],
) -> Vec<String> {
    let source_map = header_index_map(source_headers);
    let mut out = vec![String::new(); target_headers.len()];
    for (idx, target_header) in target_headers.iter().enumerate() {
        if let Some(source_idx) = source_map.get(&normalize(target_header)).copied() {
            out[idx] = source_row.get(source_idx).cloned().unwrap_or_default();
        }
    }
    out
}

fn build_new_open_row(
    open_headers: &[String],
    finding: &CsvFinding,
    selected_csv_name: &str,
    warnings: &mut Vec<String>,
) -> Vec<String> {
    let map = header_index_map(open_headers);
    let mut row = vec![String::new(); open_headers.len()];

    let title = finding.get("Title");
    let description = finding.get("Description");
    let cve = finding.get("CVE ID");
    let weakness_name = if !cve.is_empty() && !title.contains(&cve) {
        format!("{title} ({cve})")
    } else {
        title.clone()
    };
    if weakness_name.trim().is_empty() {
        warnings.push(format!("Missing Title for finding {}", finding.arn));
    }

    let mut weakness_desc = description;
    let cvss = finding.get("CVSS Base Score");
    let vector = finding.get("CVSS Scoring Vector");
    let refs = finding.get("Reference URLs");
    if !cvss.is_empty() {
        weakness_desc.push_str(&format!("\nCVSS Base Score: {cvss}"));
    }
    if !vector.is_empty() {
        weakness_desc.push_str(&format!("\nCVSS Vector: {vector}"));
    }
    if !refs.is_empty() {
        weakness_desc.push_str(&format!("\nReferences: {refs}"));
    }

    let remediation_plan = compose_remediation_plan(finding);
    let risk = map_risk_rating(&finding.get("Severity"));
    let original_detection = poam_date(&finding.get("First Observed At")).unwrap_or_default();
    let status_date = poam_date(&finding.get("Updated At"))
        .or_else(|| poam_date(&finding.get("Last Observed At")))
        .unwrap_or_default();
    let scheduled_completion = if original_detection.is_empty() {
        String::new()
    } else {
        derive_scheduled_completion(&original_detection, &risk)
    };

    let vendor_dependency = derive_vendor_dependency(
        &finding.get("Fix Available"),
        &finding.get("Remediation Text"),
        &finding.get("Package Remediation"),
    );

    let asset_identifier = {
        let resource_id = finding.get("Resource ID");
        if !resource_id.is_empty() {
            resource_id
        } else {
            let registry = finding.get("Registry");
            let repo = finding.get("Repository Name");
            let tags = finding.get("Image Tags");
            if registry.is_empty() && repo.is_empty() {
                String::new()
            } else if tags.is_empty() {
                format!("{registry}/{repo}")
            } else {
                format!("{registry}/{repo}:{tags}")
            }
        }
    };

    let comments = compose_comments(finding);
    let poam_id = format!("INS2-ECR-{}", last_n_chars(&finding.arn, 8));

    set_first(&mut row, &map, &["POAM ID", "POA&M ID"], poam_id);
    set_first(&mut row, &map, &["Weakness Name"], weakness_name);
    set_first(&mut row, &map, &["Weakness Description"], weakness_desc);
    set_first(
        &mut row,
        &map,
        &["Weakness Detector Source"],
        "AWS Inspector2 - ECR".to_string(),
    );
    set_first(
        &mut row,
        &map,
        &["Weakness Source Identifier"],
        finding.arn.clone(),
    );
    set_first(&mut row, &map, &["Asset Identifier"], asset_identifier);
    set_first(&mut row, &map, &["Remediation Plan"], remediation_plan);
    set_first(
        &mut row,
        &map,
        &["Original Detection Date"],
        original_detection,
    );
    set_first(
        &mut row,
        &map,
        &["Scheduled Completion Date"],
        scheduled_completion,
    );
    set_first(&mut row, &map, &["Status Date"], status_date);
    set_first(&mut row, &map, &["Vendor Dependency"], vendor_dependency);
    set_first(
        &mut row,
        &map,
        &["Vendor Dependent Product Name"],
        finding.get("Package Name"),
    );
    set_first(&mut row, &map, &["Original Risk Rating"], risk);
    set_first(
        &mut row,
        &map,
        &["Supporting Documents"],
        selected_csv_name.to_string(),
    );
    set_first(&mut row, &map, &["Comments"], comments);
    set_first(&mut row, &map, &["CVE"], cve);

    row
}

fn compose_remediation_plan(finding: &CsvFinding) -> String {
    let mut parts: Vec<String> = Vec::new();
    let rem_text = finding.get("Remediation Text");
    let pkg_rem = finding.get("Package Remediation");
    let fixed_in = finding.get("Fixed In Version");
    let rem_url = finding.get("Remediation URL");

    if !rem_text.is_empty() {
        parts.push(rem_text);
    }
    if !pkg_rem.is_empty() {
        parts.push(pkg_rem);
    }
    if !fixed_in.is_empty() {
        parts.push(format!("Fixed In Version: {fixed_in}"));
    }
    if !rem_url.is_empty() {
        parts.push(format!("Reference: {rem_url}"));
    }
    parts.join("; ")
}

fn compose_comments(finding: &CsvFinding) -> String {
    let fields = [
        ("Inspector Score", finding.get("Inspector Score")),
        ("EPSS Score", finding.get("EPSS Score")),
        ("In Use Count", finding.get("In Use Count")),
        ("Affected Image Count", finding.get("Affected Image Count")),
        ("Oldest Push Date", finding.get("Oldest Push Date")),
        ("Newest Push Date", finding.get("Newest Push Date")),
        ("Has Closed Findings", finding.get("Has Closed Findings")),
        ("Status", finding.get("Status")),
    ];
    let mut parts = Vec::new();
    for (label, value) in fields {
        if !value.is_empty() {
            parts.push(format!("{label}: {value}"));
        }
    }
    parts.join("; ")
}

fn derive_vendor_dependency(
    fix_available: &str,
    remediation_text: &str,
    package_remediation: &str,
) -> String {
    let waiting = remediation_text.to_ascii_lowercase().contains("vendor")
        || remediation_text.to_ascii_lowercase().contains("upstream")
        || package_remediation.to_ascii_lowercase().contains("vendor");

    if fix_available.eq_ignore_ascii_case("NO") && waiting {
        "Yes".to_string()
    } else {
        "No".to_string()
    }
}

fn derive_scheduled_completion(original_detection: &str, risk: &str) -> String {
    let parsed = NaiveDate::parse_from_str(original_detection, "%m/%d/%y");
    let Ok(date) = parsed else {
        return String::new();
    };
    let days = match risk.to_ascii_lowercase().as_str() {
        "critical" => 30,
        "high" => 90,
        "moderate" => 180,
        "low" => 365,
        _ => 180,
    };
    (date + Duration::days(days)).format("%m/%d/%y").to_string()
}

fn map_risk_rating(severity: &str) -> String {
    match severity.trim().to_ascii_lowercase().as_str() {
        "critical" => "Critical".to_string(),
        "high" => "High".to_string(),
        "medium" | "moderate" => "Moderate".to_string(),
        "low" => "Low".to_string(),
        "informational" | "info" => "Low".to_string(),
        _ => "Moderate".to_string(),
    }
}

fn poam_date(raw: &str) -> Option<String> {
    if raw.trim().is_empty() {
        return None;
    }
    if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(raw) {
        return Some(dt.date_naive().format("%m/%d/%y").to_string());
    }
    if let Ok(d) = NaiveDate::parse_from_str(raw, "%Y-%m-%d") {
        return Some(d.format("%m/%d/%y").to_string());
    }
    None
}

fn last_n_chars(s: &str, n: usize) -> String {
    let chars: Vec<char> = s.chars().collect();
    let start = chars.len().saturating_sub(n);
    chars[start..].iter().collect()
}

fn set_first(row: &mut [String], map: &HashMap<String, usize>, names: &[&str], value: String) {
    for name in names {
        if let Some(idx) = map.get(&normalize(name)).copied() {
            if idx < row.len() {
                row[idx] = value;
                return;
            }
        }
    }
}

fn header_index_map(headers: &[String]) -> HashMap<String, usize> {
    let mut out = HashMap::new();
    for (i, header) in headers.iter().enumerate() {
        let normalized_full = normalize(header);
        if !normalized_full.is_empty() {
            out.insert(normalized_full, i);
        }
        let normalized_label = normalize_header_label(header);
        if !normalized_label.is_empty() {
            out.insert(normalized_label, i);
        }
    }
    out
}

fn header_idx(map: &HashMap<String, usize>, names: &[&str]) -> Option<usize> {
    for name in names {
        if let Some(idx) = map.get(&normalize(name)).copied() {
            return Some(idx);
        }
    }
    None
}

fn normalize(input: &str) -> String {
    input
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_lowercase())
        .collect()
}

fn normalize_header_label(input: &str) -> String {
    let first_non_empty_line = input
        .lines()
        .map(|line| line.trim())
        .find(|line| !line.is_empty())
        .unwrap_or("")
        .trim_matches('"');
    let candidate = first_non_empty_line
        .split(" (")
        .next()
        .unwrap_or(first_non_empty_line)
        .trim();
    normalize(candidate)
}

fn is_newer_finding(new: &CsvFinding, old: &CsvFinding) -> bool {
    let new_updated = new.get("Updated At");
    let old_updated = old.get("Updated At");
    let new_date = chrono::DateTime::parse_from_rfc3339(&new_updated).ok();
    let old_date = chrono::DateTime::parse_from_rfc3339(&old_updated).ok();
    match (new_date, old_date) {
        (Some(a), Some(b)) => a > b,
        _ => new_updated > old_updated,
    }
}

fn read_ecr_csv(path: &Path) -> Result<(Vec<CsvFinding>, Vec<String>)> {
    let mut reader = csv::ReaderBuilder::new()
        .flexible(true)
        .from_path(path)
        .with_context(|| format!("cannot open CSV {}", path.display()))?;
    let headers = reader.headers().context("cannot read CSV header")?.clone();

    let mut normalized_headers: Vec<String> = Vec::new();
    for h in &headers {
        normalized_headers.push(normalize(h));
    }
    let arn_idx = normalized_headers
        .iter()
        .position(|h| h == &normalize("Finding ARN"))
        .context("CSV missing required 'Finding ARN' column")?;

    let mut findings = Vec::new();
    let mut warnings = Vec::new();
    for (row_idx, rec) in reader.records().enumerate() {
        let record = rec.with_context(|| format!("CSV parse error at row {}", row_idx + 2))?;
        let arn = record.get(arn_idx).unwrap_or("").trim().to_string();
        if arn.is_empty() {
            warnings.push(format!("Row {} skipped: missing Finding ARN", row_idx + 2));
            continue;
        }
        let mut values = HashMap::new();
        for (i, header_key) in normalized_headers.iter().enumerate() {
            values.insert(header_key.clone(), record.get(i).unwrap_or("").to_string());
        }
        findings.push(CsvFinding { arn, values });
    }

    Ok((findings, warnings))
}

pub fn select_latest_ecr_csv(dir: &Path) -> Result<(String, PathBuf)> {
    let mut best: Option<(CsvKey, String, PathBuf)> = None;
    for entry in std::fs::read_dir(dir).with_context(|| format!("cannot read {}", dir.display()))? {
        let entry = entry?;
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let Some(name_os) = path.file_name() else {
            continue;
        };
        let name = name_os.to_string_lossy().to_string();
        let Some(key) = parse_ecr_csv_key(&name) else {
            continue;
        };

        match &best {
            None => {
                best = Some((key, name, path));
            }
            Some((current_key, _, _)) => {
                if key > *current_key {
                    best = Some((key, name, path));
                }
            }
        }
    }

    match best {
        Some((_, name, path)) => Ok((name, path)),
        None => bail!(
            "no files matching '{}YYYY-MM-DD-######.csv' in {}",
            ECR_PREFIX,
            dir.display()
        ),
    }
}

fn parse_ecr_csv_key(filename: &str) -> Option<CsvKey> {
    if !filename.starts_with(ECR_PREFIX) || !filename.ends_with(".csv") {
        return None;
    }
    let stem = filename.strip_suffix(".csv")?;
    let tail = stem.strip_prefix(ECR_PREFIX)?;
    let parts: Vec<&str> = tail.split('-').collect();
    if parts.len() != 4 {
        return None;
    }
    let year = parts[0].parse::<u32>().ok()?;
    let month = parts[1].parse::<u32>().ok()?;
    let day = parts[2].parse::<u32>().ok()?;
    let sequence = parts[3].parse::<u64>().ok()?;
    Some(CsvKey {
        year,
        month,
        day,
        sequence,
    })
}

fn read_poam_workbook(path: &Path) -> Result<WorkbookData> {
    let mut workbook: Xlsx<_> =
        open_workbook(path).with_context(|| format!("cannot open workbook {}", path.display()))?;
    let (open_headers, open_rows) = read_sheet_rows(&mut workbook, OPEN_SHEET, OPEN_HEADER_ROW)?;
    let (closed_headers, closed_rows) =
        read_sheet_rows(&mut workbook, CLOSED_SHEET, CLOSED_HEADER_ROW)?;
    Ok(WorkbookData {
        open_headers,
        closed_headers,
        open_rows,
        closed_rows,
    })
}

fn read_sheet_rows(
    workbook: &mut Xlsx<std::io::BufReader<std::fs::File>>,
    sheet_name: &str,
    header_row_1based: u32,
) -> Result<(Vec<String>, Vec<Vec<String>>)> {
    let range = workbook
        .worksheet_range(sheet_name)
        .with_context(|| format!("worksheet '{sheet_name}' not found"))?;

    let mut header_idx = (header_row_1based as usize).saturating_sub(1);
    let rows: Vec<Vec<String>> = range
        .rows()
        .map(|r| r.iter().map(|c| c.to_string()).collect())
        .collect();
    if rows.is_empty() {
        bail!("worksheet '{sheet_name}' is empty");
    }
    if header_idx >= rows.len() || !looks_like_header(&rows[header_idx]) {
        if let Some(found_idx) = rows.iter().position(|row| looks_like_header(row)) {
            header_idx = found_idx;
        } else if let Some(first_non_empty) = rows
            .iter()
            .position(|row| row.iter().any(|v| !v.trim().is_empty()))
        {
            header_idx = first_non_empty;
        } else {
            bail!("worksheet '{sheet_name}' has no usable header row");
        }
    }

    let headers = rows[header_idx].clone();
    let mut data_rows: Vec<Vec<String>> = Vec::new();
    for row in rows.iter().skip(header_idx + 1) {
        let mut out_row = vec![String::new(); headers.len()];
        let mut non_empty = false;
        for (idx, value) in row.iter().enumerate().take(headers.len()) {
            out_row[idx] = value.trim().to_string();
            if !out_row[idx].is_empty() {
                non_empty = true;
            }
        }
        if sheet_name == OPEN_SHEET && is_open_template_metadata_row(&out_row) {
            continue;
        }
        if non_empty {
            data_rows.push(out_row);
        }
    }
    Ok((headers, data_rows))
}

fn is_open_template_metadata_row(row: &[String]) -> bool {
    if row.len() < 4 {
        return false;
    }

    if row.iter().skip(4).any(|v| !v.trim().is_empty()) {
        return false;
    }

    let a = normalize(row.first().map(String::as_str).unwrap_or(""));
    let b = normalize(row.get(1).map(String::as_str).unwrap_or(""));
    let c = normalize(row.get(2).map(String::as_str).unwrap_or(""));
    let d = normalize(row.get(3).map(String::as_str).unwrap_or(""));

    let metadata_labels = a == "cloudserviceprovider"
        && b == "cloudserviceoffering"
        && c == "impactlevel"
        && d == "poamdate";

    let metadata_instructions = a.starts_with("enterthenameofthecsp")
        && b.starts_with("enterthenameofthecso")
        && c.starts_with("enterthecsosimpactlevel")
        && d.starts_with("enterthedateofthispoamsubmission");

    metadata_labels || metadata_instructions
}

fn looks_like_header(row: &[String]) -> bool {
    let mut keys: HashSet<String> = HashSet::new();
    for value in row {
        let full = normalize(value);
        if !full.is_empty() {
            keys.insert(full);
        }
        let label = normalize_header_label(value);
        if !label.is_empty() {
            keys.insert(label);
        }
    }
    keys.contains(&normalize("Weakness Source Identifier"))
        || keys.contains(&normalize("Weakness Name"))
        || keys.contains(&normalize("POAM ID"))
        || keys.contains(&normalize("POA&M ID"))
}

fn write_poam_workbook(
    path: &Path,
    open_rows: &[Vec<String>],
    closed_rows: &[Vec<String>],
) -> Result<()> {
    let template_bytes =
        std::fs::read(path).with_context(|| format!("cannot read workbook {}", path.display()))?;

    let mut probe = ZipArchive::new(Cursor::new(template_bytes.as_slice()))
        .context("workbook is not a valid ZIP/xlsx archive")?;
    let workbook_xml = zip_entry_to_string(&mut probe, "xl/workbook.xml")?;
    let rels_xml = zip_entry_to_string(&mut probe, "xl/_rels/workbook.xml.rels")?;
    drop(probe);

    let open_rel = sheet_rel_id(&workbook_xml, OPEN_SHEET)
        .with_context(|| format!("sheet '{OPEN_SHEET}' not found"))?;
    let closed_rel = sheet_rel_id(&workbook_xml, CLOSED_SHEET)
        .with_context(|| format!("sheet '{CLOSED_SHEET}' not found"))?;
    let open_sheet_path =
        sheet_target(&rels_xml, &open_rel).context("unable to resolve Open sheet path")?;
    let closed_sheet_path =
        sheet_target(&rels_xml, &closed_rel).context("unable to resolve Closed sheet path")?;

    let mut probe2 = ZipArchive::new(Cursor::new(template_bytes.as_slice()))
        .context("cannot re-open workbook ZIP")?;
    let open_sheet_xml = zip_entry_to_string(&mut probe2, &open_sheet_path)?;
    let closed_sheet_xml = zip_entry_to_string(&mut probe2, &closed_sheet_path)?;
    drop(probe2);

    let open_modified = inject_rows(&open_sheet_xml, OPEN_HEADER_ROW, open_rows);
    let closed_modified = inject_rows(&closed_sheet_xml, CLOSED_HEADER_ROW, closed_rows);

    let mut out_buf: Vec<u8> = Vec::with_capacity(template_bytes.len() + 1024);
    {
        let mut writer = ZipWriter::new(Cursor::new(&mut out_buf));
        let mut source = ZipArchive::new(Cursor::new(template_bytes.as_slice()))
            .context("cannot open source workbook ZIP")?;
        for idx in 0..source.len() {
            let mut entry = source.by_index(idx).context("cannot read ZIP entry")?;
            let name = entry.name().to_string();
            let compression = entry.compression();
            let mut raw = Vec::new();
            entry.read_to_end(&mut raw)?;
            drop(entry);

            let content: &[u8] = if name == open_sheet_path {
                open_modified.as_bytes()
            } else if name == closed_sheet_path {
                closed_modified.as_bytes()
            } else {
                &raw
            };

            let opts = SimpleFileOptions::default().compression_method(compression);
            writer.start_file(&name, opts)?;
            writer.write_all(content)?;
        }
        writer.finish()?;
    }

    std::fs::write(path, out_buf)
        .with_context(|| format!("cannot write workbook {}", path.display()))?;
    Ok(())
}

fn zip_entry_to_string<R: Read + std::io::Seek>(
    archive: &mut ZipArchive<R>,
    path: &str,
) -> Result<String> {
    let mut entry = archive
        .by_name(path)
        .with_context(|| format!("ZIP entry '{path}' not found"))?;
    let mut buf = Vec::new();
    entry.read_to_end(&mut buf)?;
    String::from_utf8(buf).context("ZIP entry is not valid UTF-8")
}

fn sheet_rel_id(workbook_xml: &str, target_sheet: &str) -> Option<String> {
    for chunk in workbook_xml.split('<') {
        if !chunk.starts_with("sheet ") {
            continue;
        }
        let sheet_name = extract_attr(chunk, "name")?;
        if decode_xml_attr(&sheet_name) != target_sheet {
            continue;
        }
        for attr in ["r:id", "relationships:id"] {
            if let Some(id) = extract_attr(chunk, attr) {
                return Some(id);
            }
        }
    }
    None
}

fn sheet_target(rels_xml: &str, rel_id: &str) -> Option<String> {
    for chunk in rels_xml.split('<') {
        if !chunk.starts_with("Relationship ") {
            continue;
        }
        if extract_attr(chunk, "Id").as_deref() != Some(rel_id) {
            continue;
        }
        let target = extract_attr(chunk, "Target")?;
        return Some(if target.starts_with('/') {
            target.trim_start_matches('/').to_string()
        } else {
            format!("xl/{target}")
        });
    }
    None
}

fn extract_attr(chunk: &str, attr: &str) -> Option<String> {
    let needle = format!("{attr}=\"");
    let pos = chunk.find(&needle)?;
    let rest = &chunk[pos + needle.len()..];
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

fn decode_xml_attr(input: &str) -> String {
    input
        .replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
}

fn inject_rows(sheet_xml: &str, header_rows_to_keep: u32, rows: &[Vec<String>]) -> String {
    let open_tag = "<sheetData>";
    let close_tag = "</sheetData>";
    let (start, end) = match (sheet_xml.find(open_tag), sheet_xml.find(close_tag)) {
        (Some(s), Some(e)) => (s, e),
        _ => return sheet_xml.to_string(),
    };
    let before = &sheet_xml[..start + open_tag.len()];
    let after = &sheet_xml[end..];
    let existing = &sheet_xml[start + open_tag.len()..end];

    let kept = extract_rows_up_to(existing, header_rows_to_keep);
    let mut data = String::new();
    let mut written_rows = 0u32;
    for row in rows {
        if row.iter().all(|v| v.trim().is_empty()) {
            continue;
        }
        let excel_row = header_rows_to_keep + 1 + written_rows;
        data.push_str(&build_row_xml(excel_row, row));
        written_rows += 1;
    }
    format!("{before}{kept}{data}{after}")
}

fn extract_rows_up_to(sheet_data: &str, max_row: u32) -> String {
    let mut result = String::new();
    let mut remaining = sheet_data;
    while let Some(row_start) = remaining.find("<row ") {
        let attrs_end_rel = match remaining[row_start..].find('>') {
            Some(p) => p,
            None => break,
        };
        let attrs = &remaining[row_start + 5..row_start + attrs_end_rel];
        let row_num = extract_attr(attrs, "r")
            .and_then(|n| n.parse::<u32>().ok())
            .unwrap_or(0);

        let row_close_rel = match remaining[row_start..].find("</row>") {
            Some(p) => p,
            None => break,
        };
        let row_end = row_start + row_close_rel + 6;
        if row_num > 0 && row_num <= max_row {
            result.push_str(&remaining[row_start..row_end]);
        }
        remaining = &remaining[row_end..];
    }
    result
}

fn build_row_xml(row_num: u32, cells: &[String]) -> String {
    let mut xml = format!("<row r=\"{row_num}\">");
    for (col, value) in cells.iter().enumerate() {
        if value.is_empty() {
            continue;
        }
        let cell_ref = format!("{}{row_num}", col_letter(col));
        let escaped = escape_xml(value);
        xml.push_str(&format!(
            "<c r=\"{cell_ref}\" t=\"inlineStr\"><is><t>{escaped}</t></is></c>"
        ));
    }
    xml.push_str("</row>");
    xml
}

fn col_letter(mut col: usize) -> String {
    let mut bytes = Vec::new();
    loop {
        bytes.push((b'A' + (col % 26) as u8) as char);
        if col < 26 {
            break;
        }
        col = (col / 26) - 1;
    }
    bytes.iter().rev().collect()
}

fn escape_xml(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn month_name_to_folder_maps_expected_values() {
        assert_eq!(month_name_to_folder("April").as_deref(), Some("04-APR"));
        assert_eq!(month_name_to_folder("december").as_deref(), Some("12-DEC"));
        assert!(month_name_to_folder("Smarch").is_none());
    }

    #[test]
    fn parse_ecr_csv_key_parses_expected_pattern() {
        let key =
            parse_ecr_csv_key("Corporate_Security_Inspector2_ECR_Findings-2026-04-08-214017.csv")
                .expect("key");
        assert_eq!(key.year, 2026);
        assert_eq!(key.month, 4);
        assert_eq!(key.day, 8);
        assert_eq!(key.sequence, 214017);
    }

    #[test]
    fn select_latest_ecr_csv_picks_newest_by_date_and_sequence() {
        let dir = tempdir().expect("tempdir");
        let files = [
            "Corporate_Security_Inspector2_ECR_Findings-2026-04-08-214017.csv",
            "Corporate_Security_Inspector2_ECR_Findings-2026-04-08-214116.csv",
            "Corporate_Security_Inspector2_ECR_Findings-2026-03-31-235959.csv",
        ];
        for name in files {
            std::fs::write(dir.path().join(name), "Finding ARN,Title\narn:1,test\n")
                .expect("write");
        }

        let (name, _) = select_latest_ecr_csv(dir.path()).expect("select latest");
        assert_eq!(
            name,
            "Corporate_Security_Inspector2_ECR_Findings-2026-04-08-214116.csv"
        );
    }

    #[test]
    fn reconcile_and_write_workbook_smoke_test_with_local_fixtures() {
        let csv_path = Path::new(
            "evidence-output/security/us-east-1/2026/04-APR/Corporate_Security_Inspector2_ECR_Findings-2026-04-08-214017.csv",
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
            "Corporate_Security_Inspector2_ECR_Findings-2026-04-08-214017.csv",
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
        let verbose = "Weakness Source Identifier\n\n(\n\ninstruction text here\n)";
        let headers = vec![verbose.to_string()];
        let map = header_index_map(&headers);
        let idx = header_idx(&map, &["Weakness Source Identifier"]);
        assert_eq!(idx, Some(0));
    }

    #[test]
    fn looks_like_header_accepts_verbose_open_poam_header_row() {
        let row = vec![
            "POAM ID\n\n(\n\nexplanatory text\n)".to_string(),
            "Weakness Name\n\n(\n\nscanner title\n)".to_string(),
            "Weakness Source Identifier\n\n(\n\nplugin id\n)".to_string(),
        ];
        assert!(looks_like_header(&row));
    }

    #[test]
    fn is_open_template_metadata_row_detects_template_rows() {
        let labels = vec![
            "Cloud Service Provider".to_string(),
            "Cloud Service Offering".to_string(),
            "Impact Level".to_string(),
            "POA&M Date".to_string(),
            "".to_string(),
        ];
        assert!(is_open_template_metadata_row(&labels));

        let instructions = vec![
            "Enter the name of the CSP as it appears in the SSP and on the FedRAMP Marketplace"
                .to_string(),
            "Enter the name of the CSO as it appears in the SSP and on the FedRAMP Marketplace"
                .to_string(),
            "Enter the CSO's impact level (LI-SaaS, Low, Moderate or High)".to_string(),
            "Enter the date of this POA&M submission. At a minimum, the POA&M must be updated monthly."
                .to_string(),
        ];
        assert!(is_open_template_metadata_row(&instructions));

        let real_item = vec![
            "INS2-ECR-12345678".to_string(),
            "".to_string(),
            "CVE-2026-0001".to_string(),
            "Real vulnerability".to_string(),
            "AWS Inspector2 - ECR".to_string(),
            "arn:aws:inspector2:us-east-1:123456789012:finding/abc".to_string(),
        ];
        assert!(!is_open_template_metadata_row(&real_item));
    }
}
