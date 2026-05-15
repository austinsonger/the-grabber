use std::collections::{HashMap, HashSet};

use chrono::{Duration, NaiveDate};

use super::csv_reader::CsvFinding;
use super::workbook::WorkbookData;

#[derive(Debug)]
pub(super) struct ReconcileResult {
    pub(super) open_rows: Vec<Vec<String>>,
    pub(super) closed_rows: Vec<Vec<String>>,
    pub(super) added_open_count: usize,
    pub(super) moved_closed_count: usize,
}

pub(super) fn reconcile_workbook(
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

    let mut current_by_key: HashMap<String, CsvFinding> = HashMap::new();
    for finding in csv_findings {
        match current_by_key.get(&finding.stable_key) {
            None => {
                current_by_key.insert(finding.stable_key.clone(), finding);
            }
            Some(existing) => {
                if is_newer_finding(&finding, existing) {
                    current_by_key.insert(finding.stable_key.clone(), finding);
                }
            }
        }
    }

    let current_keys: HashSet<String> = current_by_key.keys().cloned().collect();
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
            if !key.is_empty() && !current_keys.contains(&key) {
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
    let mut keys: Vec<String> = current_keys.into_iter().collect();
    keys.sort();
    for key in keys {
        if open_set.contains(&key) {
            continue;
        }
        if closed_set.contains(&key) {
            warnings.push(format!(
                "Finding key already in Closed sheet and reappeared: {key}; treating as new Open item"
            ));
        }
        if let Some(finding) = current_by_key.get(&key) {
            let row =
                build_new_open_row(&workbook.open_headers, finding, selected_csv_name, warnings);
            kept_open.push(row);
            open_set.insert(key);
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
        warnings.push(format!("Missing Title for finding {}", finding.stable_key));
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
    let status_date = poam_date(&finding.get("First Observed At")).unwrap_or_default();
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

    let asset_identifier = finding.get("Asset Identifier");

    let comments = compose_comments(finding);
    let cve_slug = cve.replace(['/', ':'], "-").to_ascii_uppercase();
    let poam_id = if !cve_slug.is_empty() {
        format!("INS2-ECR-{cve_slug}")
    } else {
        format!("INS2-ECR-{}", last_n_chars(&finding.arn, 8))
    };

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
        finding.stable_key.clone(),
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

    if !rem_text.is_empty() {
        parts.push(rem_text);
    }
    if !pkg_rem.is_empty() {
        parts.push(pkg_rem);
    }
    if !fixed_in.is_empty() {
        parts.push(format!("Fixed In Version: {fixed_in}"));
    }
    parts.join("; ")
}

fn compose_comments(finding: &CsvFinding) -> String {
    let fields = [
        ("Inspector Score", finding.get("Inspector Score")),
        ("EPSS Score", finding.get("EPSS Score")),
        ("CVSS Version", finding.get("CVSS Version")),
        ("Scan Type", finding.get("Scan Type")),
        ("Currently In Use", finding.get("Currently In Use")),
        ("In Use Count", finding.get("In Use Count")),
        ("Days Open", finding.get("Days Open")),
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
    let new_observed = new.get("First Observed At");
    let old_observed = old.get("First Observed At");
    let new_date = chrono::DateTime::parse_from_rfc3339(&new_observed).ok();
    let old_date = chrono::DateTime::parse_from_rfc3339(&old_observed).ok();
    match (new_date, old_date) {
        (Some(a), Some(b)) => a > b,
        _ => new_observed > old_observed,
    }
}
