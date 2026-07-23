use std::path::PathBuf;

use anyhow::{Context, Result};
use chrono::Local;

use crate::fedramp_map::FedRampMapping;

pub const FEDRAMP_HEADERS: [&str; 3] = [
    "FedRAMP Req IDs",
    "FedRAMP Control IDs",
    "Source Evidence File",
];

/// Same as `FEDRAMP_HEADERS` but without the "FedRAMP Control IDs" column,
/// for collectors that opt out of it (e.g. the STIG collector, whose Req
/// IDs already hold the NIST 800-53 controls, so a second column would be a
/// duplicate).
pub const FEDRAMP_HEADERS_NO_CONTROL: [&str; 2] = ["FedRAMP Req IDs", "Source Evidence File"];

/// Preferred writer. Appends three metadata columns to every row and writes
/// a two-line footer identifying the file and its FedRAMP mapping.
pub fn write_csv_bytes_with_manifest(
    headers: &[&str],
    rows: &[Vec<String>],
    mapping: &FedRampMapping,
    source_evidence_file: &str,
) -> Result<Vec<u8>> {
    write_csv_bytes_with_manifest_impl(headers, rows, mapping, source_evidence_file, |_| None, true)
}

/// Like `write_csv_bytes_with_manifest`, but lets each row supply its own
/// FedRAMP mapping — for collectors where every row is a distinct control
/// (e.g. a STIG/compliance-checklist CSV) rather than a uniform snapshot of
/// one resource type. Rows for which `row_mapping` returns `None` fall back
/// to `mapping`. The footer still reports the collector-wide `mapping` — a
/// single summary line can't represent N different per-row values.
///
/// `emit_control_ids` controls whether the "FedRAMP Control IDs" column is
/// written; pass `false` to suppress it for collectors that don't need it.
pub fn write_csv_bytes_with_manifest_per_row(
    headers: &[&str],
    rows: &[Vec<String>],
    mapping: &FedRampMapping,
    source_evidence_file: &str,
    row_mapping: impl Fn(&[String]) -> Option<FedRampMapping>,
    emit_control_ids: bool,
) -> Result<Vec<u8>> {
    write_csv_bytes_with_manifest_impl(
        headers,
        rows,
        mapping,
        source_evidence_file,
        row_mapping,
        emit_control_ids,
    )
}

fn write_csv_bytes_with_manifest_impl(
    headers: &[&str],
    rows: &[Vec<String>],
    mapping: &FedRampMapping,
    source_evidence_file: &str,
    row_mapping: impl Fn(&[String]) -> Option<FedRampMapping>,
    emit_control_ids: bool,
) -> Result<Vec<u8>> {
    let mut writer = csv::Writer::from_writer(Vec::new());

    let mut full_headers: Vec<&str> = headers.to_vec();
    if emit_control_ids {
        full_headers.extend_from_slice(&FEDRAMP_HEADERS);
    } else {
        full_headers.extend_from_slice(&FEDRAMP_HEADERS_NO_CONTROL);
    }
    writer
        .write_record(&full_headers)
        .context("CSV write headers")?;

    let req_joined = mapping.req_ids_joined();
    let control_joined = mapping.control_ids_joined();

    for row in rows {
        let (row_req, row_control) = match row_mapping(row) {
            Some(m) => (m.req_ids_joined(), m.control_ids_joined()),
            None => (req_joined.clone(), control_joined.clone()),
        };
        let mut full_row: Vec<String> = row.clone();
        full_row.push(row_req);
        if emit_control_ids {
            full_row.push(row_control);
        }
        full_row.push(source_evidence_file.to_string());
        writer.write_record(&full_row).context("CSV write row")?;
    }

    // Keep footer rows the same width as data rows so csv::Writer does not reject
    // mixed record lengths.
    let footer_width = full_headers.len();

    let blank_row = vec![String::new(); footer_width];
    writer
        .write_record(&blank_row)
        .context("CSV write blank footer separator")?;

    let mut req_footer = vec![String::new(); footer_width];
    req_footer[0] = "# FedRAMP Req IDs".to_string();
    if footer_width > 1 {
        req_footer[1] = req_joined.clone();
    }
    writer
        .write_record(&req_footer)
        .context("CSV write req_ids footer")?;

    let mut source_footer = vec![String::new(); footer_width];
    source_footer[0] = "# Source Evidence File".to_string();
    if footer_width > 1 {
        source_footer[1] = source_evidence_file.to_string();
    }
    writer
        .write_record(&source_footer)
        .context("CSV write source footer")?;

    writer.flush().context("CSV flush")?;
    writer
        .into_inner()
        .map_err(|e| anyhow::anyhow!("CSV into_inner: {e}"))
}

/// Nested `YYYY/MM-MON` directory suffix used by callers in multi_account and tui_session.
pub fn date_path_suffix() -> PathBuf {
    let now = Local::now();
    let year = now.format("%Y").to_string();
    let month_num = now.format("%m").to_string();
    let month_abbr = match month_num.as_str() {
        "01" => "JAN",
        "02" => "FEB",
        "03" => "MAR",
        "04" => "APR",
        "05" => "MAY",
        "06" => "JUN",
        "07" => "JUL",
        "08" => "AUG",
        "09" => "SEP",
        "10" => "OCT",
        "11" => "NOV",
        "12" => "DEC",
        _ => "UNK",
    };
    PathBuf::from(&year).join(format!("{month_num}-{month_abbr}"))
}

/// Build the canonical basename: `{account_id}_{prefix}-{timestamp}.csv`.
/// `timestamp` MUST be the shared per-run UTC string produced at run entry.
pub fn evidence_basename(account_id: &str, prefix: &str, timestamp: &str, ext: &str) -> String {
    format!("{account_id}_{prefix}-{timestamp}.{ext}")
}

/// Format a path as an OSC 8 hyperlink when stderr is a TTY.
pub fn format_path_with_osc8(path: &std::path::Path) -> String {
    use std::io::IsTerminal;

    let text = path.display().to_string();
    if !std::io::stderr().is_terminal() {
        return text;
    }
    let abs = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
    let url = format!("file://{}", abs.display());
    format!("\x1b]8;;{url}\x07{text}\x1b]8;;\x07")
}

pub fn write_inventory_outputs(
    _output_dir: &PathBuf,
    timestamp: &str,
    inventory_rows: &[Vec<String>],
    skip_inventory_csv: bool,
) -> Result<Vec<String>> {
    let mut written_files = Vec::new();

    if inventory_rows.is_empty() {
        eprintln!("=== Inventory: no rows collected (all asset types empty) ===");
        return Ok(written_files);
    }

    let now_local = Local::now();
    let year = now_local.format("%Y").to_string();
    let month_num = now_local.format("%m").to_string();
    let month_abbr = match month_num.as_str() {
        "01" => "JAN",
        "02" => "FEB",
        "03" => "MAR",
        "04" => "APR",
        "05" => "MAY",
        "06" => "JUN",
        "07" => "JUL",
        "08" => "AUG",
        "09" => "SEP",
        "10" => "OCT",
        "11" => "NOV",
        "12" => "DEC",
        other => {
            eprintln!("=== WARN: unexpected month '{other}', using 'UNK' in path ===");
            "UNK"
        }
    };

    let inventory_dir = PathBuf::from("inventory")
        .join(&year)
        .join(format!("{month_num}-{month_abbr}"));

    if !skip_inventory_csv {
        std::fs::create_dir_all(&inventory_dir).with_context(|| {
            format!(
                "Failed to create inventory directory {}",
                inventory_dir.display()
            )
        })?;
        let basename = format!("AWS_Inventory-{}.csv", timestamp);
        let path = inventory_dir.join(&basename);
        let mapping = crate::fedramp_map::bundled().get("AWS_Inventory");
        let bytes = write_csv_bytes_with_manifest(
            crate::inventory_core::INVENTORY_CSV_HEADERS,
            inventory_rows,
            &mapping,
            &basename,
        )?;
        std::fs::write(&path, bytes)
            .with_context(|| format!("Failed to write {}", path.display()))?;
        eprintln!(
            "=== Inventory CSV: {} ({} rows) ===",
            path.display(),
            inventory_rows.len()
        );
        written_files.push(path.display().to_string());
    }

    let xlsx_filename = now_local
        .format("SSP-Appendix-M-Integrated-Inventory-Workbook-%Y-%m-%d.xlsx")
        .to_string();
    let xlsx_path = inventory_dir.join(&xlsx_filename);
    let template_path = std::path::Path::new("assets/Inventory.xlsx");
    if template_path.exists() {
        crate::inventory_xlsx::write_inventory_xlsx(inventory_rows, template_path, &xlsx_path)?;
        eprintln!(
            "=== Inventory XLSX: {} ({} rows) ===",
            xlsx_path.display(),
            inventory_rows.len()
        );
        written_files.push(xlsx_path.display().to_string());
    } else {
        eprintln!(
            "=== WARN: inventory XLSX skipped — template not found at '{}' ===",
            template_path.display()
        );
    }

    Ok(written_files)
}
