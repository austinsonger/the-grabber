use std::path::PathBuf;

use anyhow::{Context, Result};
use chrono::Local;

use crate::fedramp_map::FedRampMapping;

pub const FEDRAMP_HEADERS: [&str; 3] = [
    "FedRAMP Req IDs",
    "FedRAMP Control IDs",
    "Source Evidence File",
];

/// Preferred writer. Appends three metadata columns to every row and writes
/// a two-line footer identifying the file and its FedRAMP mapping.
pub fn write_csv_bytes_with_manifest(
    headers: &[&str],
    rows: &[Vec<String>],
    mapping: &FedRampMapping,
    source_evidence_file: &str,
) -> Result<Vec<u8>> {
    let mut writer = csv::Writer::from_writer(Vec::new());

    let mut full_headers: Vec<&str> = headers.to_vec();
    full_headers.extend_from_slice(&FEDRAMP_HEADERS);
    writer
        .write_record(&full_headers)
        .context("CSV write headers")?;

    let req_joined = mapping.req_ids_joined();
    let control_joined = mapping.control_ids_joined();

    for row in rows {
        let mut full_row: Vec<String> = row.clone();
        full_row.push(req_joined.clone());
        full_row.push(control_joined.clone());
        full_row.push(source_evidence_file.to_string());
        writer.write_record(&full_row).context("CSV write row")?;
    }

    // Blank separator + two footer rows.
    writer
        .write_record::<[&str; 0], &str>([])
        .context("CSV write blank footer separator")?;
    writer
        .write_record(["# FedRAMP Req IDs", &req_joined])
        .context("CSV write req_ids footer")?;
    writer
        .write_record(["# Source Evidence File", source_evidence_file])
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

/// `YYYY-MM-DD-HHMMSS` timestamp for evidence filenames.
pub fn evidence_timestamp() -> String {
    Local::now().format("%Y-%m-%d-%H%M%S").to_string()
}

/// Build the canonical basename: `{account_id}_{prefix}-{timestamp}.csv`.
pub fn evidence_basename(account_id: &str, prefix: &str, ext: &str) -> String {
    format!("{account_id}_{prefix}-{}.{ext}", evidence_timestamp())
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
        .format("%Y-%m-%d_Inventory_%H-%M-%S.xlsx")
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
