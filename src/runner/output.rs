use std::path::PathBuf;

use anyhow::{Context, Result};
use chrono::Local;

pub fn write_csv_bytes(headers: &[&str], rows: &[Vec<String>]) -> Result<Vec<u8>> {
    let mut writer = csv::Writer::from_writer(Vec::new());
    writer.write_record(headers).context("CSV write headers")?;
    for row in rows {
        writer.write_record(row).context("CSV write row")?;
    }
    writer.flush().context("CSV flush")?;
    writer
        .into_inner()
        .map_err(|e| anyhow::anyhow!("CSV into_inner: {e}"))
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

pub fn write_inventory_outputs(
    output_dir: &PathBuf,
    timestamp: &str,
    inventory_rows: &[Vec<String>],
    skip_inventory_csv: bool,
) -> Result<Vec<String>> {
    let mut written_files = Vec::new();

    if inventory_rows.is_empty() {
        eprintln!("=== Inventory: no rows collected (all asset types empty) ===");
        return Ok(written_files);
    }

    if !skip_inventory_csv {
        std::fs::create_dir_all(output_dir).with_context(|| {
            format!("Failed to create output directory {}", output_dir.display())
        })?;
        let filename = format!("AWS_Inventory-{}.csv", timestamp);
        let path = output_dir.join(&filename);
        let bytes = write_csv_bytes(crate::inventory_core::INVENTORY_CSV_HEADERS, inventory_rows)?;
        std::fs::write(&path, bytes)
            .with_context(|| format!("Failed to write {}", path.display()))?;
        eprintln!(
            "=== Inventory CSV: {} ({} rows) ===",
            path.display(),
            inventory_rows.len()
        );
        written_files.push(path.display().to_string());
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

    let xlsx_filename = now_local
        .format("%Y-%m-%d_Inventory_%H-%M-%S.xlsx")
        .to_string();
    let xlsx_path = PathBuf::from("inventory")
        .join(&year)
        .join(format!("{month_num}-{month_abbr}"))
        .join(&xlsx_filename);
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
