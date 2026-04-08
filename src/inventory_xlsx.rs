//! Write inventory rows into a copy of the Excel template.
//!
//! # Approach
//! `xlsx` files are ZIP archives containing XML.  We open the template ZIP,
//! locate the "Inventory" worksheet's XML via `xl/workbook.xml` +
//! `xl/_rels/workbook.xml.rels`, inject data rows starting at Excel row 3
//! (preserving rows 1 and 2 which carry the title and column headers), then
//! write a new ZIP to the output path.  Because we copy every other ZIP entry
//! verbatim, all formatting, merged cells, styles, and other sheets are
//! preserved exactly as they appear in the template.
//!
//! `calamine` is used to validate the template before we touch it.
//!
//! # Layout contract
//! - Sheet name : `"Inventory"` (second worksheet in the template)
//! - Row 1      : document title / merged header  → preserved untouched
//! - Row 2      : column header labels             → preserved untouched
//! - Row 3+     : data rows written by this module (14 columns,
//!                matching [`crate::inventory_core::INVENTORY_CSV_HEADERS`])

use anyhow::{bail, Context, Result};
use calamine::{open_workbook, Reader, Xlsx};
use std::io::{Cursor, Read, Write};
use std::path::Path;
use zip::{write::SimpleFileOptions, ZipArchive, ZipWriter};

/// Open `template_path` (validated with calamine), inject `rows` starting at
/// Excel row 3 on the `"Inventory"` sheet, and save the result to
/// `output_path`.  All template formatting is preserved.
pub fn write_inventory_xlsx(
    rows: &[Vec<String>],
    template_path: &Path,
    output_path: &Path,
) -> Result<()> {
    // ── 1. Validate template with calamine ────────────────────────────────────
    let mut cal_wb: Xlsx<_> = open_workbook(template_path).with_context(|| {
        format!(
            "calamine: cannot open template '{}'",
            template_path.display()
        )
    })?;
    let sheet_names = cal_wb.sheet_names().to_vec();
    if !sheet_names.iter().any(|s| s == "Inventory") {
        bail!(
            "Template '{}' has no sheet named 'Inventory'. Found: {:?}",
            template_path.display(),
            sheet_names
        );
    }
    drop(cal_wb); // release file handle before we re-open as ZIP

    // ── 2. Read template bytes ─────────────────────────────────────────────────
    let template_bytes = std::fs::read(template_path).with_context(|| {
        format!("Cannot read template '{}'", template_path.display())
    })?;

    // ── 3. Resolve the Inventory worksheet path inside the ZIP ─────────────────
    let mut probe = ZipArchive::new(Cursor::new(template_bytes.as_slice()))
        .context("Template is not a valid ZIP/xlsx archive")?;
    let workbook_xml = zip_entry_to_string(&mut probe, "xl/workbook.xml")
        .context("Cannot read xl/workbook.xml from template")?;
    let rels_xml = zip_entry_to_string(&mut probe, "xl/_rels/workbook.xml.rels")
        .context("Cannot read xl/_rels/workbook.xml.rels from template")?;
    drop(probe);

    let rel_id = sheet_rel_id(&workbook_xml, "Inventory")
        .context("'Inventory' sheet not found in workbook.xml")?;
    let sheet_zip_path = sheet_target(&rels_xml, &rel_id)
        .with_context(|| format!("Cannot resolve ZIP path for rel id '{rel_id}'"))?;

    // ── 4. Build the modified worksheet XML ───────────────────────────────────
    let mut probe2 = ZipArchive::new(Cursor::new(template_bytes.as_slice()))
        .context("Cannot re-open template ZIP")?;
    let sheet_xml = zip_entry_to_string(&mut probe2, &sheet_zip_path)
        .with_context(|| format!("Cannot read '{sheet_zip_path}' from template"))?;
    drop(probe2);

    let modified_xml = inject_rows(&sheet_xml, rows);

    // ── 5. Copy ZIP to output, swapping in the modified worksheet ─────────────
    if let Some(parent) = output_path.parent() {
        std::fs::create_dir_all(parent).with_context(|| {
            format!("Cannot create directory '{}'", parent.display())
        })?;
    }

    let mut out_buf: Vec<u8> = Vec::with_capacity(template_bytes.len() + rows.len() * 256);
    {
        let mut writer = ZipWriter::new(Cursor::new(&mut out_buf));
        let mut source = ZipArchive::new(Cursor::new(template_bytes.as_slice()))
            .context("Cannot re-open template ZIP for copying")?;

        for i in 0..source.len() {
            let mut entry = source.by_index(i).context("Cannot read ZIP entry")?;
            let name = entry.name().to_owned();
            let compression = entry.compression();

            let mut raw = Vec::new();
            entry.read_to_end(&mut raw).with_context(|| {
                format!("Cannot decompress ZIP entry '{name}'")
            })?;
            drop(entry);

            let content: &[u8] = if name == sheet_zip_path {
                modified_xml.as_bytes()
            } else {
                &raw
            };

            let opts = SimpleFileOptions::default().compression_method(compression);
            writer
                .start_file(&name, opts)
                .with_context(|| format!("Cannot start ZIP entry '{name}'"))?;
            writer.write_all(content).with_context(|| {
                format!("Cannot write ZIP entry '{name}'")
            })?;
        }
        writer.finish().context("Cannot finalise output ZIP")?;
    }

    std::fs::write(output_path, &out_buf).with_context(|| {
        format!("Cannot write output file '{}'", output_path.display())
    })?;

    Ok(())
}

// ── ZIP helpers ───────────────────────────────────────────────────────────────

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

// ── workbook.xml / rels helpers ───────────────────────────────────────────────

/// Extract the `r:id` for a named sheet from `xl/workbook.xml`.
fn sheet_rel_id(workbook_xml: &str, sheet_name: &str) -> Option<String> {
    let needle = format!("name=\"{sheet_name}\"");
    for chunk in workbook_xml.split('<') {
        if chunk.starts_with("sheet ") && chunk.contains(&needle) {
            for prefix in ["r:id=\"", "relationships:id=\""] {
                if let Some(pos) = chunk.find(prefix) {
                    let rest = &chunk[pos + prefix.len()..];
                    if let Some(end) = rest.find('"') {
                        return Some(rest[..end].to_string());
                    }
                }
            }
        }
    }
    None
}

/// Resolve a relationship `Id` to a ZIP-internal path using `workbook.xml.rels`.
fn sheet_target(rels_xml: &str, rel_id: &str) -> Option<String> {
    let needle = format!("Id=\"{rel_id}\"");
    for chunk in rels_xml.split('<') {
        if chunk.starts_with("Relationship ") && chunk.contains(&needle) {
            if let Some(pos) = chunk.find("Target=\"") {
                let rest = &chunk[pos + 8..];
                if let Some(end) = rest.find('"') {
                    let target = &rest[..end];
                    return Some(if target.starts_with('/') {
                        target[1..].to_string()
                    } else {
                        format!("xl/{target}")
                    });
                }
            }
        }
    }
    None
}

// ── worksheet XML injection ───────────────────────────────────────────────────

/// Keep rows 1 and 2 from the template `<sheetData>`, discard any rows ≥ 3,
/// then append the supplied inventory `rows` starting at Excel row 3.
fn inject_rows(sheet_xml: &str, rows: &[Vec<String>]) -> String {
    let open_tag = "<sheetData>";
    let close_tag = "</sheetData>";

    let (sd_start, sd_end) = match (sheet_xml.find(open_tag), sheet_xml.find(close_tag)) {
        (Some(s), Some(e)) => (s, e),
        _ => return sheet_xml.to_string(), // unexpected format — return unchanged
    };

    let before = &sheet_xml[..sd_start + open_tag.len()];
    let after = &sheet_xml[sd_end..]; // includes </sheetData>
    let existing = &sheet_xml[sd_start + open_tag.len()..sd_end];

    let header_rows = extract_header_rows(existing);
    let mut data_rows = String::new();
    for (i, row) in rows.iter().enumerate() {
        data_rows.push_str(&build_row_xml((i + 3) as u32, row));
    }

    format!("{before}{header_rows}{data_rows}{after}")
}

/// Return the raw XML text for rows whose `r` attribute is `"1"` or `"2"`.
fn extract_header_rows(sheet_data: &str) -> String {
    let mut result = String::new();
    let mut remaining = sheet_data;

    while let Some(rel_pos) = remaining.find("<row ") {
        let tag_end_rel = match remaining[rel_pos..].find('>') {
            Some(p) => p,
            None => break,
        };
        let attrs = &remaining[rel_pos + 5..rel_pos + tag_end_rel];
        let is_header = attrs.contains("r=\"1\"")
            || attrs.contains("r=\"2\"")
            || attrs.contains("r='1'")
            || attrs.contains("r='2'");

        match remaining[rel_pos..].find("</row>") {
            Some(close_rel) => {
                let row_end = rel_pos + close_rel + 6;
                if is_header {
                    result.push_str(&remaining[rel_pos..row_end]);
                }
                remaining = &remaining[row_end..];
            }
            None => break,
        }
    }
    result
}

// ── cell / row XML builders ───────────────────────────────────────────────────

fn build_row_xml(row_num: u32, cells: &[String]) -> String {
    let mut xml = format!("<row r=\"{row_num}\">");
    for (col, value) in cells.iter().enumerate() {
        if !value.is_empty() {
            let cell_ref = format!("{}{row_num}", col_letter(col));
            let v = escape_xml(value);
            xml.push_str(&format!(
                "<c r=\"{cell_ref}\" t=\"inlineStr\"><is><t>{v}</t></is></c>"
            ));
        }
    }
    xml.push_str("</row>");
    xml
}

/// Convert a 0-based column index to an Excel column letter (A, B, … Z, AA, …).
fn col_letter(col: usize) -> String {
    let mut n = col;
    let mut bytes = Vec::new();
    loop {
        bytes.push(b'A' + (n % 26) as u8);
        if n < 26 {
            break;
        }
        n = n / 26 - 1;
    }
    bytes.reverse();
    String::from_utf8(bytes).unwrap_or_default()
}

fn escape_xml(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn col_letters() {
        assert_eq!(col_letter(0), "A");
        assert_eq!(col_letter(25), "Z");
        assert_eq!(col_letter(26), "AA");
        assert_eq!(col_letter(27), "AB");
        assert_eq!(col_letter(51), "AZ");
        assert_eq!(col_letter(52), "BA");
    }

    #[test]
    fn xml_escaping() {
        assert_eq!(escape_xml("a & b < c > d"), "a &amp; b &lt; c &gt; d");
        assert_eq!(escape_xml("say \"hi\""), "say &quot;hi&quot;");
    }

    #[test]
    fn row_xml_skips_empty_cells() {
        let cells = vec!["foo".to_string(), String::new(), "bar".to_string()];
        let xml = build_row_xml(3, &cells);
        assert!(xml.contains("A3"));
        assert!(!xml.contains("B3")); // empty → skipped
        assert!(xml.contains("C3"));
    }

    #[test]
    fn inject_rows_preserves_header_rows() {
        let sheet_xml = r#"<worksheet><sheetData><row r="1"><c r="A1" t="inlineStr"><is><t>Title</t></is></c></row><row r="2"><c r="A2" t="inlineStr"><is><t>Header</t></is></c></row></sheetData></worksheet>"#;
        let rows = vec![vec!["data".to_string(), String::new()]];
        let result = inject_rows(sheet_xml, &rows);
        assert!(result.contains(r#"r="1""#), "row 1 preserved");
        assert!(result.contains(r#"r="2""#), "row 2 preserved");
        assert!(result.contains(r#"r="3""#), "row 3 injected");
        assert!(result.contains("data"));
    }
}
