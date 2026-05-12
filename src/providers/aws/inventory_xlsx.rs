//! Write inventory rows into a copy of the Excel template.
//!
//! # Approach
//! `xlsx` files are ZIP archives containing XML.  We open the template ZIP,
//! locate the "Inventory" worksheet's XML via `xl/workbook.xml` +
//! `xl/_rels/workbook.xml.rels`, derive the template's real column positions
//! from row 2, inject data rows starting at Excel row 3 (preserving rows 1 and
//! 2 which carry the title and column headers), then write a new ZIP to the
//! output path.  Because we copy every other ZIP entry verbatim, all
//! formatting, merged cells, styles, and other sheets are preserved exactly as
//! they appear in the template.
//!
//! `calamine` is used to validate the template before we touch it.
//!
//! # Layout contract
//! - Sheet name : `"Inventory"` (second worksheet in the template)
//! - Row 1      : document title / merged header  → preserved untouched
//! - Row 2      : column header labels             → preserved untouched
//! - Row 3+     : data rows written by this module, mapped into the template's
//!                actual columns by matching row-2 header labels against
//!                [`crate::inventory_core::INVENTORY_CSV_HEADERS`]

use anyhow::{bail, Context, Result};
use calamine::{open_workbook, Reader, Xlsx};
use std::collections::HashMap;
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
    let template_columns = inventory_template_columns(&mut cal_wb)?;
    drop(cal_wb); // release file handle before we re-open as ZIP

    // ── 2. Read template bytes ─────────────────────────────────────────────────
    let template_bytes = std::fs::read(template_path)
        .with_context(|| format!("Cannot read template '{}'", template_path.display()))?;

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

    let modified_xml = inject_rows(&sheet_xml, rows, &template_columns)?;

    // ── 5. Copy ZIP to output, swapping in the modified worksheet ─────────────
    if let Some(parent) = output_path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("Cannot create directory '{}'", parent.display()))?;
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
            entry
                .read_to_end(&mut raw)
                .with_context(|| format!("Cannot decompress ZIP entry '{name}'"))?;
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
            writer
                .write_all(content)
                .with_context(|| format!("Cannot write ZIP entry '{name}'"))?;
        }
        writer.finish().context("Cannot finalise output ZIP")?;
    }

    std::fs::write(output_path, &out_buf)
        .with_context(|| format!("Cannot write output file '{}'", output_path.display()))?;

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
fn inject_rows(
    sheet_xml: &str,
    rows: &[Vec<String>],
    template_columns: &[usize],
) -> Result<String> {
    let open_tag = "<sheetData>";
    let close_tag = "</sheetData>";

    let (sd_start, sd_end) = match (sheet_xml.find(open_tag), sheet_xml.find(close_tag)) {
        (Some(s), Some(e)) => (s, e),
        _ => bail!("Inventory sheet XML is missing <sheetData>"),
    };

    let before = &sheet_xml[..sd_start + open_tag.len()];
    let after = &sheet_xml[sd_end..]; // includes </sheetData>
    let existing = &sheet_xml[sd_start + open_tag.len()..sd_end];

    let header_rows = extract_header_rows(existing);
    let mut data_rows = String::new();
    for (i, row) in rows.iter().enumerate() {
        data_rows.push_str(&build_row_xml((i + 3) as u32, row, template_columns)?);
    }

    Ok(format!("{before}{header_rows}{data_rows}{after}"))
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

fn build_row_xml(row_num: u32, cells: &[String], template_columns: &[usize]) -> Result<String> {
    if cells.len() != template_columns.len() {
        bail!(
            "Inventory row has {} cells, but template mapping expects {}",
            cells.len(),
            template_columns.len()
        );
    }

    // Excel requires <c> elements within a <row> to be in strictly ascending
    // column order. `template_columns` is not sorted (e.g. Function → X(23)
    // comes before VLAN → U(20) in CSV index order), so sort non-empty cells
    // by target column before emitting.
    let mut ordered: Vec<(usize, &str)> = cells
        .iter()
        .enumerate()
        .filter(|(_, v)| !v.is_empty())
        .map(|(i, v)| (template_columns[i], v.as_str()))
        .collect();
    ordered.sort_by_key(|(col, _)| *col);

    // Defensive guard: the ascending-order invariant must hold at the point we
    // emit XML. If it doesn't, Excel flags the file as corrupt and silently
    // drops cells during its "repair" pass. Fail fast instead of writing junk.
    for pair in ordered.windows(2) {
        if pair[0].0 >= pair[1].0 {
            bail!(
                "Inventory row {}: cell columns not strictly ascending ({} then {}). \
                 This indicates a schema mismatch or duplicate template column mapping.",
                row_num,
                col_letter(pair[0].0),
                col_letter(pair[1].0)
            );
        }
    }

    let mut xml = format!("<row r=\"{row_num}\">");
    for (col, value) in ordered {
        let cell_ref = format!("{}{row_num}", col_letter(col));
        let v = escape_xml(value);
        xml.push_str(&format!(
            "<c r=\"{cell_ref}\" t=\"inlineStr\"><is><t>{v}</t></is></c>"
        ));
    }
    xml.push_str("</row>");
    Ok(xml)
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

fn inventory_template_columns<R: Read + std::io::Seek>(
    workbook: &mut Xlsx<R>,
) -> Result<Vec<usize>> {
    let range = workbook
        .worksheet_range("Inventory")
        .context("Cannot read 'Inventory' worksheet range from template")?;
    let header_row = range
        .rows()
        .nth(1)
        .context("Inventory template is missing header row 2")?;

    let header_positions = header_row
        .iter()
        .enumerate()
        .filter_map(|(idx, cell)| {
            let label = normalized_header_label(&cell.to_string());
            (!label.is_empty()).then_some((label, idx))
        })
        .collect::<HashMap<_, _>>();

    let resolved: Vec<usize> = crate::inventory_core::INVENTORY_CSV_HEADERS
        .iter()
        .map(|header| {
            let normalized = normalized_header_label(header);
            header_positions.get(&normalized).copied().with_context(|| {
                format!("Inventory template is missing required header '{header}'")
            })
        })
        .collect::<Result<_>>()?;

    // Defensive guard: two CSV fields resolving to the same template column
    // would silently overwrite each other. Catch that here rather than emit a
    // file Excel flags as corrupt.
    let mut seen: HashMap<usize, &str> = HashMap::new();
    for (header, col) in crate::inventory_core::INVENTORY_CSV_HEADERS
        .iter()
        .zip(resolved.iter())
    {
        if let Some(prev) = seen.insert(*col, header) {
            bail!(
                "Inventory template has duplicate column mapping at {}: '{}' and '{}' \
                 both resolve to the same position",
                col_letter(*col),
                prev,
                header
            );
        }
    }

    Ok(resolved)
}

fn normalized_header_label(raw: &str) -> String {
    let expanded = raw.replace("_x000a_", "\n").replace("\r\n", "\n").replace('\r', "\n");
    let visible = expanded.split("\n\n(").next().unwrap_or(&expanded);
    visible
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .trim()
        .to_ascii_lowercase()
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
    fn row_xml_uses_template_columns_and_skips_empty_cells() {
        let cells = vec!["foo".to_string(), String::new(), "bar".to_string()];
        let xml = build_row_xml(3, &cells, &[0, 6, 23]).expect("row XML");
        assert!(xml.contains("A3"));
        assert!(!xml.contains("G3")); // empty → skipped
        assert!(xml.contains("X3"));
    }

    #[test]
    fn row_xml_emits_cells_in_ascending_column_order() {
        // CSV index order puts X(23) before U(20) before S(18); Excel requires
        // ascending column order within a <row> or it flags the file as
        // corrupt on open.
        let cells = vec!["fn".to_string(), "vlan".to_string(), "cmt".to_string()];
        let xml = build_row_xml(3, &cells, &[23, 20, 18]).expect("row XML");
        let s_pos = xml.find("S3").expect("S3 cell present");
        let u_pos = xml.find("U3").expect("U3 cell present");
        let x_pos = xml.find("X3").expect("X3 cell present");
        assert!(s_pos < u_pos && u_pos < x_pos, "cells must be S < U < X");
    }

    #[test]
    fn row_xml_rejects_duplicate_target_columns() {
        // Two CSV fields both mapped to column C — build_row_xml must bail
        // rather than emit two <c r="C3"> elements.
        let cells = vec!["a".to_string(), "b".to_string()];
        let err = build_row_xml(3, &cells, &[2, 2]).expect_err("should fail");
        let msg = format!("{err}");
        assert!(
            msg.contains("not strictly ascending"),
            "unexpected error: {msg}"
        );
    }

    #[test]
    fn inject_rows_preserves_header_rows() {
        let sheet_xml = r#"<worksheet><sheetData><row r="1"><c r="A1" t="inlineStr"><is><t>Title</t></is></c></row><row r="2"><c r="A2" t="inlineStr"><is><t>Header</t></is></c></row></sheetData></worksheet>"#;
        let rows = vec![vec!["data".to_string(), String::new()]];
        let result = inject_rows(sheet_xml, &rows, &[0, 23]).expect("inject rows");
        assert!(result.contains(r#"r="1""#), "row 1 preserved");
        assert!(result.contains(r#"r="2""#), "row 2 preserved");
        assert!(result.contains(r#"r="3""#), "row 3 injected");
        assert!(result.contains("data"));
    }

    #[test]
    #[ignore]
    fn integration_writes_against_real_template() {
        let tmp = std::env::temp_dir().join("grabber_inventory_test.xlsx");
        let _ = std::fs::remove_file(&tmp);
        let row = crate::inventory_core::RowBuilder::new()
            .unique_id("arn:test")
            .virtual_flag("Yes")
            .public("No")
            .location("us-east-1")
            .asset_type("KMS Key")
            .sw_vendor("Amazon Web Services")
            .sw_name_ver("AWS KMS")
            .function("Test row")
            .comments("Integration smoke test")
            .build();
        let rows = vec![row];
        write_inventory_xlsx(
            &rows,
            std::path::Path::new("assets/Inventory.xlsx"),
            &tmp,
        )
        .expect("write_inventory_xlsx must succeed against real template");
        let bytes = std::fs::metadata(&tmp).expect("output exists").len();
        assert!(bytes > 10_000, "output xlsx looks too small ({bytes} bytes)");
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn normalizes_template_headers_with_descriptions() {
        assert_eq!(
            normalized_header_label("VLAN/\nNetwork ID\n\n(\nDescription\n)"),
            "vlan/ network id"
        );
        assert_eq!(
            normalized_header_label("Function_x000a__x000a_(_x000a_Description_x000a_)"),
            "function"
        );
        // FedRAMP template re-saved on macOS / strict OOXML uses CRLF line
        // breaks inside cells; the split on "\n\n(" must still trigger.
        assert_eq!(
            normalized_header_label("UNIQUE ASSET IDENTIFIER\r\n\r\n(\r\nUnique Identifier ...\r\n)"),
            "unique asset identifier"
        );
    }
}
