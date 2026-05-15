use std::io::Read;

use anyhow::{Context, Result};
use zip::ZipArchive;

pub(super) fn zip_entry_to_string<R: Read + std::io::Seek>(
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

pub(super) fn sheet_rel_id(workbook_xml: &str, target_sheet: &str) -> Option<String> {
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

pub(super) fn sheet_target(rels_xml: &str, rel_id: &str) -> Option<String> {
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

pub(super) fn inject_rows(
    sheet_xml: &str,
    header_rows_to_keep: u32,
    rows: &[Vec<String>],
) -> String {
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
        // xml:space="preserve" is required for Excel to retain newlines and leading/trailing spaces
        xml.push_str(&format!(
            "<c r=\"{cell_ref}\" t=\"inlineStr\"><is><t xml:space=\"preserve\">{escaped}</t></is></c>"
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
    // Strip characters that are illegal in XML 1.0 (U+0000–U+0008, U+000B, U+000C, U+000E–U+001F).
    // Tab (U+0009), LF (U+000A), and CR (U+000D) are valid and preserved.
    let cleaned: String = input
        .chars()
        .filter(|&c| c >= '\u{0020}' || c == '\t' || c == '\n' || c == '\r')
        .collect();
    cleaned
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}
