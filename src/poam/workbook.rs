use std::collections::HashSet;
use std::io::{Cursor, Read, Write};
use std::path::Path;

use anyhow::{bail, Context, Result};
use calamine::{open_workbook, Reader, Xlsx};
use zip::{write::SimpleFileOptions, ZipArchive, ZipWriter};

use super::xml_utils::{inject_rows, sheet_rel_id, sheet_target, zip_entry_to_string};

const OPEN_SHEET: &str = "Open POA&M Items";
const CLOSED_SHEET: &str = "Closed POA&M Items";
const OPEN_HEADER_ROW: u32 = 5;
const CLOSED_HEADER_ROW: u32 = 2;

#[derive(Debug)]
pub(super) struct WorkbookData {
    pub(super) open_headers: Vec<String>,
    pub(super) closed_headers: Vec<String>,
    pub(super) open_rows: Vec<Vec<String>>,
    pub(super) closed_rows: Vec<Vec<String>>,
}

pub(super) fn read_poam_workbook(path: &Path) -> Result<WorkbookData> {
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

pub(super) fn write_poam_workbook(
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
