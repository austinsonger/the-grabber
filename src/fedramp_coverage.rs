//! Post-run coverage report — for every Req ID in the bundled mapping, list
//! which collector and file (if any) covered it during this run.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use crate::fedramp_map::bundled;

#[derive(Debug, Clone)]
pub struct CoverageEmission {
    pub filename_prefix: String,
    pub source_evidence_file: String,
    pub row_count: usize,
}

#[derive(Debug, Default)]
pub struct CoverageRun {
    pub emitted: Vec<CoverageEmission>,
}

impl CoverageRun {
    pub fn record(
        &mut self,
        filename_prefix: impl Into<String>,
        source_evidence_file: impl Into<String>,
        row_count: usize,
    ) {
        self.emitted.push(CoverageEmission {
            filename_prefix: filename_prefix.into(),
            source_evidence_file: source_evidence_file.into(),
            row_count,
        });
    }
}

pub fn write_coverage_report(run: &CoverageRun, run_dir: &Path) -> Result<PathBuf> {
    let map = bundled();

    // Invert emissions to Req ID → all (collector, file, rows) hits. A Req ID can be
    // satisfied by more than one collector, so we accumulate rather than overwrite.
    let mut by_req: BTreeMap<String, Vec<(String, String, usize)>> = BTreeMap::new();
    for e in &run.emitted {
        let mapping = map.get(&e.filename_prefix);
        for req in &mapping.req_ids {
            by_req.entry(req.clone()).or_default().push((
                e.filename_prefix.clone(),
                e.source_evidence_file.clone(),
                e.row_count,
            ));
        }
    }

    let path = run_dir.join("fedramp-coverage-actual.csv");
    let mut wtr = csv::Writer::from_path(&path)
        .with_context(|| format!("open coverage report at {}", path.display()))?;

    wtr.write_record([
        "Req ID",
        "Control ID",
        "Family",
        "Description",
        "Collector Name",
        "Source Evidence File",
        "Row Count",
        "Bucket",
    ])
    .context("write coverage header")?;

    for (req_id, info) in map.all_requirements() {
        let (collector, file, rows, bucket) = match by_req.get(req_id.as_str()) {
            Some(hits) if !hits.is_empty() => {
                let collectors = hits
                    .iter()
                    .map(|(c, _, _)| c.as_str())
                    .collect::<Vec<_>>()
                    .join(" | ");
                let files = hits
                    .iter()
                    .map(|(_, f, _)| f.as_str())
                    .collect::<Vec<_>>()
                    .join(" | ");
                let total_rows: usize = hits.iter().map(|(_, _, r)| r).sum();
                (collectors, files, total_rows, "COVERED")
            }
            _ => (String::new(), String::new(), 0usize, "UNCOVERED"),
        };
        wtr.write_record([
            req_id.as_str(),
            info.control_id.as_str(),
            info.family.as_str(),
            info.description.as_str(),
            &collector,
            &file,
            &rows.to_string(),
            bucket,
        ])
        .context("write coverage row")?;
    }

    wtr.flush().context("flush coverage report")?;
    Ok(path)
}
