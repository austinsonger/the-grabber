use std::collections::HashMap;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};

const ECR_MARKER: &str = "_Inspector2_ECR_Image_Findings-";

#[derive(Debug, Clone)]
pub(super) struct CsvFinding {
    pub(super) arn: String,
    pub(super) stable_key: String, // CVE ID|Package Name — stable across rescans
    pub(super) values: HashMap<String, String>, // normalized header -> value
}

impl CsvFinding {
    pub(super) fn get(&self, header: &str) -> String {
        self.values
            .get(&normalize(header))
            .cloned()
            .unwrap_or_default()
    }
}

#[cfg(test)]
impl CsvFinding {
    pub(super) fn new_for_test(arn: String, stable_key: String, values: HashMap<String, String>) -> Self {
        CsvFinding { arn, stable_key, values }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd)]
struct CsvKey {
    year: u32,
    month: u32,
    day: u32,
    sequence: u64,
}

pub(super) fn read_ecr_csv(path: &Path) -> Result<(Vec<CsvFinding>, Vec<String>)> {
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
    let cve_idx = normalized_headers
        .iter()
        .position(|h| h == &normalize("CVE ID"));
    let pkg_idx = normalized_headers
        .iter()
        .position(|h| h == &normalize("Package Name"));

    let mut findings = Vec::new();
    let mut warnings = Vec::new();
    for (row_idx, rec) in reader.records().enumerate() {
        let record = rec.with_context(|| format!("CSV parse error at row {}", row_idx + 2))?;
        let arn = record.get(arn_idx).unwrap_or("").trim().to_string();
        if arn.is_empty() {
            warnings.push(format!("Row {} skipped: missing Finding ARN", row_idx + 2));
            continue;
        }
        let cve_id = cve_idx
            .and_then(|i| record.get(i))
            .unwrap_or("")
            .trim()
            .to_string();
        let pkg_name = pkg_idx
            .and_then(|i| record.get(i))
            .unwrap_or("")
            .trim()
            .to_string();
        let stable_key = if !cve_id.is_empty() && !pkg_name.is_empty() {
            format!("{cve_id}|{pkg_name}")
        } else if !cve_id.is_empty() {
            cve_id.clone()
        } else {
            arn.clone()
        };
        let mut values = HashMap::new();
        for (i, header_key) in normalized_headers.iter().enumerate() {
            values.insert(header_key.clone(), record.get(i).unwrap_or("").to_string());
        }
        findings.push(CsvFinding {
            arn,
            stable_key,
            values,
        });
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
            "no files matching '*{}YYYY-MM-DD-######.csv' in {}",
            ECR_MARKER,
            dir.display()
        ),
    }
}

fn parse_ecr_csv_key(filename: &str) -> Option<CsvKey> {
    if !filename.ends_with(".csv") {
        return None;
    }
    let stem = filename.strip_suffix(".csv")?;
    // Accept any prefix — match on the shared marker segment.
    let marker_pos = stem.find(ECR_MARKER)?;
    let tail = &stem[marker_pos + ECR_MARKER.len()..];
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

fn normalize(input: &str) -> String {
    input
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_lowercase())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn parse_ecr_csv_key_parses_expected_pattern() {
        let key = parse_ecr_csv_key(
            "Corporate_Security_Inspector2_ECR_Image_Findings-2026-04-08-214017.csv",
        )
        .expect("key");
        assert_eq!(key.year, 2026);
        assert_eq!(key.month, 4);
        assert_eq!(key.day, 8);
        assert_eq!(key.sequence, 214017);
    }

    #[test]
    fn parse_ecr_csv_key_parses_federal_prefix() {
        let key = parse_ecr_csv_key(
            "Federal_Operations_Inspector2_ECR_Image_Findings-2026-04-24-204228.csv",
        )
        .expect("key");
        assert_eq!(key.year, 2026);
        assert_eq!(key.month, 4);
        assert_eq!(key.day, 24);
        assert_eq!(key.sequence, 204228);
    }

    #[test]
    fn select_latest_ecr_csv_picks_newest_by_date_and_sequence() {
        let dir = tempdir().expect("tempdir");
        let files = [
            "Corporate_Security_Inspector2_ECR_Image_Findings-2026-04-08-214017.csv",
            "Corporate_Security_Inspector2_ECR_Image_Findings-2026-04-08-214116.csv",
            "Corporate_Security_Inspector2_ECR_Image_Findings-2026-03-31-235959.csv",
        ];
        for name in files {
            std::fs::write(dir.path().join(name), "Finding ARN,Title\narn:1,test\n")
                .expect("write");
        }

        let (name, _) = select_latest_ecr_csv(dir.path()).expect("select latest");
        assert_eq!(
            name,
            "Corporate_Security_Inspector2_ECR_Image_Findings-2026-04-08-214116.csv"
        );
    }
}
