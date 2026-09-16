//! Cross-check: every asset referenced by the latest Inspector2 ECR image
//! findings CSV must appear (repo + image digest) in the latest inventory CSV.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};

const ECR_MARKER: &str = "_Inspector2_ECR_Image_Findings-";
const INVENTORY_MARKER: &str = "AWS_Inventory-";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Gap {
    pub finding_arn: String,
    pub cve_id: String,
    pub resource_id: String,
    pub reason: &'static str,
}

/// Asset key for an ECR image: (region, account, repo, digest).
type ImageKey = (String, String, String, String);

/// Parses `arn:aws:ecr:<region>:<account>:repository/<repo>/sha256:<hex>`.
fn parse_finding_resource(resource_id: &str) -> Option<ImageKey> {
    let rest = resource_id.trim().strip_prefix("arn:aws:ecr:")?;
    let (region, rest) = rest.split_once(':')?;
    let (account, rest) = rest.split_once(':')?;
    let rest = rest.strip_prefix("repository/")?;
    let idx = rest.rfind("/sha256:")?;
    Some((
        region.to_string(),
        account.to_string(),
        rest[..idx].to_string(),
        rest[idx + 1..].to_string(),
    ))
}

/// Parses an inventory `Comments` cell: `RepositoryArn: arn:aws:ecr:... | ImageDigest: sha256:...`.
fn parse_inventory_comments(comments: &str) -> Option<ImageKey> {
    let mut repo_arn = None;
    let mut digest = None;
    for part in comments.split(" | ") {
        if let Some(v) = part.trim().strip_prefix("RepositoryArn:") {
            repo_arn = Some(v.trim());
        } else if let Some(v) = part.trim().strip_prefix("ImageDigest:") {
            digest = Some(v.trim());
        }
    }
    let digest = digest.filter(|d| !d.is_empty())?;
    parse_finding_resource(&format!("{}/{digest}", repo_arn?))
}

fn repo_of(k: &ImageKey) -> (String, String, String) {
    (k.0.clone(), k.1.clone(), k.2.clone())
}

/// Pure comparison. `findings` = (finding ARN, CVE ID, Resource ID). A rolled-up
/// finding lists several image ARNs in Resource ID separated by `;`; each image
/// is checked (and reported) on its own.
pub fn find_gaps(findings: &[(String, String, String)], inventory: &HashSet<ImageKey>) -> Vec<Gap> {
    let repos: HashSet<_> = inventory.iter().map(repo_of).collect();
    findings
        .iter()
        .flat_map(|(arn, cve, rids)| {
            rids.split(';')
                .map(str::trim)
                .filter(|rid| !rid.is_empty())
                .map(move |rid| (arn, cve, rid.to_string()))
        })
        .filter_map(|(arn, cve, rid)| {
            let rid = &rid;
            let reason = match parse_finding_resource(rid) {
                None => "UNPARSEABLE_RESOURCE_ID",
                Some(k) if inventory.contains(&k) => return None,
                Some(k) if repos.contains(&repo_of(&k)) => "DIGEST_MISMATCH",
                Some(_) => "MISSING_REPO",
            };
            Some(Gap {
                finding_arn: arn.clone(),
                cve_id: cve.clone(),
                resource_id: rid.clone(),
                reason,
            })
        })
        .collect()
}

/// Newest file under `dir` (recursive) whose name contains `marker` followed by a
/// fixed-width `YYYY-MM-DD-HHMMSS.csv` suffix.
fn latest_by_marker(dir: &Path, marker: &str) -> Result<PathBuf> {
    fn walk(dir: &Path, marker: &str, best: &mut Option<(String, PathBuf)>) -> Result<()> {
        for entry in
            std::fs::read_dir(dir).with_context(|| format!("cannot read {}", dir.display()))?
        {
            let path = entry?.path();
            if path.is_dir() {
                walk(&path, marker, best)?;
                continue;
            }
            let name = path
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .to_string();
            let Some(stem) = name.strip_suffix(".csv") else {
                continue;
            };
            let Some(pos) = stem.find(marker) else {
                continue;
            };
            let stamp = stem[pos + marker.len()..].to_string();
            if stamp.len() != 17 || !stamp.chars().all(|c| c.is_ascii_digit() || c == '-') {
                continue;
            }
            if best.as_ref().is_none_or(|(s, _)| stamp > *s) {
                *best = Some((stamp, path));
            }
        }
        Ok(())
    }
    let mut best = None;
    walk(dir, marker, &mut best)?;
    match best {
        Some((_, p)) => Ok(p),
        None => bail!(
            "no '*{marker}YYYY-MM-DD-HHMMSS.csv' found under {}",
            dir.display()
        ),
    }
}

fn read_csv(path: &Path) -> Result<(csv::StringRecord, Vec<csv::StringRecord>)> {
    let mut r = csv::ReaderBuilder::new()
        .flexible(true)
        .from_path(path)
        .with_context(|| format!("cannot open {}", path.display()))?;
    let headers = r.headers()?.clone();
    let rows = r
        .records()
        .collect::<Result<Vec<_>, _>>()
        .with_context(|| format!("CSV parse error in {}", path.display()))?;
    Ok((headers, rows))
}

fn col(headers: &csv::StringRecord, name: &str, file: &Path) -> Result<usize> {
    headers
        .iter()
        .position(|h| h.trim() == name)
        .with_context(|| format!("{} missing '{name}' column", file.display()))
}

/// CLI entry: returns the number of gaps (0 = every finding asset is inventoried).
pub fn run(evidence_dir: &Path, inventory_dir: &Path) -> Result<usize> {
    let ecr_path = latest_by_marker(evidence_dir, ECR_MARKER)?;
    let inv_path = latest_by_marker(inventory_dir, INVENTORY_MARKER)?;
    println!("Findings:  {}", ecr_path.display());
    println!("Inventory: {}", inv_path.display());

    let (h, rows) = read_csv(&ecr_path)?;
    let (arn_i, cve_i, rid_i) = (
        col(&h, "Finding ARN", &ecr_path)?,
        col(&h, "CVE ID", &ecr_path)?,
        col(&h, "Resource ID", &ecr_path)?,
    );
    let get = |r: &csv::StringRecord, i: usize| r.get(i).unwrap_or("").trim().to_string();
    let findings: Vec<_> = rows
        .iter()
        .map(|r| (get(r, arn_i), get(r, cve_i), get(r, rid_i)))
        .filter(|f| !f.0.is_empty())
        .collect();

    let (h, rows) = read_csv(&inv_path)?;
    let (type_i, comments_i) = (
        col(&h, "Asset Type", &inv_path)?,
        col(&h, "Comments", &inv_path)?,
    );
    let inventory: HashSet<ImageKey> = rows
        .iter()
        .filter(|r| r.get(type_i).map(str::trim) == Some("Container Image"))
        .filter_map(|r| parse_inventory_comments(r.get(comments_i).unwrap_or("")))
        .collect();

    let gaps = find_gaps(&findings, &inventory);
    let assets: HashSet<_> = findings
        .iter()
        .flat_map(|f| f.2.split(';').map(str::trim))
        .filter(|a| !a.is_empty())
        .collect();
    println!(
        "Checked {} findings across {} image assets against {} inventoried images: {} gaps",
        findings.len(),
        assets.len(),
        inventory.len(),
        gaps.len()
    );

    if !gaps.is_empty() {
        let out = PathBuf::from(format!(
            "ECR-Inventory-Gaps-{}.csv",
            chrono::Local::now().format("%Y-%m-%d-%H%M%S")
        ));
        let mut w = csv::Writer::from_path(&out)
            .with_context(|| format!("cannot write {}", out.display()))?;
        w.write_record(["Finding ARN", "CVE ID", "Resource ID", "Reason"])?;
        for g in &gaps {
            w.write_record([&g.finding_arn, &g.cve_id, &g.resource_id, g.reason])?;
        }
        w.flush()?;
        println!("Gap report: {}", out.display());
    }
    Ok(gaps.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    const RID: &str = "arn:aws:ecr:us-east-1:123456789012:repository/team/app/sha256:abc";

    #[test]
    fn keys_from_both_sides_match_and_gaps_are_classified() {
        let inv_key = parse_inventory_comments(
            "RepositoryArn: arn:aws:ecr:us-east-1:123456789012:repository/team/app | ScanOnPush: false | ImageDigest: sha256:abc | ImageTags: v1",
        )
        .expect("inventory key");
        assert_eq!(Some(inv_key.clone()), parse_finding_resource(RID));

        let inventory = HashSet::from([inv_key]);
        let f = |rid: &str| ("arn:f".to_string(), "CVE-1".to_string(), rid.to_string());
        let gaps = find_gaps(
            &[
                f(RID),
                f("arn:aws:ecr:us-east-1:123456789012:repository/team/app/sha256:old"),
                f("arn:aws:ecr:us-east-1:123456789012:repository/other/sha256:abc"),
                f("garbage"),
                // rolled-up finding: first image inventoried, second repo missing
                f(&format!(
                    "{RID}; arn:aws:ecr:us-east-1:123456789012:repository/gone/sha256:abc"
                )),
            ],
            &inventory,
        );
        let reasons: Vec<_> = gaps.iter().map(|g| g.reason).collect();
        assert_eq!(
            reasons,
            [
                "DIGEST_MISMATCH",
                "MISSING_REPO",
                "UNPARSEABLE_RESOURCE_ID",
                "MISSING_REPO"
            ]
        );
        assert!(gaps[3].resource_id.contains("repository/gone/"));
    }
}
