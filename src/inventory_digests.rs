//! Container image digests listed in an inventory CSV (`AWS_Inventory-*.csv`).
//! The inventory decides which ECR image digests the findings output covers.

use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InventoryImage {
    pub asset_id: String,
    pub account: String,
    pub region: String,
    pub repository: String,
    pub repository_arn: String,
    pub digest: String,
}

#[derive(Debug, Clone)]
pub struct Inventory {
    pub path: PathBuf,
    pub images: Vec<InventoryImage>,
    pub rows_without_digest: usize,
}

/// Newest file under `dir` (recursive; hidden dirs and `target` skipped) whose
/// name contains `marker` followed by a fixed-width `YYYY-MM-DD-HHMMSS.csv`.
pub fn latest_file(dir: &Path, marker: &str) -> Result<PathBuf> {
    fn walk(dir: &Path, marker: &str, best: &mut Option<(String, PathBuf)>) -> Result<()> {
        for entry in
            std::fs::read_dir(dir).with_context(|| format!("cannot read {}", dir.display()))?
        {
            let path = entry?.path();
            let name = path
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .to_string();
            if path.is_dir() {
                if !name.starts_with('.') && name != "target" {
                    walk(&path, marker, best)?;
                }
                continue;
            }
            let Some(stem) = name.strip_suffix(".csv") else {
                continue;
            };
            let Some(pos) = stem.find(marker) else {
                continue;
            };
            let stamp = &stem[pos + marker.len()..];
            if stamp.len() != 17 || !stamp.chars().all(|c| c.is_ascii_digit() || c == '-') {
                continue;
            }
            if best.as_ref().is_none_or(|(s, _)| stamp > s.as_str()) {
                *best = Some((stamp.to_string(), path));
            }
        }
        Ok(())
    }
    let mut best = None;
    walk(dir, marker, &mut best)?;
    match best {
        Some((_, p)) => Ok(p),
        None => bail!(
            "no '*{marker}YYYY-MM-DD-HHMMSS.csv' under {}",
            dir.display()
        ),
    }
}

fn comment_field<'a>(comments: &'a str, key: &str) -> Option<&'a str> {
    comments
        .split(" | ")
        .find_map(|p| p.trim().strip_prefix(key).map(str::trim))
        .filter(|v| !v.is_empty())
}

/// `Container Image` rows of an inventory CSV that carry an `ImageDigest`.
pub fn read_inventory(path: &Path) -> Result<Inventory> {
    let mut reader = csv::ReaderBuilder::new()
        .flexible(true)
        .from_path(path)
        .with_context(|| format!("cannot open {}", path.display()))?;
    let headers = reader.headers().context("inventory CSV header")?.clone();
    let col = |name: &str| {
        headers
            .iter()
            .position(|h| h.trim() == name)
            .with_context(|| format!("{} missing '{name}' column", path.display()))
    };
    let (id_i, type_i, comments_i) = (
        col("UNIQUE ASSET IDENTIFIER")?,
        col("Asset Type")?,
        col("Comments")?,
    );

    let mut images = Vec::new();
    let mut rows_without_digest = 0;
    for rec in reader.records() {
        let rec = rec.with_context(|| format!("CSV parse error in {}", path.display()))?;
        if rec.get(type_i).map(str::trim) != Some("Container Image") {
            continue;
        }
        let comments = rec.get(comments_i).unwrap_or("");
        let (Some(arn), Some(digest)) = (
            comment_field(comments, "RepositoryArn:"),
            comment_field(comments, "ImageDigest:"),
        ) else {
            rows_without_digest += 1;
            continue;
        };
        // arn:aws:ecr:<region>:<account>:repository/<name>
        let mut parts = arn.splitn(6, ':');
        let (region, account, rest) = (parts.nth(3), parts.next(), parts.next());
        let (Some(region), Some(account), Some(repository)) = (
            region,
            account,
            rest.and_then(|r| r.strip_prefix("repository/")),
        ) else {
            rows_without_digest += 1;
            continue;
        };
        images.push(InventoryImage {
            asset_id: rec.get(id_i).unwrap_or("").trim().to_string(),
            account: account.to_string(),
            region: region.to_string(),
            repository: repository.to_string(),
            repository_arn: arn.to_string(),
            digest: digest.to_string(),
        });
    }
    Ok(Inventory {
        path: path.to_path_buf(),
        images,
        rows_without_digest,
    })
}

pub fn load_latest(dir: &Path) -> Result<Inventory> {
    read_inventory(&latest_file(dir, "AWS_Inventory-")?)
}

#[cfg(test)]
mod tests {
    use super::*;

    const HEADER: &str = "UNIQUE ASSET IDENTIFIER,IPv4 or IPv6 Address,Virtual,Public,DNS Name or URL,MAC Address,Location,Asset Type,Hardware Make/Model,Software/ Database Vendor,Software/ Database Name & Version,Function,VLAN/ Network ID,Comments,FedRAMP Req IDs,FedRAMP Control IDs,Source Evidence File\n";

    fn write(dir: &Path, name: &str, body: &str) -> PathBuf {
        let p = dir.join(name);
        std::fs::write(&p, format!("{HEADER}{body}")).expect("write");
        p
    }

    #[test]
    fn parses_container_rows() {
        let dir = tempfile::tempdir().expect("tempdir");
        let p = write(
            dir.path(),
            "AWS_Inventory-2026-09-16-172542.csv",
            "123456789012.dkr.ecr.us-east-1.amazonaws.com/team/app,,Yes,No,,,us-east-1 / ECR Repo: team/app,Container Image,,team/app,team/app | Tags: v1,,,\"RepositoryArn: arn:aws:ecr:us-east-1:123456789012:repository/team/app | ImageDigest: sha256:abc | ImageTags: v1\",,,f.csv\n\
             123456789012.dkr.ecr.us-east-1.amazonaws.com/empty,,Yes,No,,,us-east-1,Container Image,,empty,empty,,,\"RepositoryArn: arn:aws:ecr:us-east-1:123456789012:repository/empty | ImageCount: 0\",,,f.csv\n\
             arn:aws:kms:us-east-1:123456789012:key/1,,Yes,No,,,us-east-1,KMS Key,,x,x,,,Arn: x,,,f.csv\n",
        );
        let inv = read_inventory(&p).expect("read");
        assert_eq!(inv.rows_without_digest, 1);
        assert_eq!(
            inv.images,
            vec![InventoryImage {
                asset_id: "123456789012.dkr.ecr.us-east-1.amazonaws.com/team/app".into(),
                account: "123456789012".into(),
                region: "us-east-1".into(),
                repository: "team/app".into(),
                repository_arn: "arn:aws:ecr:us-east-1:123456789012:repository/team/app".into(),
                digest: "sha256:abc".into(),
            }]
        );
    }

    #[test]
    fn latest_file_picks_newest_recursively() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir_all(dir.path().join("2026/08-AUG")).expect("mkdir");
        std::fs::create_dir_all(dir.path().join("2026/09-SEP")).expect("mkdir");
        write(
            &dir.path().join("2026/08-AUG"),
            "AWS_Inventory-2026-08-31-235959.csv",
            "",
        );
        let newest = write(
            &dir.path().join("2026/09-SEP"),
            "AWS_Inventory-2026-09-16-172542.csv",
            "",
        );
        write(
            &dir.path().join("2026/09-SEP"),
            "AWS_Inventory-2026-09-16-090000.csv",
            "",
        );
        assert_eq!(
            latest_file(dir.path(), "AWS_Inventory-").expect("found"),
            newest
        );
        assert!(latest_file(dir.path(), "Nope-").is_err());
    }
}
