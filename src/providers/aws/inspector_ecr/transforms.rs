pub(super) fn secs_to_rfc3339(secs: i64) -> String {
    chrono::DateTime::<chrono::Utc>::from_timestamp(secs, 0)
        .map(|c| c.to_rfc3339())
        .unwrap_or_default()
}

// Second-pass cross-repository rollup — FedRAMP requires one row per CVE with
// all affected assets listed, not one row per (CVE + repository).
//
// Called after dedup_ecr_image_rows(). Groups by (CVE ID + Package Name) across
// all repos. The highest Inspector Score row is kept as representative; all
// other per-repo fields are merged into it.
//
// Indices reference the post-annotation column layout:
//   6  Inspector Score   8  CVE ID        15 Package Name    16 Package Version
//  23  Repository Name  24  Image Tags    25  Image Hash     30 Currently In Use
//  31  In Use Count     32  Resource ID   40  First Observed At  41 Days Open
//  42  Affected Image Count  43 Oldest Push Date  44 Newest Push Date
//  46  Package Version Varies
pub(super) fn rollup_ecr_by_cve(rows: Vec<Vec<String>>) -> Vec<Vec<String>> {
    use std::collections::{HashMap, HashSet};

    let mut groups: HashMap<String, Vec<Vec<String>>> = HashMap::new();
    for row in rows {
        let cve_id = row.get(8).map(|s| s.as_str()).unwrap_or("");
        let pkg_name = row.get(15).map(|s| s.as_str()).unwrap_or("");
        // Non-CVE findings keep their own row
        let key = if !cve_id.is_empty() {
            format!("{}|{}", cve_id, pkg_name)
        } else {
            format!("arn:{}", row.get(0).map(|s| s.as_str()).unwrap_or(""))
        };
        groups.entry(key).or_default().push(row);
    }

    let mut out = Vec::with_capacity(groups.len());
    for (_key, group_rows) in groups {
        if group_rows.len() == 1 {
            out.extend(group_rows);
            continue;
        }

        // Representative row = highest Inspector Score
        let best_idx = group_rows
            .iter()
            .enumerate()
            .max_by(|(_, a), (_, b)| {
                let sa: f64 = a.get(6).and_then(|s| s.parse().ok()).unwrap_or(0.0);
                let sb: f64 = b.get(6).and_then(|s| s.parse().ok()).unwrap_or(0.0);
                sa.partial_cmp(&sb).unwrap_or(std::cmp::Ordering::Equal)
            })
            .map(|(i, _)| i)
            .unwrap_or(0);
        let mut best = group_rows[best_idx].clone();

        // ── Accumulate per-repo fields ──────────────────────────────────
        let mut repos: Vec<String> = group_rows
            .iter()
            .flat_map(|r| {
                r.get(23)
                    .map(|s| s.split("; ").map(str::to_string).collect::<Vec<_>>())
                    .unwrap_or_default()
            })
            .filter(|s| !s.is_empty())
            .collect::<HashSet<_>>()
            .into_iter()
            .collect();
        repos.sort();

        let mut tags: Vec<String> = group_rows
            .iter()
            .flat_map(|r| {
                r.get(24)
                    .map(|s| s.split("; ").map(str::to_string).collect::<Vec<_>>())
                    .unwrap_or_default()
            })
            .filter(|s| !s.is_empty())
            .collect::<HashSet<_>>()
            .into_iter()
            .collect();
        tags.sort();

        let hashes: HashSet<String> = group_rows
            .iter()
            .filter_map(|r| r.get(25).map(|s| s.to_string()))
            .filter(|s| !s.is_empty())
            .collect();
        let image_hash = if hashes.len() == 1 {
            hashes.into_iter().next().unwrap()
        } else {
            "multiple".to_string()
        };

        let mut res_ids: Vec<String> = group_rows
            .iter()
            .flat_map(|r| {
                r.get(32)
                    .map(|s| s.split("; ").map(str::to_string).collect::<Vec<_>>())
                    .unwrap_or_default()
            })
            .filter(|s| !s.is_empty())
            .collect::<HashSet<_>>()
            .into_iter()
            .collect();
        res_ids.sort();

        let in_use_total: i64 = group_rows
            .iter()
            .filter_map(|r| r.get(31).and_then(|s| s.parse::<i64>().ok()))
            .sum();

        let currently_in_use = if group_rows
            .iter()
            .any(|r| r.get(30).map(|s| s == "YES").unwrap_or(false))
        {
            "YES"
        } else if group_rows
            .iter()
            .all(|r| r.get(30).map(|s| s == "UNKNOWN").unwrap_or(false))
        {
            "UNKNOWN"
        } else {
            "NO"
        };

        // Earliest first_observed drives Days Open for FedRAMP timeline compliance
        let earliest_observed: String = group_rows
            .iter()
            .filter_map(|r| r.get(40).map(|s| s.to_string()))
            .filter(|s| !s.is_empty())
            .min()
            .unwrap_or_default();
        let days_open = chrono::DateTime::parse_from_rfc3339(&earliest_observed)
            .map(|dt| {
                chrono::Utc::now()
                    .signed_duration_since(dt.with_timezone(&chrono::Utc))
                    .num_days()
                    .to_string()
            })
            .unwrap_or_default();

        let total_images: i64 = group_rows
            .iter()
            .filter_map(|r| r.get(42).and_then(|s| s.parse::<i64>().ok()))
            .sum();

        let all_push_dates: Vec<String> = group_rows
            .iter()
            .flat_map(|r| {
                [
                    r.get(43).map(|s| s.to_string()),
                    r.get(44).map(|s| s.to_string()),
                ]
            })
            .flatten()
            .filter(|s| !s.is_empty())
            .collect();
        let oldest_push = all_push_dates.iter().min().cloned().unwrap_or_default();
        let newest_push = all_push_dates.iter().max().cloned().unwrap_or_default();

        let version_varies = if group_rows
            .iter()
            .any(|r| r.get(46).map(|s| s == "YES").unwrap_or(false))
        {
            "YES"
        } else {
            let versions: HashSet<&str> = group_rows
                .iter()
                .filter_map(|r| r.get(16).map(|s| s.as_str()))
                .filter(|s| !s.is_empty())
                .collect();
            if versions.len() > 1 {
                "YES"
            } else {
                "NO"
            }
        }
        .to_string();

        // Accumulate Asset Identifiers across all merged repos (index 47)
        let mut asset_ids: Vec<String> = group_rows
            .iter()
            .flat_map(|r| {
                r.get(47)
                    .map(|s| s.split("; ").map(|p| p.to_string()).collect::<Vec<_>>())
                    .unwrap_or_default()
            })
            .filter(|s| !s.is_empty())
            .collect::<HashSet<_>>()
            .into_iter()
            .collect();
        asset_ids.sort();

        // Write merged values back into the representative row
        macro_rules! set {
            ($idx:expr, $val:expr) => {
                if let Some(v) = best.get_mut($idx) {
                    *v = $val;
                }
            };
        }
        set!(23, repos.join("; "));
        set!(24, tags.join("; "));
        set!(25, image_hash);
        set!(30, currently_in_use.to_string());
        set!(31, in_use_total.to_string());
        set!(32, res_ids.join("; "));
        set!(40, earliest_observed);
        set!(41, days_open);
        set!(42, total_images.to_string());
        set!(43, oldest_push);
        set!(44, newest_push);
        set!(46, version_varies);
        set!(47, asset_ids.join("; "));

        out.push(best);
    }
    out
}

// Pre-dedup filter: for each repo, keep only findings from the most recently
// pushed image hash.  Inspector2 reports findings for every image digest ever
// pushed to a repo, including old superseded versions.  For compliance reporting
// only the current (latest) image matters — old versions inflate the count with
// vulnerabilities that may already be resolved in newer pushes.
//
// Indices:  23 = Repository Name,  25 = Image Hash,  29 = Pushed At
pub(super) fn filter_latest_image_per_repo(mut rows: Vec<Vec<String>>) -> Vec<Vec<String>> {
    use std::collections::HashMap;

    // Step 1: for each repo, find the image hash with the latest Pushed At.
    let mut latest_hash: HashMap<String, String> = HashMap::new();
    let mut latest_push: HashMap<String, String> = HashMap::new();

    for row in &rows {
        let repo = row.get(23).map(|s| s.as_str()).unwrap_or("");
        let hash = row.get(25).map(|s| s.as_str()).unwrap_or("");
        let pushed = row.get(29).map(|s| s.as_str()).unwrap_or("");
        if repo.is_empty() || hash.is_empty() {
            continue;
        }

        let current_push = latest_push.get(repo).map(|s| s.as_str()).unwrap_or("");
        if pushed > current_push {
            latest_push.insert(repo.to_string(), pushed.to_string());
            latest_hash.insert(repo.to_string(), hash.to_string());
        }
    }

    // Step 2: discard rows from older image versions.
    rows.retain(|row| {
        let repo = row.get(23).map(|s| s.as_str()).unwrap_or("");
        let hash = row.get(25).map(|s| s.as_str()).unwrap_or("");

        if repo.is_empty() || hash.is_empty() {
            return true; // keep rows without repo/hash info
        }

        match latest_hash.get(repo) {
            Some(lh) => hash == lh,
            None => true, // keep if repo not tracked
        }
    });

    rows
}

// Dedup for InspectorEcrImagesCollector — same logic as dedup_ecr_rows but with
// indices matched to the leaner image-specific column layout.
//
// Column index map (base columns only, before annotations are appended):
//   0  Finding ARN       8  CVE ID        15 Package Name    16 Package Version
//  23  Repository Name  29  Pushed At     38 Status
pub(super) fn dedup_ecr_image_rows(rows: Vec<Vec<String>>) -> Vec<Vec<String>> {
    use std::collections::HashMap;

    let mut groups: HashMap<String, Vec<Vec<String>>> = HashMap::new();
    for row in rows {
        let cve_id = row.get(8).map(|s| s.as_str()).unwrap_or("");
        let pkg_name = row.get(15).map(|s| s.as_str()).unwrap_or("");
        let repo = row.get(23).map(|s| s.as_str()).unwrap_or("");
        let arn = row.get(0).map(|s| s.as_str()).unwrap_or("");

        let key = if !cve_id.is_empty() && !repo.is_empty() && !pkg_name.is_empty() {
            format!("repo_pkg:{}|{}|{}", cve_id, repo, pkg_name)
        } else if !cve_id.is_empty() && !pkg_name.is_empty() {
            format!("pkg:{}|{}", cve_id, pkg_name)
        } else if !cve_id.is_empty() {
            format!("cve:{}", cve_id)
        } else {
            format!("arn:{}", arn)
        };

        groups.entry(key).or_default().push(row);
    }

    let mut out = Vec::with_capacity(groups.len());
    for (_key, mut group_rows) in groups {
        group_rows.sort_by(|a, b| {
            let pa = a.get(29).map(|s| s.as_str()).unwrap_or("");
            let pb = b.get(29).map(|s| s.as_str()).unwrap_or("");
            pb.cmp(pa)
        });

        let image_count = group_rows.len().to_string();

        let pushed_dates: Vec<&str> = group_rows
            .iter()
            .map(|r| r.get(29).map(|s| s.as_str()).unwrap_or(""))
            .filter(|s| !s.is_empty())
            .collect();
        let newest_push = pushed_dates.first().copied().unwrap_or("").to_string();
        let oldest_push = pushed_dates.last().copied().unwrap_or("").to_string();

        let has_closed = if group_rows
            .iter()
            .any(|r| r.get(38).map(|s| s.as_str()).unwrap_or("") == "CLOSED")
        {
            "YES"
        } else {
            "NO"
        };

        let pkg_versions: std::collections::HashSet<&str> = group_rows
            .iter()
            .map(|r| r.get(16).map(|s| s.as_str()).unwrap_or(""))
            .filter(|s| !s.is_empty())
            .collect();
        let version_varies = if pkg_versions.len() > 1 { "YES" } else { "NO" };

        // Build Asset Identifier before consuming group_rows.
        // Format: registry/repo:tag per image (one entry per tag; hash prefix if no tag).
        let mut asset_ids: Vec<String> = group_rows
            .iter()
            .flat_map(|r| {
                let registry = r.get(26).map(|s| s.as_str()).unwrap_or("");
                let repo = r.get(23).map(|s| s.as_str()).unwrap_or("");
                let tags = r.get(24).map(|s| s.as_str()).unwrap_or("");
                let hash = r.get(25).map(|s| s.as_str()).unwrap_or("");
                if tags.is_empty() {
                    let h = hash.get(..19).unwrap_or(hash);
                    vec![format!("{}/{} ({})", registry, repo, h)]
                } else {
                    tags.split("; ")
                        .map(|t| format!("{}/{}:{}", registry, repo, t))
                        .collect()
                }
            })
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();
        asset_ids.sort();

        let mut best_row = group_rows.into_iter().next().unwrap();
        best_row.push(image_count);
        best_row.push(oldest_push);
        best_row.push(newest_push);
        best_row.push(has_closed.to_string());
        best_row.push(version_varies.to_string());
        best_row.push(asset_ids.join("; ")); // Asset Identifier (index 47)

        out.push(best_row);
    }
    out
}
