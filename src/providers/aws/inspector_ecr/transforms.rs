pub(super) fn secs_to_rfc3339(secs: i64) -> String {
    chrono::DateTime::<chrono::Utc>::from_timestamp(secs, 0)
        .map(|c| c.to_rfc3339())
        .unwrap_or_default()
}

/// Appends the per-image annotation columns (42–48) to a 42-column finding row.
pub(super) fn annotate_inventory_row(
    mut row: Vec<String>,
    asset_id: &str,
    inventory_file: &str,
) -> Vec<String> {
    let pushed = row.get(29).cloned().unwrap_or_default();
    row.push("1".to_string()); // 42 Affected Image Count
    row.push(pushed.clone()); // 43 Oldest Push Date
    row.push(pushed); // 44 Newest Push Date
    row.push("NO".to_string()); // 45 Has Closed Findings (ACTIVE only)
    row.push("NO".to_string()); // 46 Package Version Varies
    row.push(asset_id.to_string()); // 47 Asset Identifier
    row.push(inventory_file.to_string()); // 48 Inventory File
    row
}

/// Per-platform digests inside an image index manifest; attestation manifests
/// (`os: unknown`) are skipped.
pub(super) fn index_child_digests(manifest_json: &str) -> Vec<String> {
    #[derive(serde::Deserialize)]
    struct Index {
        #[serde(default)]
        manifests: Vec<Child>,
    }
    #[derive(serde::Deserialize)]
    struct Child {
        digest: String,
        platform: Option<Platform>,
    }
    #[derive(serde::Deserialize)]
    struct Platform {
        #[serde(default)]
        os: String,
    }
    serde_json::from_str::<Index>(manifest_json)
        .map(|i| {
            i.manifests
                .into_iter()
                .filter(|c| c.platform.as_ref().is_none_or(|p| p.os != "unknown"))
                .map(|c| c.digest)
                .collect()
        })
        .unwrap_or_default()
}

// Second-pass cross-repository rollup — FedRAMP requires one row per CVE with
// all affected assets listed, not one row per (CVE + repository).
//
// Groups by (CVE ID + Package Name) across all repos. The highest Inspector
// Score row is kept as representative; all other per-repo fields are merged
// into it. Multi-value cells are "; "-separated on one line so every finding stays one CSV row.
//
// Indices reference the post-annotation column layout:
//   6  Inspector Score   8  CVE ID        15 Package Name    16 Package Version
//  23  Repository Name  24  Image Tags    25  Image Hash     30 Currently In Use
//  31  In Use Count     32  Resource ID   40  First Observed At  41 Days Open
//  42  Affected Image Count  43 Oldest Push Date  44 Newest Push Date
//  46  Package Version Varies  47 Asset Identifier
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
            format!("arn:{}", row.first().map(|s| s.as_str()).unwrap_or(""))
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

        let mut hashes: Vec<String> = group_rows
            .iter()
            .flat_map(|r| {
                r.get(25)
                    .map(|s| s.split("; ").map(str::to_string).collect::<Vec<_>>())
                    .unwrap_or_default()
            })
            .filter(|s| !s.is_empty())
            .collect::<HashSet<_>>()
            .into_iter()
            .collect();
        hashes.sort();

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
        set!(25, hashes.join("; "));
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

#[cfg(test)]
mod tests {
    use super::*;

    const IDX_ASSET_ID: usize = 47;
    const IDX_INVENTORY_FILE: usize = 48;

    fn base_row(
        cve: &str,
        pkg: &str,
        repo: &str,
        hash: &str,
        res_id: &str,
        score: &str,
    ) -> Vec<String> {
        let mut r = vec![String::new(); 42];
        r[0] = format!("arn:finding:{repo}:{cve}");
        r[6] = score.to_string();
        r[8] = cve.to_string();
        r[15] = pkg.to_string();
        r[16] = "1.0".to_string();
        r[23] = repo.to_string();
        r[24] = "v1".to_string();
        r[25] = hash.to_string();
        r[29] = "2026-09-01T00:00:00+00:00".to_string();
        r[30] = "NO".to_string();
        r[31] = "0".to_string();
        r[32] = res_id.to_string();
        r[40] = "2026-08-01T00:00:00+00:00".to_string();
        r
    }

    #[test]
    fn annotate_appends_inventory_columns() {
        let row = annotate_inventory_row(
            base_row("CVE-1", "openssl", "app", "sha256:a", "arn:a", "7"),
            "asset-app",
            "AWS_Inventory-x.csv",
        );
        assert_eq!(row.len(), 49);
        assert_eq!(row[42], "1");
        assert_eq!(row[43], row[29]);
        assert_eq!(row[IDX_ASSET_ID], "asset-app");
        assert_eq!(row[IDX_INVENTORY_FILE], "AWS_Inventory-x.csv");
    }

    #[test]
    fn rollup_groups_same_cve_package_on_one_line_and_keeps_different_cves_apart() {
        let rows = vec![
            annotate_inventory_row(
                base_row("CVE-1", "openssl", "web", "sha256:w", "arn:w", "5"),
                "asset-web",
                "inv.csv",
            ),
            annotate_inventory_row(
                base_row("CVE-1", "openssl", "api", "sha256:p", "arn:p", "9"),
                "asset-api",
                "inv.csv",
            ),
            annotate_inventory_row(
                base_row("CVE-2", "openssl", "api", "sha256:p", "arn:p", "4"),
                "asset-api",
                "inv.csv",
            ),
        ];
        let mut out = rollup_ecr_by_cve(rows);
        out.sort_by(|a, b| a[8].cmp(&b[8]));
        assert_eq!(out.len(), 2);
        assert_eq!(out[0][8], "CVE-1");
        assert_eq!(out[0][IDX_ASSET_ID], "asset-api; asset-web");
        assert_eq!(out[0][23], "api; web");
        assert_eq!(out[0][25], "sha256:p; sha256:w");
        assert_eq!(out[0][32], "arn:p; arn:w");
        assert_eq!(out[0][42], "2");
        assert_eq!(out[1][8], "CVE-2");
        assert_eq!(out[1][IDX_ASSET_ID], "asset-api");
    }

    #[test]
    fn index_children_skip_attestations() {
        let m = r#"{"manifests":[
            {"digest":"sha256:amd","platform":{"os":"linux","architecture":"amd64"}},
            {"digest":"sha256:att","platform":{"os":"unknown","architecture":"unknown"}}]}"#;
        assert_eq!(index_child_digests(m), ["sha256:amd"]);
        assert!(index_child_digests("not json").is_empty());
    }
}
