use anyhow::Result;
use async_trait::async_trait;
use aws_sdk_inspector2::types::{
    FilterCriteria, SortCriteria, SortField, SortOrder, StringComparison, StringFilter,
};
use aws_sdk_inspector2::Client as Inspector2Client;

use crate::evidence::CsvCollector;

fn secs_to_rfc3339(secs: i64) -> String {
    chrono::DateTime::<chrono::Utc>::from_timestamp(secs, 0)
        .map(|c| c.to_rfc3339())
        .unwrap_or_default()
}

pub struct InspectorEcrImagesCollector {
    client: Inspector2Client,
}

impl InspectorEcrImagesCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self {
            client: Inspector2Client::new(config),
        }
    }
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
fn rollup_ecr_by_cve(rows: Vec<Vec<String>>) -> Vec<Vec<String>> {
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
fn filter_latest_image_per_repo(mut rows: Vec<Vec<String>>) -> Vec<Vec<String>> {
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
fn dedup_ecr_image_rows(rows: Vec<Vec<String>>) -> Vec<Vec<String>> {
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

// Column layout for InspectorEcrImagesCollector (indices used by dedup above):
//  0  Finding ARN          8  CVE ID           13 CVSS Version
// 15  Package Name        16  Package Version   23 Repository Name
// 29  Pushed At           30  Currently In Use  38 Status
// 40  First Observed At   41  Days Open
#[async_trait]
impl CsvCollector for InspectorEcrImagesCollector {
    fn name(&self) -> &str {
        "Inspector2 ECR Image Findings"
    }
    fn filename_prefix(&self) -> &str {
        "Inspector2_ECR_Image_Findings"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            // Finding identity
            "Finding ARN", // 0
            "Account ID",  // 1
            "Type",        // 2
            "Title",       // 3
            "Description", // 4
            // Scoring
            "Severity",        // 5
            "Inspector Score", // 6
            "EPSS Score",      // 7
            // CVE / vulnerability
            "CVE ID",              // 8
            "CVE Source",          // 9
            "Vendor Severity",     // 10
            "CVSS Base Score",     // 11
            "CVSS Scoring Vector", // 12
            "CVSS Version",        // 13
            "Reference URLs",      // 14
            // Vulnerable package
            "Package Name",        // 15
            "Package Version",     // 16
            "Package Arch",        // 17
            "Package Manager",     // 18
            "Package File Path",   // 19
            "Fixed In Version",    // 20
            "Package Remediation", // 21
            "Source Layer Hash",   // 22
            // ECR container image
            "Repository Name",  // 23
            "Image Tags",       // 24
            "Image Hash",       // 25
            "Registry",         // 26
            "Architecture",     // 27
            "Platform",         // 28
            "Pushed At",        // 29
            "Currently In Use", // 30
            "In Use Count",     // 31
            // Resource
            "Resource ID",     // 32
            "Resource Region", // 33
            // Remediation
            "Remediation Text", // 34
            // Exploitability
            "Exploit Available",     // 35
            "Last Known Exploit At", // 36
            // FedRAMP evidence
            "Scan Type", // 37
            // Lifecycle
            "Status",            // 38
            "Fix Available",     // 39
            "First Observed At", // 40
            "Days Open",         // 41
            // Dedup annotations (appended by dedup_ecr_image_rows)
            "Affected Image Count",   // 42
            "Oldest Push Date",       // 43
            "Newest Push Date",       // 44
            "Has Closed Findings",    // 45
            "Package Version Varies", // 46
            "Asset Identifier",       // 47
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        match tokio::time::timeout(
            std::time::Duration::from_secs(30),
            self.client.get_configuration().send(),
        )
        .await
        {
            Err(_) => {
                eprintln!("  WARN: Inspector2 ECR Images get_configuration timed out — skipping");
                return Ok(Vec::new());
            }
            Ok(Err(e)) => {
                eprintln!("  WARN: Inspector2 ECR Images get_configuration (not enabled?): {e:#}");
                return Ok(Vec::new());
            }
            Ok(Ok(_)) => {}
        }

        const MAX_ROWS_PER_SEVERITY: usize = 10_000;
        const SEVERITY_LEVELS: [&str; 5] = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"];
        let _ = dates;

        let mut rows = Vec::new();

        for severity in SEVERITY_LEVELS {
            let resource_filter = StringFilter::builder()
                .comparison(StringComparison::Equals)
                .value("AWS_ECR_CONTAINER_IMAGE")
                .build()
                .expect("StringFilter is always valid");
            let severity_filter = StringFilter::builder()
                .comparison(StringComparison::Equals)
                .value(severity)
                .build()
                .expect("StringFilter is always valid");
            let status_filter = StringFilter::builder()
                .comparison(StringComparison::Equals)
                .value("ACTIVE")
                .build()
                .expect("StringFilter is always valid");
            let filter = FilterCriteria::builder()
                .resource_type(resource_filter)
                .severity(severity_filter)
                .finding_status(status_filter)
                .build();

            let mut next_token: Option<String> = None;
            let mut severity_count: usize = 0;

            loop {
                if severity_count >= MAX_ROWS_PER_SEVERITY {
                    eprintln!(
                        "  WARN: Inspector2 ECR Images list_findings ({severity}): hit {MAX_ROWS_PER_SEVERITY}-row cap, truncating"
                    );
                    break;
                }

                let mut req = self
                    .client
                    .list_findings()
                    .max_results(100)
                    .filter_criteria(filter.clone())
                    .sort_criteria(
                        SortCriteria::builder()
                            .field(SortField::InspectorScore)
                            .sort_order(SortOrder::Desc)
                            .build()
                            .expect("SortCriteria is always valid"),
                    );
                if let Some(ref t) = next_token {
                    req = req.next_token(t);
                }
                let resp = match req.send().await {
                    Ok(r) => r,
                    Err(e) => {
                        let msg = format!("{e:#}");
                        if msg.contains("AccessDeniedException")
                            || msg.contains("ResourceNotFoundException")
                            || msg.contains("ValidationException")
                            || msg.contains("BadRequestException")
                        {
                            eprintln!("  WARN: Inspector2 ECR Images list_findings ({severity}, not enabled?): {msg}");
                            return Ok(rows);
                        }
                        eprintln!(
                            "  WARN: Inspector2 ECR Images list_findings ({severity}): {msg}"
                        );
                        break;
                    }
                };

                for f in resp.findings() {
                    let resource_type_str = f
                        .resources()
                        .first()
                        .map(|r| r.r#type().as_str())
                        .unwrap_or("");
                    if resource_type_str != "AWS_ECR_CONTAINER_IMAGE" {
                        continue;
                    }
                    if f.status().as_str() == "CLOSED" {
                        continue;
                    }

                    // ── Finding identity ─────────────────────────────────────────
                    let finding_arn = f.finding_arn().to_string();
                    let account_id = f.aws_account_id().to_string();
                    let f_type = f.r#type().as_str().to_string();
                    let title = f.title().unwrap_or("").to_string();
                    let description = f
                        .description()
                        .to_string()
                        .replace(
                            "
", " ",
                        )
                        .replace("\r", " ");

                    // ── Scoring ──────────────────────────────────────────────────
                    let severity = f.severity().as_str().to_string();
                    let inspector_score = f
                        .inspector_score()
                        .map(|s| format!("{s:.2}"))
                        .unwrap_or_default();
                    let epss_score = f
                        .epss()
                        .map(|e| format!("{:.4}", e.score()))
                        .unwrap_or_default();

                    // ── Package vulnerability ────────────────────────────────────
                    let (
                        cve_id,
                        cve_source,
                        vendor_severity,
                        cvss_score,
                        cvss_vector,
                        reference_urls,
                        pkg_name,
                        pkg_version,
                        pkg_arch,
                        pkg_manager,
                        pkg_file_path,
                        fixed_in_version,
                        pkg_remediation,
                        src_layer_hash,
                    ) = if let Some(v) = f.package_vulnerability_details() {
                        let cve_id = v.vulnerability_id().to_string();
                        let source = v.source().to_string();
                        let vend_sev = v.vendor_severity().unwrap_or("").to_string();

                        let (cvss_s, cvss_v) = v
                            .cvss()
                            .iter()
                            .max_by(|a, b| {
                                a.base_score()
                                    .partial_cmp(&b.base_score())
                                    .unwrap_or(std::cmp::Ordering::Equal)
                            })
                            .map(|c| {
                                (
                                    format!("{:.1}", c.base_score()),
                                    c.scoring_vector().to_string(),
                                )
                            })
                            .unwrap_or_default();

                        let refs = v.reference_urls().join("; ");

                        let (pn, pv, pa, pm, pfp, fiv, pr, slh) = v
                            .vulnerable_packages()
                            .first()
                            .map(|p| {
                                (
                                    p.name().to_string(),
                                    p.version().to_string(),
                                    p.arch().unwrap_or("").to_string(),
                                    p.package_manager()
                                        .map(|m| m.as_str().to_string())
                                        .unwrap_or_default(),
                                    p.file_path().unwrap_or("").to_string(),
                                    p.fixed_in_version().unwrap_or("").to_string(),
                                    p.remediation().unwrap_or("").to_string(),
                                    p.source_layer_hash().unwrap_or("").to_string(),
                                )
                            })
                            .unwrap_or_default();

                        (
                            cve_id, source, vend_sev, cvss_s, cvss_v, refs, pn, pv, pa, pm, pfp,
                            fiv, pr, slh,
                        )
                    } else {
                        (
                            String::new(),
                            String::new(),
                            String::new(),
                            String::new(),
                            String::new(),
                            String::new(),
                            String::new(),
                            String::new(),
                            String::new(),
                            String::new(),
                            String::new(),
                            String::new(),
                            String::new(),
                            String::new(),
                        )
                    };

                    let cvss_version = if cvss_vector.starts_with("CVSS:3.1/") {
                        "v3.1".to_string()
                    } else if cvss_vector.starts_with("CVSS:3.0/") {
                        "v3.0".to_string()
                    } else if !cvss_vector.is_empty() {
                        "v2".to_string()
                    } else {
                        String::new()
                    };

                    // ── ECR container image details ──────────────────────────────
                    let (
                        repo_name,
                        image_tags,
                        image_hash,
                        registry,
                        architecture,
                        platform,
                        pushed_at,
                        in_use_count,
                    ) = f
                        .resources()
                        .first()
                        .and_then(|r| r.details())
                        .and_then(|d| d.aws_ecr_container_image())
                        .map(|ecr| {
                            (
                                ecr.repository_name().to_string(),
                                ecr.image_tags().join("; "),
                                ecr.image_hash().to_string(),
                                ecr.registry().to_string(),
                                ecr.architecture().unwrap_or("").to_string(),
                                ecr.platform().unwrap_or("").to_string(),
                                ecr.pushed_at()
                                    .map(|d| secs_to_rfc3339(d.secs()))
                                    .unwrap_or_default(),
                                ecr.in_use_count()
                                    .map(|n| n.to_string())
                                    .unwrap_or_default(),
                            )
                        })
                        .unwrap_or_default();

                    let currently_in_use = match in_use_count.trim() {
                        "" => "UNKNOWN".to_string(),
                        "0" => "NO".to_string(),
                        _ => "YES".to_string(),
                    };

                    // ── Resource ─────────────────────────────────────────────────
                    let (res_id, res_region) = f
                        .resources()
                        .first()
                        .map(|r| (r.id().to_string(), r.region().unwrap_or("").to_string()))
                        .unwrap_or_default();

                    // ── Remediation ──────────────────────────────────────────────
                    let rem_text = f
                        .remediation()
                        .and_then(|r| r.recommendation())
                        .and_then(|rec| rec.text())
                        .unwrap_or("")
                        .to_string();

                    // ── Exploitability ───────────────────────────────────────────
                    let exploit_available = f
                        .exploit_available()
                        .map(|e| e.as_str().to_string())
                        .unwrap_or_default();
                    let last_known_exploit = f
                        .exploitability_details()
                        .and_then(|e| e.last_known_exploit_at())
                        .map(|d| secs_to_rfc3339(d.secs()))
                        .unwrap_or_default();

                    // ── Lifecycle ────────────────────────────────────────────────
                    let status = f.status().as_str().to_string();
                    let fix_available = f
                        .fix_available()
                        .map(|x| x.as_str().to_string())
                        .unwrap_or_default();
                    let first_observed = secs_to_rfc3339(f.first_observed_at().secs());

                    let days_open = chrono::DateTime::parse_from_rfc3339(&first_observed)
                        .map(|dt| {
                            let diff = chrono::Utc::now()
                                .signed_duration_since(dt.with_timezone(&chrono::Utc));
                            diff.num_days().to_string()
                        })
                        .unwrap_or_default();

                    rows.push(vec![
                        finding_arn,
                        account_id,
                        f_type,
                        title,
                        description,
                        severity,
                        inspector_score,
                        epss_score,
                        cve_id,
                        cve_source,
                        vendor_severity,
                        cvss_score,
                        cvss_vector,
                        cvss_version,
                        reference_urls,
                        pkg_name,
                        pkg_version,
                        pkg_arch,
                        pkg_manager,
                        pkg_file_path,
                        fixed_in_version,
                        pkg_remediation,
                        src_layer_hash,
                        repo_name,
                        image_tags,
                        image_hash,
                        registry,
                        architecture,
                        platform,
                        pushed_at,
                        currently_in_use,
                        in_use_count,
                        res_id,
                        res_region,
                        rem_text,
                        exploit_available,
                        last_known_exploit,
                        "Enhanced".to_string(),
                        status,
                        fix_available,
                        first_observed,
                        days_open,
                    ]);
                    severity_count += 1;
                }

                next_token = resp.next_token().map(|s| s.to_string());
                if next_token.is_none() {
                    break;
                }
            }

            if severity_count > 0 {
                eprintln!("  Inspector2 ECR Images ({severity}): {severity_count} findings");
            }
        }

        let before = rows.len();
        let rows = filter_latest_image_per_repo(rows);
        let after_latest = rows.len();
        let rows = dedup_ecr_image_rows(rows);
        let after_dedup = rows.len();
        let rows = rollup_ecr_by_cve(rows);
        let after_rollup = rows.len();
        if before > after_rollup {
            eprintln!(
                "  Inspector2 ECR Images: {before} → {after_latest} (latest image) → {after_dedup} (image dedup) → {after_rollup} (cross-repo CVE rollup)",
            );
        }

        Ok(rows)
    }
}
