use anyhow::Result;
use async_trait::async_trait;
use aws_sdk_inspector2::Client as Inspector2Client;
use aws_sdk_inspector2::primitives::DateTime as InspectorDateTime;
use aws_sdk_inspector2::types::{DateFilter, FilterCriteria, SortCriteria, SortField, SortOrder};

use crate::evidence::CsvCollector;

fn secs_to_rfc3339(secs: i64) -> String {
    chrono::DateTime::<chrono::Utc>::from_timestamp(secs, 0)
        .map(|c| c.to_rfc3339())
        .unwrap_or_default()
}

// Deduplicate ECR findings by (CVE ID, Repository Name, Package Name).
//
// Within each group the row with the newest Pushed At (col 33) is kept as the
// representative finding — it reflects the current state of the repo. Five
// annotation columns are appended to that row summarising the group:
//
//   Affected Image Count  — how many distinct images had this finding
//   Oldest Push Date      — earliest Pushed At across the group
//   Newest Push Date      — latest Pushed At across the group
//   Has Closed Findings   — YES if any image in the group has status CLOSED
//   Package Version Varies — YES if the vulnerable package version differs
//                            across images (vuln persists through upgrades)
//
// Fallback key when fields are empty:
//   1. CVE ID + Repository Name + Package Name  (primary)
//   2. CVE ID + Package Name                    (no repo)
//   3. CVE ID only                              (no package)
//   4. Finding ARN                              (non-CVE)
//
// RFC3339 date strings compare correctly as plain strings, so string max/min
// correctly identifies newest/oldest dates.
fn dedup_ecr_rows(rows: Vec<Vec<String>>) -> Vec<Vec<String>> {
    use std::collections::HashMap;

    // Group rows by dedup key
    let mut groups: HashMap<String, Vec<Vec<String>>> = HashMap::new();
    for row in rows {
        let cve_id   = row.get(8).map(|s| s.as_str()).unwrap_or("");
        let pkg_name = row.get(18).map(|s| s.as_str()).unwrap_or("");
        let repo     = row.get(26).map(|s| s.as_str()).unwrap_or("");
        let arn      = row.get(0).map(|s| s.as_str()).unwrap_or("");

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
        // Sort descending by Pushed At so index 0 is the newest image
        group_rows.sort_by(|a, b| {
            let pa = a.get(33).map(|s| s.as_str()).unwrap_or("");
            let pb = b.get(33).map(|s| s.as_str()).unwrap_or("");
            pb.cmp(pa)
        });

        // Collect group-level metadata
        let image_count = group_rows.len().to_string();

        let pushed_dates: Vec<&str> = group_rows.iter()
            .map(|r| r.get(33).map(|s| s.as_str()).unwrap_or(""))
            .filter(|s| !s.is_empty())
            .collect();
        // After sort-desc: first = newest, last = oldest
        let newest_push = pushed_dates.first().copied().unwrap_or("").to_string();
        let oldest_push = pushed_dates.last().copied().unwrap_or("").to_string();

        let has_closed = if group_rows.iter()
            .any(|r| r.get(43).map(|s| s.as_str()).unwrap_or("") == "CLOSED")
        { "YES" } else { "NO" };

        let pkg_versions: std::collections::HashSet<&str> = group_rows.iter()
            .map(|r| r.get(19).map(|s| s.as_str()).unwrap_or(""))
            .filter(|s| !s.is_empty())
            .collect();
        let version_varies = if pkg_versions.len() > 1 { "YES" } else { "NO" };

        // Take the best row (newest Pushed At) and append annotation columns
        let mut best_row = group_rows.into_iter().next().unwrap();
        best_row.push(image_count);
        best_row.push(oldest_push);
        best_row.push(newest_push);
        best_row.push(has_closed.to_string());
        best_row.push(version_varies.to_string());

        out.push(best_row);
    }
    out
}

pub struct InspectorEcrCollector {
    client: Inspector2Client,
}

impl InspectorEcrCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self { client: Inspector2Client::new(config) }
    }
}

#[async_trait]
impl CsvCollector for InspectorEcrCollector {
    fn name(&self) -> &str { "Inspector2 ECR Findings" }
    fn filename_prefix(&self) -> &str { "Inspector2_ECR_Findings" }
    fn headers(&self) -> &'static [&'static str] {
        &[
            // Finding identity
            "Finding ARN",
            "Account ID",
            "Type",
            "Title",
            "Description",
            // Scoring
            "Severity",
            "Inspector Score",
            "EPSS Score",
            // CVE / package vulnerability
            "CVE ID",
            "CVE Source",
            "CVE Source URL",
            "Vendor Severity",
            "Vendor Created At",
            "Vendor Updated At",
            "CVSS Base Score",
            "CVSS Scoring Vector",
            "Related Vulnerabilities",
            "Reference URLs",
            // Vulnerable package (first affected)
            "Package Name",
            "Package Version",
            "Package Arch",
            "Package Manager",
            "Package File Path",
            "Fixed In Version",
            "Package Remediation",
            "Source Layer Hash",
            // ECR container image resource details
            "Repository Name",
            "Image Tags",
            "Image Hash",
            "Registry",
            "Architecture",
            "Platform",
            "Author",
            "Pushed At",
            "Last In Use At",
            "In Use Count",
            // Resource (fallback / additional)
            "Resource ID",
            "Resource Type",
            "Resource Region",
            // Remediation guidance
            "Remediation Text",
            "Remediation URL",
            // Exploitability
            "Exploit Available",
            "Last Known Exploit At",
            // Lifecycle
            "Status",
            "Fix Available",
            "First Observed At",
            "Last Observed At",
            "Updated At",
            // Dedup annotations (appended by dedup_ecr_rows)
            "Affected Image Count",
            "Oldest Push Date",
            "Newest Push Date",
            "Has Closed Findings",
            "Package Version Varies",
        ]
    }

    async fn collect_rows(&self, _account_id: &str, _region: &str, dates: Option<(i64, i64)>) -> Result<Vec<Vec<String>>> {
        // Pre-check: bail immediately if Inspector2 is not enabled in this region.
        match tokio::time::timeout(
            std::time::Duration::from_secs(30),
            self.client.get_configuration().send(),
        )
        .await
        {
            Err(_) => {
                eprintln!("  WARN: Inspector2 ECR get_configuration timed out — skipping");
                return Ok(Vec::new());
            }
            Ok(Err(e)) => {
                eprintln!("  WARN: Inspector2 ECR get_configuration (not enabled?): {e:#}");
                return Ok(Vec::new());
            }
            Ok(Ok(_)) => {}
        }

        // Cap at 10 000 rows to avoid unbounded pagination.
        const MAX_ROWS: usize = 10_000;

        let mut rows = Vec::new();
        let mut next_token: Option<String> = None;

        // !! DATE FILTER: MUST use first_observed_at — do NOT use last_observed_at or updated_at !!
        // See inspector.rs for full rationale. Short version: last_observed_at and updated_at
        // are refreshed on every rescan (always today's date), making them useless for
        // period scoping. first_observed_at is immutable after finding creation.
        let filter = dates.map(|(start, end)| {
            FilterCriteria::builder()
                .first_observed_at(
                    DateFilter::builder()
                        .start_inclusive(InspectorDateTime::from_secs(start))
                        .end_inclusive(InspectorDateTime::from_secs(end))
                        .build()
                )
                .build()
        });

        // NOTE: We intentionally do NOT apply a server-side resource_type filter.
        // Inspector2's FilterCriteria resource_type field can silently drop findings
        // if the API interprets the filter differently than expected (e.g. strict
        // mode vs. partial match).  Instead we fetch all findings and post-filter
        // in Rust, which is guaranteed to include both AWS_ECR_CONTAINER_IMAGE and
        // AWS_ECR_REPOSITORY resource types.
        loop {
            if rows.len() >= MAX_ROWS {
                eprintln!("  WARN: Inspector2 ECR list_findings: hit {MAX_ROWS}-row cap, truncating");
                break;
            }

            let mut req = self.client
                .list_findings()
                .max_results(100)
                .sort_criteria(
                    SortCriteria::builder()
                        .field(SortField::InspectorScore)
                        .sort_order(SortOrder::Desc)
                        .build()
                        .expect("SortCriteria is always valid")
                );
            if let Some(ref f) = filter {
                req = req.filter_criteria(f.clone());
            }
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
                        eprintln!("  WARN: Inspector2 ECR list_findings (not enabled?): {msg}");
                        return Ok(rows);
                    }
                    eprintln!("  WARN: Inspector2 ECR list_findings: {msg}");
                    break;
                }
            };

            for f in resp.findings() {
                // Post-filter: only ECR resource types
                let resource_type_str = f.resources()
                    .first()
                    .map(|r| r.r#type().as_str())
                    .unwrap_or("");
                if !resource_type_str.contains("ECR") {
                    continue;
                }

                // ── Finding identity ─────────────────────────────────────────
                let finding_arn = f.finding_arn().to_string();
                let account_id  = f.aws_account_id().to_string();
                let f_type      = f.r#type().as_str().to_string();
                let title       = f.title().unwrap_or("").to_string();
                let description = f.description().to_string();

                // ── Scoring ──────────────────────────────────────────────────
                let severity        = f.severity().as_str().to_string();
                let inspector_score = f.inspector_score()
                    .map(|s| format!("{s:.2}"))
                    .unwrap_or_default();
                let epss_score = f.epss()
                    .map(|e| format!("{:.4}", e.score()))
                    .unwrap_or_default();

                // ── Package vulnerability ────────────────────────────────────
                let (
                    cve_id, cve_source, cve_source_url,
                    vendor_severity, vendor_created_at, vendor_updated_at,
                    cvss_score, cvss_vector,
                    related_vulns, reference_urls,
                    pkg_name, pkg_version, pkg_arch, pkg_manager,
                    pkg_file_path, fixed_in_version, pkg_remediation, src_layer_hash,
                ) = if let Some(v) = f.package_vulnerability_details() {
                    let cve_id     = v.vulnerability_id().to_string();
                    let source     = v.source().to_string();
                    let source_url = v.source_url().unwrap_or("").to_string();
                    let vend_sev   = v.vendor_severity().unwrap_or("").to_string();
                    let vend_cre   = v.vendor_created_at().map(|d| secs_to_rfc3339(d.secs())).unwrap_or_default();
                    let vend_upd   = v.vendor_updated_at().map(|d| secs_to_rfc3339(d.secs())).unwrap_or_default();

                    let (cvss_s, cvss_v) = v.cvss().iter()
                        .max_by(|a, b| a.base_score().partial_cmp(&b.base_score()).unwrap_or(std::cmp::Ordering::Equal))
                        .map(|c| (format!("{:.1}", c.base_score()), c.scoring_vector().to_string()))
                        .unwrap_or_default();

                    let related = v.related_vulnerabilities().join("; ");
                    let refs    = v.reference_urls().join("; ");

                    let (pn, pv, pa, pm, pfp, fiv, pr, slh) =
                        v.vulnerable_packages().first()
                        .map(|p| (
                            p.name().to_string(),
                            p.version().to_string(),
                            p.arch().unwrap_or("").to_string(),
                            p.package_manager().map(|m| m.as_str().to_string()).unwrap_or_default(),
                            p.file_path().unwrap_or("").to_string(),
                            p.fixed_in_version().unwrap_or("").to_string(),
                            p.remediation().unwrap_or("").to_string(),
                            p.source_layer_hash().unwrap_or("").to_string(),
                        ))
                        .unwrap_or_default();

                    (cve_id, source, source_url, vend_sev, vend_cre, vend_upd,
                     cvss_s, cvss_v, related, refs, pn, pv, pa, pm, pfp, fiv, pr, slh)
                } else {
                    (
                        String::new(), String::new(), String::new(),
                        String::new(), String::new(), String::new(),
                        String::new(), String::new(), String::new(), String::new(),
                        String::new(), String::new(), String::new(), String::new(),
                        String::new(), String::new(), String::new(), String::new(),
                    )
                };

                // ── ECR container image details ──────────────────────────────
                let (
                    repo_name, image_tags, image_hash, registry,
                    architecture, platform, author,
                    pushed_at, last_in_use_at, in_use_count,
                ) = f.resources().first()
                    .and_then(|r| r.details())
                    .and_then(|d| d.aws_ecr_container_image())
                    .map(|ecr| (
                        ecr.repository_name().to_string(),
                        ecr.image_tags().join("; "),
                        ecr.image_hash().to_string(),
                        ecr.registry().to_string(),
                        ecr.architecture().unwrap_or("").to_string(),
                        ecr.platform().unwrap_or("").to_string(),
                        ecr.author().unwrap_or("").to_string(),
                        ecr.pushed_at().map(|d| secs_to_rfc3339(d.secs())).unwrap_or_default(),
                        ecr.last_in_use_at().map(|d| secs_to_rfc3339(d.secs())).unwrap_or_default(),
                        ecr.in_use_count().map(|n| n.to_string()).unwrap_or_default(),
                    ))
                    .unwrap_or_default();

                // ── Resource fallback ────────────────────────────────────────
                let (res_id, res_type, res_region) = f.resources().first()
                    .map(|r| (
                        r.id().to_string(),
                        r.r#type().as_str().to_string(),
                        r.region().unwrap_or("").to_string(),
                    ))
                    .unwrap_or_default();

                // ── Remediation ──────────────────────────────────────────────
                let (rem_text, rem_url) = f.remediation()
                    .and_then(|r| r.recommendation())
                    .map(|rec| (
                        rec.text().unwrap_or("").to_string(),
                        rec.url().unwrap_or("").to_string(),
                    ))
                    .unwrap_or_default();

                // ── Exploitability ───────────────────────────────────────────
                let exploit_available  = f.exploit_available()
                    .map(|e| e.as_str().to_string())
                    .unwrap_or_default();
                let last_known_exploit = f.exploitability_details()
                    .and_then(|e| e.last_known_exploit_at())
                    .map(|d| secs_to_rfc3339(d.secs()))
                    .unwrap_or_default();

                // ── Lifecycle ────────────────────────────────────────────────
                let status         = f.status().as_str().to_string();
                let fix_available  = f.fix_available().map(|x| x.as_str().to_string()).unwrap_or_default();
                let first_observed = secs_to_rfc3339(f.first_observed_at().secs());
                let last_observed  = secs_to_rfc3339(f.last_observed_at().secs());
                let updated_at     = f.updated_at().map(|d| secs_to_rfc3339(d.secs())).unwrap_or_default();

                rows.push(vec![
                    finding_arn, account_id, f_type, title, description,
                    severity, inspector_score, epss_score,
                    cve_id, cve_source, cve_source_url,
                    vendor_severity, vendor_created_at, vendor_updated_at,
                    cvss_score, cvss_vector, related_vulns, reference_urls,
                    pkg_name, pkg_version, pkg_arch, pkg_manager,
                    pkg_file_path, fixed_in_version, pkg_remediation, src_layer_hash,
                    repo_name, image_tags, image_hash, registry,
                    architecture, platform, author,
                    pushed_at, last_in_use_at, in_use_count,
                    res_id, res_type, res_region,
                    rem_text, rem_url,
                    exploit_available, last_known_exploit,
                    status, fix_available, first_observed, last_observed, updated_at,
                ]);
            }

            next_token = resp.next_token().map(|s| s.to_string());
            if next_token.is_none() { break; }
        }

        let before = rows.len();
        let rows = dedup_ecr_rows(rows);
        let removed = before - rows.len();
        if removed > 0 {
            eprintln!("  Inspector2 ECR: removed {removed} duplicate findings ({before} → {})", rows.len());
        }

        Ok(rows)
    }
}
