use anyhow::Result;
use async_trait::async_trait;
use aws_sdk_inspector2::Client as Inspector2Client;
use aws_sdk_inspector2::primitives::DateTime as InspectorDateTime;
use aws_sdk_inspector2::types::{DateFilter, FilterCriteria, StringComparison, StringFilter};

use crate::evidence::CsvCollector;

fn secs_to_rfc3339(secs: i64) -> String {
    chrono::DateTime::<chrono::Utc>::from_timestamp(secs, 0)
        .map(|c| c.to_rfc3339())
        .unwrap_or_default()
}

pub struct InspectorCollector {
    client: Inspector2Client,
}

impl InspectorCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self { client: Inspector2Client::new(config) }
    }
}

#[async_trait]
impl CsvCollector for InspectorCollector {
    fn name(&self) -> &str { "Inspector2 Findings" }
    fn filename_prefix(&self) -> &str { "Inspector2_Findings" }
    fn headers(&self) -> &'static [&'static str] {
        &[
            // Finding identity & timing
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
            // Resource
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
        ]
    }

    async fn collect_rows(&self, _account_id: &str, _region: &str, dates: Option<(i64, i64)>) -> Result<Vec<Vec<String>>> {
        // Pre-check: verify Inspector2 is enabled in this region before listing
        // findings.  list_findings can hang indefinitely when Inspector2 is not
        // activated, so we bail early if get_configuration indicates it is off.
        match tokio::time::timeout(
            std::time::Duration::from_secs(30),
            self.client.get_configuration().send(),
        )
        .await
        {
            // Timeout or any error → Inspector2 not reachable / not enabled.
            Err(_timeout) => {
                eprintln!("  WARN: Inspector2 get_configuration timed out — skipping findings");
                return Ok(Vec::new());
            }
            Ok(Err(e)) => {
                eprintln!("  WARN: Inspector2 get_configuration (not enabled?): {e:#}");
                return Ok(Vec::new());
            }
            Ok(Ok(_)) => {} // Inspector2 is enabled — proceed.
        }

        // Cap findings at 10 000 rows so a region with millions of findings
        // doesn't run indefinitely.  Compliance reviews rarely need every
        // individual finding; the most recent/severe ones are captured first.
        const MAX_ROWS: usize = 10_000;

        let mut rows = Vec::new();
        let mut next_token: Option<String> = None;

        // Always exclude ECR resource types — those are covered by InspectorEcrCollector.
        // Without this, ECR findings dominate the result set (often 95%+) and push out
        // Lambda/EC2 findings before the row cap is reached.
        let ecr_exclusion_1 = StringFilter::builder()
            .comparison(StringComparison::NotEquals)
            .value("AWS_ECR_CONTAINER_IMAGE")
            .build()
            .expect("StringFilter is always valid");
        let ecr_exclusion_2 = StringFilter::builder()
            .comparison(StringComparison::NotEquals)
            .value("AWS_ECR_REPOSITORY")
            .build()
            .expect("StringFilter is always valid");

        let mut filter_builder = FilterCriteria::builder()
            .resource_type(ecr_exclusion_1)
            .resource_type(ecr_exclusion_2);

        // Apply audit-period overlap filter when a date range is provided.
        //
        // A finding "overlaps" the audit period when:
        //   first_observed_at <= end_date  (was present before or during the period)
        //   last_observed_at  >= start_date (was still active at or after period start)
        //
        // This returns every finding that was active at any point during the window —
        // including long-running vulnerabilities first seen before the period and
        // new ones still open at the end.  Using only updated_at would miss stable
        // findings that Inspector2 confirmed but didn't re-score during the window.
        if let Some((start, end)) = dates {
            filter_builder = filter_builder
                .last_observed_at(
                    DateFilter::builder()
                        .start_inclusive(InspectorDateTime::from_secs(start))
                        .build()
                )
                .first_observed_at(
                    DateFilter::builder()
                        .end_inclusive(InspectorDateTime::from_secs(end))
                        .build()
                );
        }
        let filter = filter_builder.build();

        loop {
            if rows.len() >= MAX_ROWS {
                eprintln!("  WARN: Inspector2 list_findings: hit {MAX_ROWS}-row cap, truncating");
                break;
            }

            let mut req = self.client
                .list_findings()
                .max_results(100)
                .filter_criteria(filter.clone());
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
                        eprintln!("  WARN: Inspector2 list_findings (not enabled?): {msg}");
                        return Ok(rows);
                    }
                    eprintln!("  WARN: Inspector2 list_findings: {msg}");
                    break;
                }
            };

            for f in resp.findings() {
                // ── Finding identity ──────────────────────────────────────
                let finding_arn = f.finding_arn().to_string();
                let account_id  = f.aws_account_id().to_string();
                let f_type      = f.r#type().as_str().to_string();
                let title       = f.title().unwrap_or("").to_string();
                let description = f.description().to_string();

                // ── Scoring ───────────────────────────────────────────────
                let severity        = f.severity().as_str().to_string();
                let inspector_score = f.inspector_score()
                    .map(|s| format!("{s:.2}"))
                    .unwrap_or_default();
                let epss_score = f.epss()
                    .map(|e| format!("{:.4}", e.score()))
                    .unwrap_or_default();

                // ── Package vulnerability ─────────────────────────────────
                let (
                    cve_id, cve_source, cve_source_url,
                    vendor_severity, vendor_created_at, vendor_updated_at,
                    cvss_score, cvss_vector,
                    related_vulns, reference_urls,
                    pkg_name, pkg_version, pkg_arch, pkg_manager,
                    pkg_file_path, fixed_in_version, pkg_remediation, src_layer_hash,
                ) = if let Some(v) = f.package_vulnerability_details() {
                    let cve_id      = v.vulnerability_id().to_string();
                    let source      = v.source().to_string();
                    let source_url  = v.source_url().unwrap_or("").to_string();
                    let vend_sev    = v.vendor_severity().unwrap_or("").to_string();
                    let vend_cre    = v.vendor_created_at().map(|d| secs_to_rfc3339(d.secs())).unwrap_or_default();
                    let vend_upd    = v.vendor_updated_at().map(|d| secs_to_rfc3339(d.secs())).unwrap_or_default();

                    // Highest CVSS score (prefer v3 by taking max base_score)
                    let (cvss_s, cvss_v) = v.cvss().iter()
                        .max_by(|a, b| a.base_score().partial_cmp(&b.base_score()).unwrap_or(std::cmp::Ordering::Equal))
                        .map(|c| (format!("{:.1}", c.base_score()), c.scoring_vector().to_string()))
                        .unwrap_or_default();

                    let related = v.related_vulnerabilities().join("; ");
                    let refs    = v.reference_urls().join("; ");

                    // First affected package
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

                // ── Resource (first) ──────────────────────────────────────
                let (res_id, res_type, res_region) = f.resources().first()
                    .map(|r| (
                        r.id().to_string(),
                        r.r#type().as_str().to_string(),
                        r.region().unwrap_or("").to_string(),
                    ))
                    .unwrap_or_default();

                // ── Remediation ───────────────────────────────────────────
                let (rem_text, rem_url) = f.remediation()
                    .and_then(|r| r.recommendation())
                    .map(|rec| (
                        rec.text().unwrap_or("").to_string(),
                        rec.url().unwrap_or("").to_string(),
                    ))
                    .unwrap_or_default();

                // ── Exploitability ────────────────────────────────────────
                let exploit_available   = f.exploit_available()
                    .map(|e| e.as_str().to_string())
                    .unwrap_or_default();
                let last_known_exploit  = f.exploitability_details()
                    .and_then(|e| e.last_known_exploit_at())
                    .map(|d| secs_to_rfc3339(d.secs()))
                    .unwrap_or_default();

                // ── Lifecycle ─────────────────────────────────────────────
                let status          = f.status().as_str().to_string();
                let fix_available   = f.fix_available()
                    .map(|x| x.as_str().to_string())
                    .unwrap_or_default();
                let first_observed  = secs_to_rfc3339(f.first_observed_at().secs());
                let last_observed   = secs_to_rfc3339(f.last_observed_at().secs());
                let updated_at      = f.updated_at().map(|d| secs_to_rfc3339(d.secs())).unwrap_or_default();

                rows.push(vec![
                    finding_arn, account_id, f_type, title, description,
                    severity, inspector_score, epss_score,
                    cve_id, cve_source, cve_source_url,
                    vendor_severity, vendor_created_at, vendor_updated_at,
                    cvss_score, cvss_vector, related_vulns, reference_urls,
                    pkg_name, pkg_version, pkg_arch, pkg_manager,
                    pkg_file_path, fixed_in_version, pkg_remediation, src_layer_hash,
                    res_id, res_type, res_region,
                    rem_text, rem_url,
                    exploit_available, last_known_exploit,
                    status, fix_available, first_observed, last_observed, updated_at,
                ]);
            }

            next_token = resp.next_token().map(|s| s.to_string());
            if next_token.is_none() { break; }
        }

        Ok(rows)
    }
}
