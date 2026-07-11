mod transforms;
use transforms::{
    dedup_ecr_image_rows, filter_latest_image_per_repo, rollup_ecr_by_cve, secs_to_rfc3339,
};

use anyhow::Result;
use async_trait::async_trait;
use aws_sdk_inspector2::primitives::DateTime as InspectorDateTime;
use aws_sdk_inspector2::types::{
    DateFilter, FilterCriteria, SortCriteria, SortField, SortOrder, StringComparison, StringFilter,
};
use aws_sdk_inspector2::Client as Inspector2Client;

use crate::evidence::CsvCollector;

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

            let mut filter_builder = FilterCriteria::builder()
                .resource_type(resource_filter)
                .severity(severity_filter)
                .finding_status(status_filter);

            // !! DATE FILTER: MUST use first_observed_at — do NOT use last_observed_at or updated_at !!
            // Inspector2 rescans continuously; last_observed_at/updated_at are stamped with today's
            // date on every rescan and so return the full active set regardless of window.
            // first_observed_at is set ONCE at finding creation and is the only reliable scoping field.
            if let Some((start, end)) = dates {
                filter_builder = filter_builder.first_observed_at(
                    DateFilter::builder()
                        .start_inclusive(InspectorDateTime::from_secs(start))
                        .end_inclusive(InspectorDateTime::from_secs(end))
                        .build(),
                );
            }
            let filter = filter_builder.build();

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
