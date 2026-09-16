mod transforms;
use transforms::{annotate_inventory_row, index_child_digests, rollup_ecr_by_cve, secs_to_rfc3339};

use anyhow::{Context, Result};
use async_trait::async_trait;
use aws_sdk_inspector2::types::{FilterCriteria, StringComparison, StringFilter};
use aws_sdk_inspector2::Client as Inspector2Client;

use crate::evidence::CsvCollector;

pub struct InspectorEcrImagesCollector {
    client: Inspector2Client,
    ecr: aws_sdk_ecr::Client,
}

impl InspectorEcrImagesCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self {
            client: Inspector2Client::new(config),
            ecr: aws_sdk_ecr::Client::new(config),
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
            "Inventory File",         // 48
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        region: &str,
        _dates: Option<(i64, i64)>,
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

        let inventory =
            match crate::inventory_digests::load_latest(std::path::Path::new("inventory")) {
                Ok(inv) => inv,
                Err(e) => anyhow::bail!(
                    "Inspector2 ECR Images needs an inventory: run inventory first ({e:#})"
                ),
            };
        let inventory_file = inventory
            .path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();
        if let Ok(modified) = std::fs::metadata(&inventory.path).and_then(|m| m.modified()) {
            let age = std::time::SystemTime::now()
                .duration_since(modified)
                .unwrap_or_default();
            if age > std::time::Duration::from_secs(24 * 3600) {
                eprintln!(
                    "  WARN: inventory {} is {} hours old",
                    inventory.path.display(),
                    age.as_secs() / 3600
                );
            }
        }
        eprintln!(
            "  Inspector2 ECR Images: inventory {} ({} images, {} container rows without a digest)",
            inventory.path.display(),
            inventory.images.len(),
            inventory.rows_without_digest
        );

        let mut rows = Vec::new();
        let mut failures: Vec<(String, String, anyhow::Error)> = Vec::new();
        for image in inventory.images.iter().filter(|i| i.region == region) {
            let digests = match platform_digests(
                &self.ecr,
                &image.account,
                &image.repository,
                &image.digest,
            )
            .await
            {
                Ok(d) => d,
                Err(e) => {
                    eprintln!(
                        "  WARN: {}: could not read image index {} ({e:#}); per-platform findings may be missing",
                        image.asset_id, image.digest
                    );
                    vec![image.digest.clone()]
                }
            };
            for digest in digests {
                match active_findings_for_digest(
                    &self.client,
                    &image.account,
                    &image.repository,
                    &digest,
                )
                .await
                {
                    Ok(findings) => rows.extend(
                        findings
                            .iter()
                            .filter_map(finding_row)
                            .map(|r| annotate_inventory_row(r, &image.asset_id, &inventory_file)),
                    ),
                    Err(e) => failures.push((image.asset_id.clone(), digest.clone(), e)),
                }
            }
        }

        if !failures.is_empty() {
            let detail = failures
                .iter()
                .map(|(asset_id, digest, e)| format!("{asset_id} ({digest}): {e:#}"))
                .collect::<Vec<_>>()
                .join("; ");
            anyhow::bail!(
                "Inspector2 ECR Images: {} ListFindings lookup(s) failed: {detail}",
                failures.len()
            );
        }

        let before = rows.len();
        let rows = rollup_ecr_by_cve(rows);
        eprintln!(
            "  Inspector2 ECR Images: {before} ACTIVE findings on inventory digests → {} rows (one per CVE + package)",
            rows.len()
        );
        Ok(rows)
    }
}

const INDEX_MEDIA_TYPES: [&str; 2] = [
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
];

/// The digest itself, or its per-platform digests when it is an image index.
pub(crate) async fn platform_digests(
    ecr: &aws_sdk_ecr::Client,
    registry_id: &str,
    repository: &str,
    digest: &str,
) -> Result<Vec<String>> {
    let resp = ecr
        .batch_get_image()
        .registry_id(registry_id)
        .repository_name(repository)
        .image_ids(
            aws_sdk_ecr::types::ImageIdentifier::builder()
                .image_digest(digest)
                .build(),
        )
        .set_accepted_media_types(Some(
            INDEX_MEDIA_TYPES
                .iter()
                .map(|s| s.to_string())
                .chain([
                    "application/vnd.oci.image.manifest.v1+json".to_string(),
                    "application/vnd.docker.distribution.manifest.v2+json".to_string(),
                ])
                .collect(),
        ))
        .send()
        .await
        .with_context(|| format!("ecr:BatchGetImage {repository}@{digest}"))?;
    let Some(image) = resp.images().first() else {
        anyhow::bail!("ecr:BatchGetImage {repository}@{digest}: image not found");
    };
    let is_index = image
        .image_manifest_media_type()
        .is_some_and(|m| INDEX_MEDIA_TYPES.contains(&m));
    let children = if is_index {
        index_child_digests(image.image_manifest().unwrap_or(""))
    } else {
        vec![]
    };
    Ok(if children.is_empty() {
        vec![digest.to_string()]
    } else {
        children
    })
}

/// Every ACTIVE Inspector2 finding on one ECR image digest.
pub(crate) async fn active_findings_for_digest(
    client: &Inspector2Client,
    account: &str,
    repository: &str,
    digest: &str,
) -> Result<Vec<aws_sdk_inspector2::types::Finding>> {
    let eq = |v: &str| {
        StringFilter::builder()
            .comparison(StringComparison::Equals)
            .value(v)
            .build()
            .context("Inspector2 string filter")
    };
    let criteria = FilterCriteria::builder()
        .resource_type(eq("AWS_ECR_CONTAINER_IMAGE")?)
        .aws_account_id(eq(account)?)
        .ecr_image_repository_name(eq(repository)?)
        .ecr_image_hash(eq(digest)?)
        .finding_status(eq("ACTIVE")?)
        .build();
    let mut out = Vec::new();
    let mut token: Option<String> = None;
    loop {
        let resp = client
            .list_findings()
            .max_results(100)
            .filter_criteria(criteria.clone())
            .set_next_token(token.clone())
            .send()
            .await
            .with_context(|| format!("inspector2:ListFindings {repository}@{digest}"))?;
        out.extend(resp.findings().iter().cloned());
        token = resp.next_token().map(str::to_string);
        if token.is_none() {
            break;
        }
    }
    Ok(out)
}

const ECR_IMAGE_BASE_COLUMNS: usize = 42;

/// The 42 base columns (see `headers()`, indices 0–41) for one ECR image finding.
fn finding_row(f: &aws_sdk_inspector2::types::Finding) -> Option<Vec<String>> {
    let resource_type_str = f
        .resources()
        .first()
        .map(|r| r.r#type().as_str())
        .unwrap_or("");
    if resource_type_str != "AWS_ECR_CONTAINER_IMAGE" {
        return None;
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
            cve_id, source, vend_sev, cvss_s, cvss_v, refs, pn, pv, pa, pm, pfp, fiv, pr, slh,
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
            let diff = chrono::Utc::now().signed_duration_since(dt.with_timezone(&chrono::Utc));
            diff.num_days().to_string()
        })
        .unwrap_or_default();

    let row = vec![
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
    ];
    debug_assert_eq!(row.len(), ECR_IMAGE_BASE_COLUMNS);
    Some(row)
}
