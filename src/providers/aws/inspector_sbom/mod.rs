use std::collections::{BTreeMap, HashSet};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use async_trait::async_trait;
use aws_sdk_ecr::Client as EcrClient;
use aws_sdk_inspector2::types::{
    Destination, ExternalReportStatus, ResourceFilterCriteria, ResourceStringComparison,
    ResourceStringFilter, SbomReportFormat,
};
use aws_sdk_inspector2::Client as Inspector2Client;
use aws_sdk_s3::Client as S3Client;

use crate::evidence::CsvCollector;

mod export_keys;
mod repo_picker;

pub use export_keys::{
    belongs_to_report, format_stem, parse_export_key, sanitize_repo_name, ExportedSbom,
};
pub use repo_picker::{exported_newest_first, newest_exported, EcrImage};

const POLL_INTERVAL_SECS: u64 = 10;
const MAX_POLL_ATTEMPTS: u32 = 60;

/// Cap on the number of per-image SBOMs downloaded into `raw/` for a single
/// repository, newest first. Anything beyond the cap is reported in the CSV
/// `Notes` column rather than dropped silently.
const MAX_RAW_PER_REPO: usize = 25;

#[derive(Clone, Debug)]
pub struct InspectorSbomConfig {
    pub bucket: String,
    pub key_prefix: Option<String>,
    pub kms_key_arn: String,
    pub format: SbomReportFormat,
    /// ECR repository names to scope the export to. Empty means export the
    /// whole account, preserving the pre-selection behaviour.
    pub repositories: Vec<String>,
}

pub struct InspectorSbomCollector {
    inspector: Inspector2Client,
    s3: S3Client,
    ecr: EcrClient,
    config: InspectorSbomConfig,
    output_dir: Option<PathBuf>,
}

impl InspectorSbomCollector {
    pub fn new(
        inspector_config: &aws_config::SdkConfig,
        s3_config: &aws_config::SdkConfig,
        config: InspectorSbomConfig,
        output_dir: Option<PathBuf>,
    ) -> Self {
        Self {
            inspector: Inspector2Client::new(inspector_config),
            s3: S3Client::new(s3_config),
            ecr: EcrClient::new(inspector_config),
            config,
            output_dir,
        }
    }
}

#[async_trait]
impl CsvCollector for InspectorSbomCollector {
    fn name(&self) -> &str {
        "Inspector SBOM Export"
    }

    fn filename_prefix(&self) -> &str {
        "Inspector_SBOM_Export"
    }

    fn headers(&self) -> &'static [&'static str] {
        &[
            "Repository",
            "Report ID",
            "Export Status",
            "Format",
            "Selected Digest",
            "Selected Image Tags",
            "Image Pushed At",
            "Exported Images",
            "Raw Downloaded",
            "Local Path",
            "Notes",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let fmt = self.config.format.as_str().to_string();
        let mut rows: Vec<Vec<String>> = Vec::new();

        if self.config.bucket.is_empty() || self.config.kms_key_arn.is_empty() {
            eprintln!("  WARN: inspector-sbom requires an SBOM bucket and a KMS key");
            rows.push(export_row(
                "(export)",
                "",
                "SKIPPED",
                &fmt,
                "Set --sbom-bucket/--sbom-kms-key, or sbom_bucket/sbom_kms_key in config.toml",
            ));
            return Ok(rows);
        }

        let destination = Destination::builder()
            .bucket_name(&self.config.bucket)
            .set_key_prefix(self.config.key_prefix.clone())
            .kms_key_arn(&self.config.kms_key_arn)
            .build()
            .context("failed to build S3 destination for SBOM export")?;

        let mut req = self
            .inspector
            .create_sbom_export()
            .report_format(self.config.format.clone())
            .s3_destination(destination);
        if let Some(filter) = resource_filter(&self.config.repositories)? {
            req = req.resource_filter_criteria(filter);
        }

        let create_resp = match req.send().await {
            Ok(r) => r,
            Err(e) => {
                let msg = format!("{e:#}");
                if msg.contains("AccessDeniedException") {
                    eprintln!("  WARN: Inspector create_sbom_export (access denied): {msg}");
                    rows.push(export_row("(export)", "", "ACCESS_DENIED", &fmt, &msg));
                    return Ok(rows);
                }
                return Err(e).context("Inspector create_sbom_export failed");
            }
        };

        let report_id = create_resp
            .report_id()
            .context("create_sbom_export response missing report_id")?
            .to_string();

        if self.config.repositories.is_empty() {
            eprintln!("  SBOM export created (account-wide): report_id={report_id}");
        } else {
            eprintln!(
                "  SBOM export created for {} repositories: report_id={report_id}",
                self.config.repositories.len()
            );
        }

        let export_status = match self.poll_sbom_export(&report_id).await {
            Ok(s) => s,
            Err(e) => {
                rows.push(export_row(
                    "(export)",
                    &report_id,
                    "TIMEOUT",
                    &fmt,
                    &format!("{e:#}"),
                ));
                return Ok(rows);
            }
        };

        let status = export_status
            .status()
            .map(|s| s.as_str().to_string())
            .unwrap_or_else(|| "UNKNOWN".to_string());

        let s3_dest = export_status.s3_destination();
        let bucket = s3_dest
            .map(|d| d.bucket_name().to_string())
            .unwrap_or_else(|| self.config.bucket.clone());
        let prefix = s3_dest
            .and_then(|d| d.key_prefix())
            .map(|p| p.to_string())
            .or_else(|| self.config.key_prefix.clone())
            .unwrap_or_default();

        if status != "Succeeded" {
            let msg = export_status
                .error_message()
                .map(|s| s.to_string())
                .unwrap_or_else(|| format!("Export ended with status: {status}"));
            rows.push(export_row("(export)", &report_id, &status, &fmt, &msg));
            return Ok(rows);
        }

        let exported = self.list_exported(&bucket, &prefix, &report_id).await?;
        if exported.is_empty() {
            rows.push(export_row(
                "(export)",
                &report_id,
                &status,
                &fmt,
                &format!(
                    "Export succeeded but no ECR image SBOMs were found under s3://{bucket}/{prefix}"
                ),
            ));
            return Ok(rows);
        }

        let mut by_repo: BTreeMap<String, Vec<ExportedSbom>> = BTreeMap::new();
        for item in exported {
            by_repo
                .entry(item.repository.clone())
                .or_default()
                .push(item);
        }

        // Report on the repositories the user asked for. When unscoped, report
        // on everything the export produced.
        let targets: Vec<String> = if self.config.repositories.is_empty() {
            by_repo.keys().cloned().collect()
        } else {
            self.config.repositories.clone()
        };

        let region_label = if region.is_empty() {
            "unknown-region"
        } else {
            region
        };
        let stem = format_stem(&self.config.format);
        let out_root: Option<PathBuf> = self
            .output_dir
            .as_ref()
            .map(|p| p.join("SBOM").join(region_label));

        for repo in targets {
            let items = by_repo.remove(&repo).unwrap_or_default();
            let mut notes: Vec<String> = Vec::new();

            if items.is_empty() {
                notes.push(
                    "Inspector produced no SBOM for this repository — no scanned images"
                        .to_string(),
                );
                rows.push(repo_row(
                    &repo, &report_id, &status, &fmt, "", "", "", 0, 0, "", &notes,
                ));
                continue;
            }

            let exported_digests: HashSet<String> =
                items.iter().map(|i| i.digest.clone()).collect();

            let images = match self.list_ecr_images(&repo).await {
                Ok(v) => v,
                Err(e) => {
                    notes.push(format!("ECR describe_images failed: {e:#}"));
                    rows.push(repo_row(
                        &repo,
                        &report_id,
                        &status,
                        &fmt,
                        "",
                        "",
                        "",
                        items.len(),
                        0,
                        "",
                        &notes,
                    ));
                    continue;
                }
            };

            let key_for = |digest: &str| -> Option<String> {
                items
                    .iter()
                    .find(|i| i.digest == digest)
                    .map(|i| i.key.clone())
            };

            // ── raw/: every exported image for this repository, newest first ──
            let ordered = exported_newest_first(&images, &exported_digests);
            let mut raw_downloaded = 0usize;

            match out_root.as_ref() {
                None => {
                    notes.push("No output directory configured — nothing downloaded".to_string())
                }
                Some(root) => {
                    for digest in ordered.iter().take(MAX_RAW_PER_REPO) {
                        let Some(key) = key_for(digest) else { continue };
                        let leaf = format!(
                            "{}_{}.{stem}.json",
                            sanitize_repo_name(&repo),
                            digest.trim_start_matches("sha256:")
                        );
                        let dest = root.join("raw").join(leaf);
                        match self.download_object(&bucket, &key, &dest).await {
                            Ok(()) => raw_downloaded += 1,
                            Err(e) => {
                                notes.push(format!("raw download failed for {digest}: {e:#}"))
                            }
                        }
                    }
                    if ordered.len() > MAX_RAW_PER_REPO {
                        notes.push(format!(
                            "{} additional exported image(s) not downloaded (per-repo cap {MAX_RAW_PER_REPO})",
                            ordered.len() - MAX_RAW_PER_REPO
                        ));
                    }
                }
            }

            // ── <repo>.<stem>.json: the newest image present in the export ──
            let mut digest_col = String::new();
            let mut tags_col = String::new();
            let mut pushed_col = String::new();
            let mut local_path = String::new();

            match newest_exported(&images, &exported_digests) {
                None => notes.push(
                    "Exported SBOMs exist but none of their digests are still present in ECR"
                        .to_string(),
                ),
                Some(img) => {
                    digest_col = img.digest.clone();
                    tags_col = img.tags.join(",");
                    pushed_col = format_epoch(img.pushed_at_secs);

                    if let (Some(root), Some(key)) = (out_root.as_ref(), key_for(&img.digest)) {
                        let dest = root.join(format!("{}.{stem}.json", sanitize_repo_name(&repo)));
                        match self.download_object(&bucket, &key, &dest).await {
                            Ok(()) => {
                                eprintln!("  SBOM {repo}: {}", dest.display());
                                local_path = dest.display().to_string();
                            }
                            Err(e) => notes.push(format!("download failed: {e:#}")),
                        }
                    }
                }
            }

            rows.push(repo_row(
                &repo,
                &report_id,
                &status,
                &fmt,
                &digest_col,
                &tags_col,
                &pushed_col,
                items.len(),
                raw_downloaded,
                &local_path,
                &notes,
            ));
        }

        Ok(rows)
    }
}

/// Scope the export to `repositories`. `None` means unscoped (whole account).
/// Free function rather than a method so it is testable without an SDK client.
fn resource_filter(repositories: &[String]) -> Result<Option<ResourceFilterCriteria>> {
    if repositories.is_empty() {
        return Ok(None);
    }
    let mut builder = ResourceFilterCriteria::builder();
    for repo in repositories {
        let filter = ResourceStringFilter::builder()
            .comparison(ResourceStringComparison::Equals)
            .value(repo.clone())
            .build()
            .with_context(|| format!("building SBOM repository filter for {repo}"))?;
        builder = builder.ecr_repository_name(filter);
    }
    Ok(Some(builder.build()))
}

impl InspectorSbomCollector {
    async fn poll_sbom_export(
        &self,
        report_id: &str,
    ) -> Result<aws_sdk_inspector2::operation::get_sbom_export::GetSbomExportOutput> {
        let interval = tokio::time::Duration::from_secs(POLL_INTERVAL_SECS);

        for attempt in 1..=MAX_POLL_ATTEMPTS {
            let resp = self
                .inspector
                .get_sbom_export()
                .report_id(report_id)
                .send()
                .await
                .context("get_sbom_export request failed")?;

            match resp.status() {
                Some(ExternalReportStatus::Succeeded) => return Ok(resp),
                Some(ExternalReportStatus::Failed) => {
                    let msg = resp.error_message().unwrap_or("unknown error");
                    anyhow::bail!("SBOM export failed: {msg}");
                }
                Some(ExternalReportStatus::Cancelled) => {
                    anyhow::bail!("SBOM export was cancelled");
                }
                _ => {
                    if attempt == MAX_POLL_ATTEMPTS {
                        anyhow::bail!(
                            "SBOM export timed out after {MAX_POLL_ATTEMPTS} attempts ({:.0} min)",
                            (MAX_POLL_ATTEMPTS * POLL_INTERVAL_SECS as u32) as f64 / 60.0
                        );
                    }
                    tokio::time::sleep(interval).await;
                }
            }
        }

        anyhow::bail!("SBOM export polling loop exited unexpectedly")
    }

    /// Every ECR container-image SBOM this export produced, parsed out of the
    /// S3 object keys under `prefix`.
    async fn list_exported(
        &self,
        bucket: &str,
        prefix: &str,
        report_id: &str,
    ) -> Result<Vec<ExportedSbom>> {
        let mut all_keys: Vec<String> = Vec::new();
        let mut continuation: Option<String> = None;

        loop {
            let mut req = self.s3.list_objects_v2().bucket(bucket);
            if !prefix.is_empty() {
                req = req.prefix(prefix);
            }
            if let Some(ref t) = continuation {
                req = req.continuation_token(t);
            }
            let resp = req.send().await.context("S3 list_objects_v2 failed")?;

            for obj in resp.contents() {
                if let Some(k) = obj.key() {
                    all_keys.push(k.to_string());
                }
            }

            continuation = resp.next_continuation_token().map(|s| s.to_string());
            if continuation.is_none() {
                break;
            }
        }

        let this_report: Vec<&String> = all_keys
            .iter()
            .filter(|k| belongs_to_report(k, report_id))
            .collect();

        let scoped: Vec<&String> = if this_report.is_empty() {
            eprintln!(
                "  WARN: no keys under '{prefix}' carry report id {report_id}; \
                 falling back to every SBOM key under the prefix"
            );
            all_keys.iter().collect()
        } else {
            this_report
        };

        Ok(scoped
            .into_iter()
            .filter_map(|k| parse_export_key(k))
            .collect())
    }

    /// Every image currently in `repository`, reduced to digest/pushed-at/tags.
    async fn list_ecr_images(&self, repository: &str) -> Result<Vec<EcrImage>> {
        let mut out: Vec<EcrImage> = Vec::new();
        let mut pages = self
            .ecr
            .describe_images()
            .repository_name(repository)
            .into_paginator()
            .items()
            .send();

        while let Some(detail) = pages.next().await {
            let detail = detail.with_context(|| format!("ECR describe_images for {repository}"))?;
            let Some(digest) = detail.image_digest() else {
                continue;
            };
            out.push(EcrImage {
                digest: digest.to_string(),
                pushed_at_secs: detail.image_pushed_at().map(|t| t.secs()).unwrap_or(0),
                tags: detail.image_tags().to_vec(),
            });
        }

        Ok(out)
    }

    async fn download_object(&self, bucket: &str, key: &str, dest: &Path) -> Result<()> {
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating {}", parent.display()))?;
        }

        let resp = self
            .s3
            .get_object()
            .bucket(bucket)
            .key(key)
            .send()
            .await
            .with_context(|| format!("S3 get_object failed for {key}"))?;

        let data = resp
            .body
            .collect()
            .await
            .with_context(|| format!("reading S3 object body for {key}"))?
            .into_bytes();

        std::fs::write(dest, data).with_context(|| format!("writing {}", dest.display()))?;
        Ok(())
    }
}

/// A row describing the export itself rather than a repository.
fn export_row(repo: &str, report_id: &str, status: &str, format: &str, notes: &str) -> Vec<String> {
    vec![
        repo.to_string(),
        report_id.to_string(),
        status.to_string(),
        format.to_string(),
        String::new(),
        String::new(),
        String::new(),
        "0".to_string(),
        "0".to_string(),
        String::new(),
        notes.to_string(),
    ]
}

#[allow(clippy::too_many_arguments)]
fn repo_row(
    repo: &str,
    report_id: &str,
    status: &str,
    format: &str,
    digest: &str,
    tags: &str,
    pushed_at: &str,
    exported_images: usize,
    raw_downloaded: usize,
    local_path: &str,
    notes: &[String],
) -> Vec<String> {
    vec![
        repo.to_string(),
        report_id.to_string(),
        status.to_string(),
        format.to_string(),
        digest.to_string(),
        tags.to_string(),
        pushed_at.to_string(),
        exported_images.to_string(),
        raw_downloaded.to_string(),
        local_path.to_string(),
        notes.join("; "),
    ]
}

fn format_epoch(secs: i64) -> String {
    chrono::DateTime::from_timestamp(secs, 0)
        .map(|dt| dt.to_rfc3339())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sbom_format_as_str_yields_the_aws_wire_values() {
        // The SDK's as_str() returns the API's wire values, NOT the lowercase
        // spellings the CLI accepts. The old `sbom_format_parsing` test asserted
        // the opposite and was encoding a bug — see parse_sbom_format in Task 5.
        assert_eq!(SbomReportFormat::Cyclonedx14.as_str(), "CYCLONEDX_1_4");
        assert_eq!(SbomReportFormat::Spdx23.as_str(), "SPDX_2_3");
    }

    #[test]
    fn a_lowercase_format_string_does_not_parse_into_a_known_variant() {
        // Guards the bug this plan fixes: `"cyclonedx14".into()` silently yields
        // an Unknown variant that AWS rejects, which is why the CLI must map the
        // user-facing spelling explicitly instead of using From<&str>.
        let bogus: SbomReportFormat = "cyclonedx14".into();
        assert_ne!(bogus, SbomReportFormat::Cyclonedx14);
    }

    #[test]
    fn no_repositories_means_an_unscoped_export() {
        let filter = resource_filter(&[]).expect("empty list is not an error");
        assert!(
            filter.is_none(),
            "an empty repository list must leave the export account-wide"
        );
    }

    #[test]
    fn repositories_become_equals_filters() {
        let repos = vec!["webapp-base".to_string(), "team/service".to_string()];
        let filter = resource_filter(&repos)
            .expect("filter builds")
            .expect("filter is present");

        let names = filter.ecr_repository_name();
        assert_eq!(names.len(), 2);
        assert_eq!(names[0].value(), "webapp-base");
        assert_eq!(names[1].value(), "team/service");
        for f in names {
            assert_eq!(*f.comparison(), ResourceStringComparison::Equals);
        }
        // Only the repository dimension is constrained.
        assert!(filter.resource_id().is_empty());
        assert!(filter.ecr_image_tags().is_empty());
    }

    #[test]
    fn export_row_has_one_cell_per_header() {
        let row = export_row("(export)", "r-1", "SKIPPED", "cyclonedx14", "why");
        assert_eq!(row.len(), 11, "export_row must match the header count");
        assert_eq!(row[0], "(export)");
        assert_eq!(row[2], "SKIPPED");
        assert_eq!(row[10], "why");
    }

    #[test]
    fn repo_row_has_one_cell_per_header_and_joins_notes() {
        let notes = vec!["first".to_string(), "second".to_string()];
        let row = repo_row(
            "app",
            "r-1",
            "Succeeded",
            "cyclonedx14",
            "sha256:aa",
            "latest",
            "2026-08-05T00:00:00+00:00",
            3,
            2,
            "/tmp/app.cyclonedx.json",
            &notes,
        );
        assert_eq!(row.len(), 11, "repo_row must match the header count");
        assert_eq!(row[7], "3");
        assert_eq!(row[8], "2");
        assert_eq!(row[10], "first; second");
    }

    #[test]
    fn format_epoch_renders_rfc3339_and_tolerates_zero() {
        assert_eq!(format_epoch(0), "1970-01-01T00:00:00+00:00");
        assert!(format_epoch(1_754_412_938).starts_with("2025-08-05T"));
    }
}
