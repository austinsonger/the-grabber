use std::path::PathBuf;

use anyhow::{Context, Result};
use async_trait::async_trait;
use aws_sdk_inspector2::types::{Destination, ExternalReportStatus, SbomReportFormat};
use aws_sdk_inspector2::Client as Inspector2Client;
use aws_sdk_s3::Client as S3Client;

use crate::evidence::CsvCollector;

const POLL_INTERVAL_SECS: u64 = 10;
const MAX_POLL_ATTEMPTS: u32 = 60;

pub struct InspectorSbomConfig {
    pub bucket: String,
    pub key_prefix: Option<String>,
    pub kms_key_arn: String,
    pub format: SbomReportFormat,
}

pub struct InspectorSbomCollector {
    inspector: Inspector2Client,
    s3: S3Client,
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
            "Report ID",
            "Status",
            "Format",
            "S3 Bucket",
            "S3 Key",
            "Local Path",
            "Error Message",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let mut rows = Vec::new();

        if self.config.bucket.is_empty() {
            eprintln!("  WARN: inspector-sbom requires --sbom-bucket and --sbom-kms-key");
            rows.push(vec![
                String::new(),
                "SKIPPED".to_string(),
                self.config.format.as_str().to_string(),
                String::new(),
                String::new(),
                String::new(),
                "Missing --sbom-bucket and --sbom-kms-key".to_string(),
            ]);
            return Ok(rows);
        }

        let destination = Destination::builder()
            .bucket_name(&self.config.bucket)
            .set_key_prefix(self.config.key_prefix.clone())
            .kms_key_arn(&self.config.kms_key_arn)
            .build()
            .context("failed to build S3 destination for SBOM export")?;

        let create_resp = match self
            .inspector
            .create_sbom_export()
            .report_format(self.config.format.clone())
            .s3_destination(destination)
            .send()
            .await
        {
            Ok(r) => r,
            Err(e) => {
                let msg = format!("{e:#}");
                if msg.contains("AccessDeniedException") {
                    eprintln!("  WARN: Inspector create_sbom_export (access denied): {msg}");
                    return Ok(rows);
                }
                return Err(e).context("Inspector create_sbom_export failed");
            }
        };

        let report_id = create_resp
            .report_id()
            .context("create_sbom_export response missing report_id")?
            .to_string();

        eprintln!("  SBOM export created: report_id={report_id}");

        let export_status = match self.poll_sbom_export(&report_id).await {
            Ok(s) => s,
            Err(e) => {
                rows.push(vec![
                    report_id.clone(),
                    "TIMEOUT".to_string(),
                    self.config.format.as_str().to_string(),
                    self.config.bucket.clone(),
                    self.config.key_prefix.clone().unwrap_or_default(),
                    String::new(),
                    format!("{e:#}"),
                ]);
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

        let mut local_path = String::new();
        let mut error_msg = String::new();

        if status == "Succeeded" {
            match self
                .download_latest_sbom(&bucket, &prefix, &report_id)
                .await
            {
                Ok(path) => local_path = path,
                Err(e) => {
                    eprintln!("  WARN: could not download SBOM from S3: {e:#}");
                    error_msg = format!("Download failed: {e:#}");
                }
            }
        } else {
            error_msg = export_status
                .error_message()
                .map(|s| s.to_string())
                .unwrap_or_else(|| format!("Export ended with status: {status}"));
        }

        rows.push(vec![
            report_id,
            status,
            self.config.format.as_str().to_string(),
            bucket,
            prefix,
            local_path,
            error_msg,
        ]);

        Ok(rows)
    }
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

    async fn download_latest_sbom(
        &self,
        bucket: &str,
        prefix: &str,
        report_id: &str,
    ) -> Result<String> {
        let output_dir = match self.output_dir {
            Some(ref p) => p.clone(),
            None => return Ok(String::new()),
        };

        let list_resp = self
            .s3
            .list_objects_v2()
            .bucket(bucket)
            .prefix(prefix)
            .send()
            .await
            .context("S3 list_objects_v2 failed")?;

        let objects = list_resp.contents();
        if objects.is_empty() {
            anyhow::bail!("No objects found in S3 under prefix '{prefix}' after export succeeded");
        }

        let latest = objects
            .iter()
            .filter_map(|o| Some((o.key()?, o.last_modified()?)))
            .max_by_key(|(_, last_mod)| last_mod.as_secs_f64() as i64)
            .context("Could not determine latest S3 object")?;

        let key = latest.0;
        let dest_filename = format!(
            "{}_{}",
            report_id,
            key.rsplit_once('/').map(|(_, name)| name).unwrap_or(key)
        );
        let dest_path = output_dir.join(&dest_filename);

        let get_resp = self
            .s3
            .get_object()
            .bucket(bucket)
            .key(key)
            .send()
            .await
            .with_context(|| format!("S3 get_object failed for {key}"))?;

        let data = get_resp
            .body
            .collect()
            .await
            .context("reading S3 object body")?
            .into_bytes();

        std::fs::write(&dest_path, data)
            .with_context(|| format!("Failed to write SBOM to {}", dest_path.display()))?;

        eprintln!("  Downloaded SBOM: {}", dest_path.display());
        Ok(dest_path.display().to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sbom_format_parsing() {
        let fmt: SbomReportFormat = "cyclonedx14".into();
        assert_eq!(fmt.as_str(), "cyclonedx14");

        let fmt2: SbomReportFormat = "spdx23".into();
        assert_eq!(fmt2.as_str(), "spdx23");
    }
}
