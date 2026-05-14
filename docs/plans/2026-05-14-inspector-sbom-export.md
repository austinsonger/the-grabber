# AWS Inspector V2 SBOM Export Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add a new `inspector-sbom` collector that creates SBOM exports via AWS Inspector V2, polls for completion, downloads the resulting SBOM file from S3, and writes metadata to CSV.

**Architecture:** A `CsvCollector` implementation triggers `create_sbom_export`, polls `get_sbom_export` with a 10-second backoff, lists the S3 prefix to discover the exported file, downloads it locally, and returns one CSV row per export containing report ID, status, format, S3 location, local path, and any error message. CLI flags configure the S3 destination. The collector is registered in the AWS provider factory so it works in both CLI and TUI modes.

**Tech Stack:** Rust, `aws-sdk-inspector2`, `aws-sdk-s3`, `tokio`, `anyhow`, `async-trait`, `csv`, `serde_json`

---

## Pre-Read References

Before touching code, read these files to internalise patterns:

- `src/evidence.rs` — `CsvCollector` trait definition
- `src/providers/aws/ecr.rs` — example `CsvCollector` with pagination and nested loops
- `src/providers/aws/factory.rs` — how collectors are registered in the factory
- `src/providers/aws/mod.rs` — module declarations
- `src/cli.rs` — CLI flag definitions
- `src/runner/cli_runners.rs` — how the S3 CloudTrail collector is built manually outside the factory (lines 293-298)
- `src/runner/collect_ops.rs` — how CSV collectors are executed and files written
- `src/runner/multi_region_cli.rs` — multi-region collector wiring
- `src/runner/multi_account.rs` — `GLOBAL_COLLECTOR_KEYS` constant (line 17)
- `AGENTS.md` — error-handling rules (`?` + `.context()`, no `unwrap`)

---

## Task 1: Add CLI flags for SBOM export destination

**Files:**
- Modify: `src/cli.rs`

**Step 1: Add CLI fields**

Insert after the `poam_month` field and before the closing `}` of `pub struct Cli`:

```rust
    // ------- Inspector SBOM export options -------
    /// S3 bucket for Inspector SBOM export destination.
    #[arg(long)]
    pub sbom_bucket: Option<String>,

    /// KMS key ARN for Inspector SBOM export encryption.
    #[arg(long)]
    pub sbom_kms_key: Option<String>,

    /// SBOM report format: cyclonedx14 or spdx23.
    #[arg(long, default_value = "cyclonedx14")]
    pub sbom_format: String,
```

**Step 2: Run check**

Run: `cargo check`
Expected: PASS

**Step 3: Commit**

```bash
git add src/cli.rs
git commit -m "feat(cli): add inspector-sbom export destination flags"
```

---

## Task 2: Create the `inspector_sbom` collector module

**Files:**
- Create: `src/providers/aws/inspector_sbom.rs`

**Step 1: Write the module**

```rust
//! AWS Inspector V2 SBOM export collector.
//!
//! Triggers `create_sbom_export`, polls `get_sbom_export`, discovers the
//! resulting file in S3, downloads it, and returns metadata rows.

use std::path::PathBuf;

use anyhow::{Context, Result};
use async_trait::async_trait;
use aws_sdk_inspector2::types::{Destination, ExternalReportStatus, SbomReportFormat};
use aws_sdk_inspector2::Client as Inspector2Client;
use aws_sdk_s3::Client as S3Client;

use crate::evidence::CsvCollector;

const POLL_INTERVAL_SECS: u64 = 10;
const MAX_POLL_ATTEMPTS: u32 = 60;

/// Configuration for where Inspector should write the SBOM.
pub struct InspectorSbomConfig {
    pub bucket: String,
    pub key_prefix: Option<String>,
    pub kms_key_arn: String,
    pub format: SbomReportFormat,
}

/// Collector that creates an SBOM export and optionally downloads it.
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
            eprintln!("  WARN: inspector-sbom collector requires --sbom-bucket and --sbom-kms-key");
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
            .build();

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
                    format!("{}", self.config.format.as_str()),
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
            match self.download_latest_sbom(&bucket, &prefix, &report_id).await {
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
            anyhow::bail!(
                "No objects found in S3 under prefix '{prefix}' after export succeeded"
            );
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
        assert_eq!(fmt.as_str(), "Cyclonedx14");

        let fmt2: SbomReportFormat = "spdx23".into();
        assert_eq!(fmt2.as_str(), "Spdx23");
    }
}
```

**Step 2: Run check**

Run: `cargo check`
Expected: PASS

**Step 3: Run the test**

Run: `cargo test inspector_sbom::tests::sbom_format_parsing -- --nocapture`
Expected: PASS

**Step 4: Commit**

```bash
git add src/providers/aws/inspector_sbom.rs
git commit -m "feat(inspector): add SBOM export collector module"
```

---

## Task 3: Register the module

**Files:**
- Modify: `src/providers/aws/mod.rs`
- Modify: `src/providers/aws/factory.rs`

**Step 1: Declare module**

In `src/providers/aws/mod.rs`, add after `pub mod inspector_history;`:

```rust
pub mod inspector_sbom;
```

**Step 2: Import in factory**

In `src/providers/aws/factory.rs`, add to the import block:

```rust
    inspector_sbom::{InspectorSbomCollector, InspectorSbomConfig},
```

**Step 3: Register in factory**

In `src/providers/aws/factory.rs` inside `csv_collectors()`, add after the `inspector-history` block:

```rust
        if has("inspector-sbom") {
            v.push(Box::new(InspectorSbomCollector::new(
                cfg,
                cfg,
                InspectorSbomConfig {
                    bucket: String::new(),
                    key_prefix: None,
                    kms_key_arn: String::new(),
                    format: aws_sdk_inspector2::types::SbomReportFormat::Cyclonedx14,
                },
                None,
            )));
        }
```

**Step 4: Run check**

Run: `cargo check`
Expected: PASS

**Step 5: Commit**

```bash
git add src/providers/aws/mod.rs src/providers/aws/factory.rs src/providers/aws/inspector_sbom.rs
git commit -m "feat(inspector): register inspector-sbom in AWS provider factory"
```

---

## Task 4: Wire up CLI runner with real config and output_dir

**Files:**
- Modify: `src/runner/cli_runners.rs`

**Step 1: Add early validation**

After `let output_dir = cli.output.clone().unwrap_or_else(|| PathBuf::from("."));` and before the empty-collectors check, add:

```rust
    if selected.iter().any(|n| n == "inspector-sbom") && cli.sbom_bucket.is_none() {
        anyhow::bail!(
            "--sbom-bucket and --sbom-kms-key are required for the inspector-sbom collector"
        );
    }
```

**Step 2: Build collector manually**

Immediately after the validation block, add:

```rust
    if selected.iter().any(|n| n == "inspector-sbom") {
        if let (Some(bucket), Some(kms_key)) = (&cli.sbom_bucket, &cli.sbom_kms_key) {
            let format: aws_sdk_inspector2::types::SbomReportFormat = cli.sbom_format.as_str().into();
            let sbom_collector = crate::providers::aws::inspector_sbom::InspectorSbomCollector::new(
                &config,
                &config,
                crate::providers::aws::inspector_sbom::InspectorSbomConfig {
                    bucket: bucket.clone(),
                    key_prefix: None,
                    kms_key_arn: kms_key.clone(),
                    format,
                },
                Some(output_dir.clone()),
            );
            csv_collectors.push(Box::new(sbom_collector));
        }
    }
```

**Step 3: Run check**

Run: `cargo check`
Expected: PASS

**Step 4: Commit**

```bash
git add src/runner/cli_runners.rs
git commit -m "feat(cli): wire inspector-sbom collector with CLI flags and output dir"
```

---

## Task 5: Multi-region CLI support

**Files:**
- Modify: `src/runner/multi_region_cli.rs`

**Step 1: Add SBOM collector wiring**

Search for every `AwsProviderFactory::new` instantiation in `src/runner/multi_region_cli.rs`. After each factory build where `csv_collectors` is in scope, add:

```rust
        if selected.iter().any(|n| n == "inspector-sbom") {
            if let (Some(bucket), Some(kms_key)) = (&cli.sbom_bucket, &cli.sbom_kms_key) {
                let format: aws_sdk_inspector2::types::SbomReportFormat =
                    cli.sbom_format.as_str().into();
                let sbom_collector = crate::providers::aws::inspector_sbom::InspectorSbomCollector::new(
                    &region_config,
                    &region_config,
                    crate::providers::aws::inspector_sbom::InspectorSbomConfig {
                        bucket: bucket.clone(),
                        key_prefix: None,
                        kms_key_arn: kms_key.clone(),
                        format,
                    },
                    Some(region_output_dir.clone()),
                );
                csv_collectors.push(Box::new(sbom_collector));
            }
        }
```

Use the same region config and region-specific output directory that the surrounding code uses.

**Step 2: Run check**

Run: `cargo check`
Expected: PASS

**Step 3: Commit**

```bash
git add src/runner/multi_region_cli.rs
git commit -m "feat(cli): support inspector-sbom in multi-region mode"
```

---

## Task 6: Update documentation

**Files:**
- Modify: `evidence-list.md`
- Modify: `README.md`

**Step 1: Add to evidence-list.md**

Find the inspector entries and add after `inspector-history`:

```markdown
| `inspector-sbom` | CSV | Inspector SBOM export metadata (requires `--sbom-bucket`, `--sbom-kms-key`) |
```

**Step 2: Add to README.md collector table**

Find the `inspector-history` row and add after it:

```markdown
| `inspector-sbom` | CSV | Inspector SBOM export metadata |
```

**Step 3: Add CLI flags to README.md**

In the CLI reference section, add:

```markdown
| `--sbom-bucket <name>` | S3 bucket for Inspector SBOM export |
| `--sbom-kms-key <arn>` | KMS key ARN for SBOM export encryption |
| `--sbom-format <fmt>` | SBOM format: `cyclonedx14` or `spdx23` (default: cyclonedx14) |
```

**Step 4: Commit**

```bash
git add evidence-list.md README.md
git commit -m "docs: document inspector-sbom collector and CLI flags"
```

---

## Task 7: Final verification

**Step 1: Check**

Run: `cargo check`
Expected: PASS with zero warnings

**Step 2: Lint**

Run: `cargo clippy -- -D warnings`
Expected: PASS

**Step 3: Format**

Run: `cargo fmt`
Expected: No changes (or auto-formatted)

**Step 4: Tests**

Run: `cargo test`
Expected: All existing tests pass, new `sbom_format_parsing` test passes

**Step 5: Commit any fixes**

```bash
git add -A
git commit -m "style: clippy and fmt fixes"
```

---

## Appendix: IAM permissions required

The collector needs these permissions (add to your AWS role/policy):

```json
{
    "Effect": "Allow",
    "Action": [
        "inspector2:CreateSbomExport",
        "inspector2:GetSbomExport"
    ],
    "Resource": "*"
},
{
    "Effect": "Allow",
    "Action": [
        "s3:GetObject",
        "s3:ListBucket"
    ],
    "Resource": [
        "arn:aws:s3:::YOUR_SBOM_BUCKET",
        "arn:aws:s3:::YOUR_SBOM_BUCKET/*"
    ]
}
```

The S3 bucket also needs a bucket policy allowing `inspector2.amazonaws.com` to `PutObject` (see AWS docs).

---

## Appendix: Usage example

```bash
# Single region, download SBOM to ./evidence-output/
grabber \
  --start-date 2026-05-01 --end-date 2026-05-14 \
  --collectors inspector-sbom \
  --sbom-bucket my-sbom-bucket \
  --sbom-kms-key arn:aws:kms:us-east-1:123456789012:key/abc123 \
  --sbom-format spdx23 \
  --output ./evidence-output

# Multi-region
grabber \
  --all-regions \
  --collectors inspector-sbom \
  --sbom-bucket my-sbom-bucket \
  --sbom-kms-key arn:aws:kms:us-east-1:123456789012:key/abc123
```
