# AWS SBOM Export — Per-Repository Selection Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the AWS `inspector-sbom` collector list every ECR repository it discovers, let the user pick which ones they need SBOMs for, scope the Inspector export to exactly those repositories, and land one clearly-named CycloneDX/SPDX file per repository representing the newest image Inspector actually exported.

**Architecture:** `inspector_sbom.rs` becomes a directory module. The Inspector export request gains `resource_filter_criteria.ecr_repository_name` so AWS itself scopes the export to the selected repositories. After the export succeeds the collector lists the export's S3 objects, recovers repository + image digest from each object *key* (the JSON body does not carry the repository name reliably), intersects those digests with live `ecr:DescribeImages` output, and picks the newest image present in both — because Inspector only exports SBOMs for images it has scanned, so the newest image in ECR is frequently absent from the export. Repository discovery and selection is surfaced as a three-screen TUI sub-flow (destination → discovery → repo picker) reusing the existing "exit the TUI, do async work, re-enter" pattern from `StigRemediationScanning`, and as `--sbom-repos` / `--sbom-all-repos` on the flag-driven CLI.

**Tech Stack:** Rust, tokio, `aws-sdk-inspector2` 1.x, `aws-sdk-ecr` 1.x, `aws-sdk-s3` 1.x, `ratatui` + `crossterm`, `clap`, `anyhow`, `chrono`.

## Global Constraints

- Work on `main`. Do **not** create a feature branch.
- `cargo clippy -- -D warnings` and `cargo fmt` must be clean before every commit.
- No `unwrap()` / `expect()` in production code. Use `anyhow::Result` / `anyhow::Context`, `anyhow::bail!` for early exits.
- Imports grouped std → external crates → `crate::*`, blank line between groups.
- **No new test files or test steps.** Verification for every task is `cargo fmt`, `cargo clippy -- -D warnings`, and the stated manual check. (This deviates from the skill's default TDD structure at the repository owner's standing instruction.)
- `inspector-sbom` must become **opt-in** in the TUI. It is currently absent from `hardcoded_optins` in `App::new` (`src/tui/app/mod.rs:202`), so it is pre-selected today; leaving it that way would push every AWS run through the two new wizard screens. Task 7 Step 1 fixes this.
- Per-repository raw download cap: **25** images, newest first. Anything beyond the cap must be reported in the CSV `Notes` column — never dropped silently.
- Local output layout, relative to the run's output directory:
  - `SBOM/<region>/<repo>.cyclonedx.json` (or `.spdx.json`) — the chosen newest image
  - `SBOM/<region>/raw/<repo>_<digest-hex>.cyclonedx.json` — every exported image, up to the cap
  - `/` in a repository name becomes `_` in filenames.
- Collector key stays `inspector-sbom`. Empty repository selection preserves today's account-wide export behaviour.
- The TUI `inspector-sbom` sub-flow discovers repositories from the **first selected AWS account** and applies the chosen repository names to every account/region in the run. Repositories absent from a given account simply produce a "no SBOM for this repository" row.

---

## File Structure

**Created**

| File | Responsibility |
|---|---|
| `src/providers/aws/inspector_sbom/mod.rs` | `InspectorSbomConfig`, `InspectorSbomCollector`, the `CsvCollector` impl, and AWS calls (create/poll export, list S3, describe images, download) |
| `src/providers/aws/inspector_sbom/export_keys.rs` | Pure parsing of Inspector's exported S3 object keys → `(repository, digest)`; filename sanitising; format stem |
| `src/providers/aws/inspector_sbom/repo_picker.rs` | Pure selection logic: newest exported image, and exported digests ordered newest-first |
| `src/providers/aws/ecr_repos.rs` | `list_repositories()` — reusable ECR repository discovery for the TUI and `--sbom-all-repos` |
| `src/tui/ui/sbom_screens.rs` | `draw_sbom_destination`, `draw_sbom_repo_discovery`, `draw_sbom_repo_selection` |

**Deleted**

- `src/providers/aws/inspector_sbom.rs` (becomes the directory module above)

**Modified**

| File | Change |
|---|---|
| `src/app_config.rs` | `sbom_bucket` / `sbom_kms_key` / `sbom_key_prefix` on `Defaults` and `Account`, plus `*_resolved()` helpers |
| `config.example.toml` | Document the three new keys |
| `src/cli.rs` | `--sbom-key-prefix`, `--sbom-repos`, `--sbom-all-repos` |
| `src/runner/cli_runners.rs` | Resolve repository list (explicit, all-repos discovery, or empty) into `InspectorSbomConfig` |
| `src/providers/aws/factory.rs` | Carry `repositories` through `with_sbom_config` |
| `src/providers/aws/mod.rs` | Declare `ecr_repos` |
| `src/runner/collector_registry.rs` | `build_csv_collectors_with_sbom()` so the TUI path can inject an `InspectorSbomConfig` |
| `src/runner/tui_session.rs` | Async ECR repo discovery block; pass the TUI-built `InspectorSbomConfig` into collector construction |
| `src/tui/state.rs` | Three new `Screen` variants |
| `src/tui/app/mod.rs` | SBOM destination/repo-selection state fields |
| `src/tui/app/nav.rs` | `next_screen` / `prev_screen` / `validate_current` / `reset` for the new screens |
| `src/tui/events.rs` | `Action::SbomDiscoverRepos`, dispatch, three handlers |
| `src/tui/ui/mod.rs` | `mod sbom_screens;` + three dispatch arms |
| `src/tui/ui/frame.rs` | `STEPS_PROVIDER_ACCOUNTS_SBOM` / `STEPS_PROVIDER_LEGACY_SBOM`, `screen_to_step`, `get_hints` |
| `src/tui/ui/mod.rs` (steps import) | Import + select the new step arrays |
| `src/tui/mod.rs` | `run()` returns `Some(app)` for `Screen::SbomRepoDiscovery` |
| `README.md`, `docs/cli-reference.md` | Document the new flags, config keys, output layout, and TUI flow |

---

## Task 1: Config keys for the SBOM destination

**Files:**
- Modify: `src/app_config.rs` (`Defaults` struct ~line 34, `Account` struct ~line 123, `impl Account` ~line 260)
- Modify: `config.example.toml` (`[defaults]` block ~line 14)

**Interfaces:**
- Consumes: nothing.
- Produces: `Defaults { sbom_bucket: Option<String>, sbom_kms_key: Option<String>, sbom_key_prefix: Option<String> }`; the same three fields on `Account`; and `Account::sbom_bucket_resolved(&self, defaults: &Defaults) -> Option<String>`, `Account::sbom_kms_key_resolved(&self, defaults: &Defaults) -> Option<String>`, `Account::sbom_key_prefix_resolved(&self, defaults: &Defaults) -> Option<String>`.

- [ ] **Step 1: Add the three fields to `Defaults`**

In `src/app_config.rs`, inside `pub struct Defaults`, immediately before the `/// Global collector enable/disable rules.` doc comment and its `#[serde(default)] pub collectors: CollectorConfig,` field, insert:

```rust
    /// Default S3 bucket for Inspector SBOM exports (`inspector-sbom` collector).
    pub sbom_bucket: Option<String>,

    /// Default KMS key ARN used to encrypt Inspector SBOM exports.
    pub sbom_kms_key: Option<String>,

    /// Optional key prefix inside `sbom_bucket`. Inspector appends
    /// `<FORMAT>_outputs_<report-id>/…` beneath whatever prefix is given.
    pub sbom_key_prefix: Option<String>,
```

- [ ] **Step 2: Add the same three fields to `Account`**

In `pub struct Account`, immediately before the `// ------------------------------------------------------------------` / `// Collector filtering (all providers)` comment block, insert:

```rust
    // ------------------------------------------------------------------
    // Inspector SBOM export (AWS)
    // ------------------------------------------------------------------
    /// Per-account override for the Inspector SBOM export bucket.
    pub sbom_bucket: Option<String>,

    /// Per-account override for the Inspector SBOM export KMS key ARN.
    pub sbom_kms_key: Option<String>,

    /// Per-account override for the Inspector SBOM export key prefix.
    pub sbom_key_prefix: Option<String>,
```

- [ ] **Step 3: Add the resolver helpers**

In `impl Account` in `src/app_config.rs`, after `pub fn jamf_client_secret_resolved(...)` and before the closing brace of the impl block, insert:

```rust
    /// Resolve the Inspector SBOM export bucket: env var, then per-account
    /// TOML, then `[defaults]`.
    pub fn sbom_bucket_resolved(&self, defaults: &Defaults) -> Option<String> {
        std::env::var("GRABBER_SBOM_BUCKET")
            .ok()
            .or_else(|| self.sbom_bucket.clone())
            .or_else(|| defaults.sbom_bucket.clone())
    }

    /// Resolve the Inspector SBOM export KMS key ARN: env var, then
    /// per-account TOML, then `[defaults]`.
    pub fn sbom_kms_key_resolved(&self, defaults: &Defaults) -> Option<String> {
        std::env::var("GRABBER_SBOM_KMS_KEY")
            .ok()
            .or_else(|| self.sbom_kms_key.clone())
            .or_else(|| defaults.sbom_kms_key.clone())
    }

    /// Resolve the Inspector SBOM export key prefix: per-account TOML, then
    /// `[defaults]`. No env override — the prefix is layout, not a secret.
    pub fn sbom_key_prefix_resolved(&self, defaults: &Defaults) -> Option<String> {
        self.sbom_key_prefix
            .clone()
            .or_else(|| defaults.sbom_key_prefix.clone())
    }
```

- [ ] **Step 4: Document the keys in `config.example.toml`**

In `config.example.toml`, inside the `[defaults]` block, after the `include_raw             = false` line, insert:

```toml

# Inspector SBOM export destination (used by the `inspector-sbom` collector).
# Inspector writes the export into this bucket; grabber then downloads the
# SBOM for the newest scanned image of each repository you select.
# Override per account with the same keys inside an [[account]] block.
# sbom_bucket     = "my-sbom-exports"
# sbom_kms_key    = "arn:aws:kms:us-east-1:123456789012:key/abc-123"
# sbom_key_prefix = "grabber"
```

- [ ] **Step 5: Verify it compiles and the example config still parses**

Run:
```bash
cargo fmt
cargo clippy -- -D warnings
```
Expected: clean.

Then confirm the example config is still valid TOML with the new keys recognised:
```bash
cargo run -- --verify-manifest /dev/null 2>&1 | head -5
```
Expected: an error about the manifest path (not a config-parse error) — this only proves config loading did not reject the new keys.

- [ ] **Step 6: Commit**

```bash
git add src/app_config.rs config.example.toml
git commit -m "feat(sbom): add sbom_bucket/sbom_kms_key/sbom_key_prefix config keys"
```

---

## Task 2: Pure key-parsing and image-picking helpers

**Files:**
- Create: `src/providers/aws/inspector_sbom/export_keys.rs`
- Create: `src/providers/aws/inspector_sbom/repo_picker.rs`
- Modify: `src/providers/aws/inspector_sbom.rs` → moved to `src/providers/aws/inspector_sbom/mod.rs`

**Interfaces:**
- Consumes: `Defaults`-independent; only `aws_sdk_inspector2::types::SbomReportFormat`.
- Produces:
  - `export_keys::ExportedSbom { key: String, repository: String, digest: String }`
  - `export_keys::parse_export_key(key: &str) -> Option<ExportedSbom>`
  - `export_keys::belongs_to_report(key: &str, report_id: &str) -> bool`
  - `export_keys::sanitize_repo_name(repository: &str) -> String`
  - `export_keys::format_stem(format: &SbomReportFormat) -> &'static str`
  - `repo_picker::EcrImage { digest: String, pushed_at_secs: i64, tags: Vec<String> }`
  - `repo_picker::newest_exported<'a>(images: &'a [EcrImage], exported: &HashSet<String>) -> Option<&'a EcrImage>`
  - `repo_picker::exported_newest_first(images: &[EcrImage], exported: &HashSet<String>) -> Vec<String>`

- [ ] **Step 1: Move the existing collector file into a directory module**

```bash
mkdir -p src/providers/aws/inspector_sbom
git mv src/providers/aws/inspector_sbom.rs src/providers/aws/inspector_sbom/mod.rs
```

No other file changes are needed — `src/providers/aws/mod.rs` already declares `pub mod inspector_sbom;`, which resolves to the directory.

- [ ] **Step 2: Create `export_keys.rs`**

Create `src/providers/aws/inspector_sbom/export_keys.rs`:

```rust
//! Parsing for the S3 object keys Inspector writes during an SBOM export.
//!
//! Inspector lays an export out as:
//!
//! ```text
//! <key_prefix>/<FORMAT>_outputs_<report_id>/account=<account_id>/
//!   resource=AWS_ECR_CONTAINER_IMAGE/
//!   arn:aws:ecr:<region>:<account_id>:repository_<repo>_<digest>_<FORMAT>.json
//! ```
//!
//! The repository name and image digest are recovered from the key, not the
//! JSON body — the body does not carry the repository name in a stable place.

use aws_sdk_inspector2::types::SbomReportFormat;

/// One exported SBOM object, identified by the repository and image digest
/// encoded in its S3 key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportedSbom {
    pub key: String,
    pub repository: String,
    /// Full digest, including the `sha256:` prefix.
    pub digest: String,
}

/// True when `key` belongs to the export identified by `report_id`.
pub fn belongs_to_report(key: &str, report_id: &str) -> bool {
    key.contains(&format!("_outputs_{report_id}/"))
}

/// Recover the repository name and image digest from an exported object key.
/// Returns `None` for keys that are not ECR container-image SBOMs.
pub fn parse_export_key(key: &str) -> Option<ExportedSbom> {
    // Search the whole key rather than only its last path segment: ECR
    // repository names may contain `/` (e.g. `team/service`), which would
    // otherwise be mistaken for a key separator.
    let after_marker = key.split_once("repository_")?.1;

    // `:` is not legal in an ECR repository name, so the first `_sha256:`
    // is always the repository/digest boundary even when the repository name
    // itself contains underscores.
    let (repository, tail) = after_marker.split_once("_sha256:")?;
    let hex = tail.split_once('_')?.0;

    if repository.is_empty() || hex.is_empty() || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }

    Some(ExportedSbom {
        key: key.to_string(),
        repository: repository.to_string(),
        digest: format!("sha256:{hex}"),
    })
}

/// Filesystem-safe leaf name for a repository — ECR allows `/` in names.
pub fn sanitize_repo_name(repository: &str) -> String {
    repository.replace('/', "_")
}

/// Filename stem for a report format, used in the local output filenames.
pub fn format_stem(format: &SbomReportFormat) -> &'static str {
    match format.as_str() {
        "spdx23" => "spdx",
        _ => "cyclonedx",
    }
}
```

- [ ] **Step 3: Create `repo_picker.rs`**

Create `src/providers/aws/inspector_sbom/repo_picker.rs`:

```rust
//! Choosing which exported image SBOM represents a repository.
//!
//! Inspector only exports SBOMs for images it has actually scanned, so the
//! newest image in ECR is frequently absent from an export. A repository's
//! representative SBOM is therefore the newest image that is *both* still
//! present in ECR and present in the export.

use std::collections::HashSet;

/// A live ECR image, reduced to the fields the picker needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EcrImage {
    /// Full digest, including the `sha256:` prefix.
    pub digest: String,
    /// `imagePushedAt` as epoch seconds. Images with no timestamp sort oldest.
    pub pushed_at_secs: i64,
    pub tags: Vec<String>,
}

/// The newest image (by `pushed_at_secs`) whose digest appears in `exported`.
pub fn newest_exported<'a>(
    images: &'a [EcrImage],
    exported: &HashSet<String>,
) -> Option<&'a EcrImage> {
    images
        .iter()
        .filter(|i| exported.contains(&i.digest))
        .max_by_key(|i| i.pushed_at_secs)
}

/// Every exported digest, newest ECR image first. Digests that are no longer
/// present in ECR sort last, in lexicographic order for run-to-run stability.
pub fn exported_newest_first(images: &[EcrImage], exported: &HashSet<String>) -> Vec<String> {
    let mut live: Vec<&EcrImage> = images
        .iter()
        .filter(|i| exported.contains(&i.digest))
        .collect();
    live.sort_by(|a, b| b.pushed_at_secs.cmp(&a.pushed_at_secs));

    let live_digests: HashSet<&str> = live.iter().map(|i| i.digest.as_str()).collect();
    let mut orphans: Vec<String> = exported
        .iter()
        .filter(|d| !live_digests.contains(d.as_str()))
        .cloned()
        .collect();
    orphans.sort();

    let mut out: Vec<String> = live.into_iter().map(|i| i.digest.clone()).collect();
    out.extend(orphans);
    out
}
```

- [ ] **Step 4: Declare the submodules and re-export from `mod.rs`**

In `src/providers/aws/inspector_sbom/mod.rs`, after the existing `use crate::evidence::CsvCollector;` line, insert:

```rust

mod export_keys;
mod repo_picker;

pub use export_keys::{
    belongs_to_report, format_stem, parse_export_key, sanitize_repo_name, ExportedSbom,
};
pub use repo_picker::{exported_newest_first, newest_exported, EcrImage};
```

- [ ] **Step 5: Verify**

Run:
```bash
cargo fmt
cargo clippy -- -D warnings
```
Expected: clean. (`mod.rs` does not yet call the new helpers; the `pub use` re-exports keep them from tripping `dead_code`.)

- [ ] **Step 6: Commit**

```bash
git add src/providers/aws/inspector_sbom/
git commit -m "refactor(sbom): split inspector_sbom into a module with key-parsing and image-picking helpers"
```

---

## Task 3: Scope the export by repository and resolve one SBOM per repository

**Files:**
- Modify: `src/providers/aws/inspector_sbom/mod.rs` (full rewrite of the struct, config, `CsvCollector` impl, and helper impl block; `poll_sbom_export` is kept, `download_latest_sbom` is replaced)

**Interfaces:**
- Consumes: `export_keys::*` and `repo_picker::*` from Task 2.
- Produces:
  - `InspectorSbomConfig { bucket: String, key_prefix: Option<String>, kms_key_arn: String, format: SbomReportFormat, repositories: Vec<String> }`, deriving `Clone, Debug`
  - `InspectorSbomCollector::new(inspector_config: &aws_config::SdkConfig, s3_config: &aws_config::SdkConfig, config: InspectorSbomConfig, output_dir: Option<PathBuf>) -> Self` (signature unchanged)
  - CSV headers: `Repository`, `Report ID`, `Export Status`, `Format`, `Selected Digest`, `Selected Image Tags`, `Image Pushed At`, `Exported Images`, `Raw Downloaded`, `Local Path`, `Notes`

- [ ] **Step 1: Replace the whole of `mod.rs`**

Overwrite `src/providers/aws/inspector_sbom/mod.rs` with:

```rust
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
        if let Some(filter) = self.resource_filter()? {
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
                None => notes
                    .push("No output directory configured — nothing downloaded".to_string()),
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
                        let dest =
                            root.join(format!("{}.{stem}.json", sanitize_repo_name(&repo)));
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

impl InspectorSbomCollector {
    /// Scope the export to the selected repositories. `None` means unscoped.
    fn resource_filter(&self) -> Result<Option<ResourceFilterCriteria>> {
        if self.config.repositories.is_empty() {
            return Ok(None);
        }
        let mut builder = ResourceFilterCriteria::builder();
        for repo in &self.config.repositories {
            let filter = ResourceStringFilter::builder()
                .comparison(ResourceStringComparison::Equals)
                .value(repo.clone())
                .build()
                .with_context(|| format!("building SBOM repository filter for {repo}"))?;
            builder = builder.ecr_repository_name(filter);
        }
        Ok(Some(builder.build()))
    }

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
            let detail =
                detail.with_context(|| format!("ECR describe_images for {repository}"))?;
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
```

- [ ] **Step 2: Fix the factory's now-incomplete struct literals**

`src/providers/aws/factory.rs` constructs `InspectorSbomConfig` twice (around lines 403–424) and will not compile without the new `repositories` field. In the `if has("inspector-sbom")` block, change the `Some((c, o))` arm's literal to:

```rust
                Some((c, o)) => (c.clone(), o.clone()),
```

and the `None` arm's literal to:

```rust
                None => (
                    InspectorSbomConfig {
                        bucket: String::new(),
                        key_prefix: None,
                        kms_key_arn: String::new(),
                        format: aws_sdk_inspector2::types::SbomReportFormat::Cyclonedx14,
                        repositories: Vec::new(),
                    },
                    None,
                ),
```

(The `Some` arm can now clone wholesale because `InspectorSbomConfig` derives `Clone`.)

- [ ] **Step 3: Verify**

Run:
```bash
cargo fmt
cargo clippy -- -D warnings
```
Expected: clean.

- [ ] **Step 4: Commit**

```bash
git add src/providers/aws/inspector_sbom/mod.rs src/providers/aws/factory.rs
git commit -m "feat(sbom): scope Inspector export by ECR repository and resolve one SBOM per repo"
```

---

## Task 4: ECR repository discovery helper

**Files:**
- Create: `src/providers/aws/ecr_repos.rs`
- Modify: `src/providers/aws/mod.rs`

**Interfaces:**
- Consumes: `aws_config::SdkConfig`.
- Produces: `EcrRepoSummary { name: String, uri: String }` and `pub async fn list_repositories(config: &aws_config::SdkConfig) -> Result<Vec<EcrRepoSummary>>`, sorted by `name`.

- [ ] **Step 1: Create `src/providers/aws/ecr_repos.rs`**

```rust
//! Standalone ECR repository discovery.
//!
//! Used by the TUI's SBOM repository picker and by `--sbom-all-repos`. This is
//! deliberately not a collector — nothing is written to disk.

use anyhow::{Context, Result};
use aws_sdk_ecr::Client as EcrClient;

/// One ECR repository, as shown in the SBOM repository picker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EcrRepoSummary {
    pub name: String,
    pub uri: String,
}

/// Every ECR repository in the account/region behind `config`, sorted by name.
pub async fn list_repositories(config: &aws_config::SdkConfig) -> Result<Vec<EcrRepoSummary>> {
    let client = EcrClient::new(config);
    let mut out: Vec<EcrRepoSummary> = Vec::new();
    let mut pages = client
        .describe_repositories()
        .into_paginator()
        .items()
        .send();

    while let Some(repo) = pages.next().await {
        let repo = repo.context("ECR describe_repositories")?;
        let Some(name) = repo.repository_name() else {
            continue;
        };
        out.push(EcrRepoSummary {
            name: name.to_string(),
            uri: repo.repository_uri().unwrap_or_default().to_string(),
        });
    }

    out.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(out)
}
```

- [ ] **Step 2: Declare the module**

In `src/providers/aws/mod.rs`, add `pub mod ecr_repos;` in the module declaration list, keeping the existing alphabetical position relative to `ecr_config` (i.e. immediately after `pub mod ecr_config;`).

- [ ] **Step 3: Verify**

Run:
```bash
cargo fmt
cargo clippy -- -D warnings
```
Expected: clean.

- [ ] **Step 4: Commit**

```bash
git add src/providers/aws/ecr_repos.rs src/providers/aws/mod.rs
git commit -m "feat(sbom): add reusable ECR repository discovery helper"
```

---

## Task 5: CLI flags and non-interactive wiring

**Files:**
- Modify: `src/cli.rs` (SBOM options block, currently ~lines 336–348)
- Modify: `src/runner/cli_runners.rs` (`inspector-sbom` block, currently ~lines 341–350)

**Interfaces:**
- Consumes: `InspectorSbomConfig` (Task 3), `ecr_repos::list_repositories` (Task 4).
- Produces: `Cli { sbom_key_prefix: Option<String>, sbom_repos: Option<String>, sbom_all_repos: bool }` alongside the existing `sbom_bucket` / `sbom_kms_key` / `sbom_format`.

- [ ] **Step 1: Add the three flags**

In `src/cli.rs`, inside the `// ------- Inspector SBOM export options -------` block, after the `pub sbom_format: String,` field, insert:

```rust
    /// Key prefix inside `--sbom-bucket`. Inspector appends
    /// `<FORMAT>_outputs_<report-id>/…` beneath this prefix.
    #[arg(long)]
    pub sbom_key_prefix: Option<String>,

    /// Comma-separated ECR repository names to export SBOMs for
    /// (e.g. `webapp-base,websocket-server`). Mutually exclusive with
    /// `--sbom-all-repos`.
    #[arg(long)]
    pub sbom_repos: Option<String>,

    /// Export SBOMs for every ECR repository discovered in the region.
    #[arg(long, default_value_t = false)]
    pub sbom_all_repos: bool,
```

- [ ] **Step 2: Resolve the repository list in `cli_runners.rs`**

In `src/runner/cli_runners.rs`, replace the whole `if selected.iter().any(|n| n == "inspector-sbom") { … }` block with:

```rust
    if selected.iter().any(|n| n == "inspector-sbom") {
        if cli.sbom_all_repos && cli.sbom_repos.is_some() {
            anyhow::bail!("--sbom-repos and --sbom-all-repos are mutually exclusive");
        }

        let repositories: Vec<String> = if let Some(ref list) = cli.sbom_repos {
            let names: Vec<String> = list
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
            if names.is_empty() {
                anyhow::bail!("--sbom-repos was given but contained no repository names");
            }
            names
        } else if cli.sbom_all_repos {
            let discovered = crate::providers::aws::ecr_repos::list_repositories(&config)
                .await
                .context("discovering ECR repositories for --sbom-all-repos")?;
            if discovered.is_empty() {
                anyhow::bail!(
                    "--sbom-all-repos found no ECR repositories in this account/region"
                );
            }
            eprintln!(
                "  --sbom-all-repos: exporting SBOMs for {} repositories",
                discovered.len()
            );
            discovered.into_iter().map(|r| r.name).collect()
        } else {
            Vec::new()
        };

        let sbom_cfg = crate::providers::aws::inspector_sbom::InspectorSbomConfig {
            bucket: cli.sbom_bucket.clone().unwrap_or_default(),
            key_prefix: cli.sbom_key_prefix.clone(),
            kms_key_arn: cli.sbom_kms_key.clone().unwrap_or_default(),
            format: cli.sbom_format.as_str().into(),
            repositories,
        };
        let sbom_out = cli.output.clone().unwrap_or_else(|| PathBuf::from("."));
        factory = factory.with_sbom_config(sbom_cfg, Some(sbom_out));
    }
```

If `anyhow::Context` is not already in scope in `cli_runners.rs`, add `Context` to its existing `use anyhow::{…};` line.

- [ ] **Step 3: Verify**

Run:
```bash
cargo fmt
cargo clippy -- -D warnings
cargo run -- --help 2>&1 | grep -A 1 "sbom"
```
Expected: `--sbom-bucket`, `--sbom-kms-key`, `--sbom-format`, `--sbom-key-prefix`, `--sbom-repos`, `--sbom-all-repos` all listed.

Then confirm the mutual-exclusion guard fires without touching AWS:
```bash
cargo run -- --lookback 1 --collectors inspector-sbom \
    --sbom-repos a --sbom-all-repos 2>&1 | tail -3
```
Expected: an error containing `--sbom-repos and --sbom-all-repos are mutually exclusive`.

- [ ] **Step 4: Commit**

```bash
git add src/cli.rs src/runner/cli_runners.rs
git commit -m "feat(sbom): add --sbom-repos, --sbom-all-repos, and --sbom-key-prefix"
```

---

## Task 6: Thread an SBOM config through the TUI collector build path

**Files:**
- Modify: `src/runner/collector_registry.rs`

**Interfaces:**
- Consumes: `InspectorSbomConfig` (Task 3).
- Produces: `pub fn build_csv_collectors_with_sbom(names: &[&str], config: &aws_config::SdkConfig, sbom: Option<(InspectorSbomConfig, std::path::PathBuf)>) -> Vec<Box<dyn CsvCollector>>`. The existing `build_csv_collectors` keeps its signature and delegates with `None`.

- [ ] **Step 1: Add the SBOM-aware builder**

In `src/runner/collector_registry.rs`, add to the existing `use` block:

```rust
use crate::providers::aws::inspector_sbom::InspectorSbomConfig;
```

Then replace the existing `pub fn build_csv_collectors` with:

```rust
pub fn build_csv_collectors(
    names: &[&str],
    config: &aws_config::SdkConfig,
) -> Vec<Box<dyn CsvCollector>> {
    build_csv_collectors_with_sbom(names, config, None)
}

/// Same as [`build_csv_collectors`], but lets the caller supply the Inspector
/// SBOM export destination + repository scope. Used by the TUI path, where
/// those values come from the wizard rather than CLI flags.
pub fn build_csv_collectors_with_sbom(
    names: &[&str],
    config: &aws_config::SdkConfig,
    sbom: Option<(InspectorSbomConfig, std::path::PathBuf)>,
) -> Vec<Box<dyn CsvCollector>> {
    let mut factory = AwsProviderFactory::new(
        config.clone(),
        String::new(),
        String::new(),
        names.iter().map(|s| s.to_string()).collect(),
    );
    if let Some((cfg, out)) = sbom {
        factory = factory.with_sbom_config(cfg, Some(out));
    }
    factory.csv_collectors()
}
```

- [ ] **Step 2: Verify**

Run:
```bash
cargo fmt
cargo clippy -- -D warnings
```
Expected: clean.

- [ ] **Step 3: Commit**

```bash
git add src/runner/collector_registry.rs
git commit -m "feat(sbom): allow the TUI path to inject an InspectorSbomConfig"
```

---

## Task 7: TUI wizard — destination, discovery, and repository picker screens

> **Expect a temporarily broken build inside this task.** `src/tui/ui/mod.rs`, `src/tui/events.rs`, and `src/tui/ui/frame.rs::get_hints` all `match` exhaustively on `Screen`, so `cargo check` will report non-exhaustive-match errors between Step 3 and Step 6. That is expected; the verification gate is Step 9. Follow the step order exactly — it keeps the broken window as short as possible.

**Files:**
- Modify: `src/tui/app/mod.rs`
- Modify: `src/tui/app/methods.rs`
- Create: `src/tui/ui/sbom_screens.rs`
- Modify: `src/tui/state.rs`
- Modify: `src/tui/ui/mod.rs`
- Modify: `src/tui/ui/frame.rs`
- Modify: `src/tui/events.rs`
- Modify: `src/tui/app/nav.rs`
- Modify: `src/tui/mod.rs`

**Interfaces:**
- Consumes: `ecr_repos::EcrRepoSummary` (Task 4).
- Produces on `App`:
  - `sbom_bucket_input: TextInput`, `sbom_kms_input: TextInput`, `sbom_prefix_input: TextInput`, `sbom_dest_field: usize`
  - `sbom_repo_list: Vec<crate::providers::aws::ecr_repos::EcrRepoSummary>`, `sbom_repo_cursor: usize`, `sbom_repo_selected: HashSet<usize>`, `sbom_repo_search: TextInput`
  - `selected_sbom_repos: Vec<String>`, `sbom_discovery_error: Option<String>`
  - `App::sbom_selected(&self) -> bool`, `App::visible_sbom_repos(&self) -> Vec<usize>`
- Produces `Screen::SbomDestination`, `Screen::SbomRepoDiscovery`, `Screen::SbomRepoSelection`.
- Produces `Action::SbomDiscoverRepos` in `src/tui/events.rs`.

- [ ] **Step 1: Add the App state fields**

In `src/tui/app/mod.rs`, inside `pub struct App`, immediately after the `// ── Jira project selection ───` block (the `selected_jira_project_keys` field), insert:

```rust
    // ── Inspector SBOM export (AWS) ───────────────────────────────────────────
    /// S3 bucket the Inspector SBOM export writes to. Pre-filled from
    /// `[defaults] sbom_bucket` / the first selected account.
    pub sbom_bucket_input: TextInput,
    /// KMS key ARN used to encrypt the export.
    pub sbom_kms_input: TextInput,
    /// Optional key prefix inside the bucket.
    pub sbom_prefix_input: TextInput,
    /// Focused field on SbomDestination: 0=bucket 1=kms 2=prefix.
    pub sbom_dest_field: usize,
    /// ECR repositories discovered from the first selected AWS account.
    /// Populated by the async driver when entering SbomRepoDiscovery.
    pub sbom_repo_list: Vec<crate::providers::aws::ecr_repos::EcrRepoSummary>,
    pub sbom_repo_cursor: usize,
    /// Indices into the *visible* (search-filtered) view committed by Space.
    /// Stored as indices into `sbom_repo_list`.
    pub sbom_repo_selected: HashSet<usize>,
    pub sbom_repo_search: TextInput,
    /// Repository names committed on SbomRepoSelection → SetOptions.
    pub selected_sbom_repos: Vec<String>,
    /// Set by the async driver if repository discovery itself fails.
    pub sbom_discovery_error: Option<String>,
```

Also add the `config_defaults` field, used by the pre-fill helper in Step 7. Immediately after the `sbom_discovery_error` field above, insert:

```rust
    /// `[defaults]` from config.toml, kept for per-account value resolution.
    pub config_defaults: app_config::Defaults,
```

`App::new` (`src/tui/app/mod.rs:180`) binds the loaded config as `let config = app_config::load_config().unwrap_or_default();`. Inside the struct literal it returns, immediately after the `selected_jira_project_keys: Vec::new(),` initialiser, insert:

```rust
            sbom_bucket_input: TextInput::new(
                config.defaults.sbom_bucket.as_deref().unwrap_or_default(),
            ),
            sbom_kms_input: TextInput::new(
                config.defaults.sbom_kms_key.as_deref().unwrap_or_default(),
            ),
            sbom_prefix_input: TextInput::new(
                config
                    .defaults
                    .sbom_key_prefix
                    .as_deref()
                    .unwrap_or_default(),
            ),
            sbom_dest_field: 0,
            sbom_repo_list: Vec::new(),
            sbom_repo_cursor: 0,
            sbom_repo_selected: HashSet::new(),
            sbom_repo_search: TextInput::new(""),
            selected_sbom_repos: Vec::new(),
            sbom_discovery_error: None,
            config_defaults: config.defaults.clone(),
```

`config.defaults` is read by several later initialisers in `new()` (e.g. `include_raw`, `zip`), so the `.clone()` here must come before any move of `config` — placing it in the struct literal as shown is safe because `config.account.clone()` is used the same way on the `accounts:` line.

Finally, make `inspector-sbom` opt-in. In the same function, add `"inspector-sbom",` to the `hardcoded_optins` array (`src/tui/app/mod.rs:202`), immediately after the existing `"inspector-config",` entry:

```rust
            "inspector",
            "inspector-config",
            "inspector-sbom",
```

Without this the collector is pre-selected and every AWS TUI run is forced through the SBOM destination and repository screens.

Then append two helper methods to `impl App` in `src/tui/app/methods.rs`, after `selected_inventory_types`:

```rust
    /// True when the user selected the `inspector-sbom` collector.
    pub fn sbom_selected(&self) -> bool {
        self.selected_collectors().iter().any(|k| k == "inspector-sbom")
    }

    /// Indices into `sbom_repo_list` matching the current search box,
    /// in list order. An empty search shows everything.
    pub fn visible_sbom_repos(&self) -> Vec<usize> {
        let needle = self.sbom_repo_search.value.trim().to_lowercase();
        self.sbom_repo_list
            .iter()
            .enumerate()
            .filter(|(_, r)| needle.is_empty() || r.name.to_lowercase().contains(&needle))
            .map(|(i, _)| i)
            .collect()
    }
```

- [ ] **Step 2: Create the render module (not yet declared, so not yet compiled)**

Create `src/tui/ui/sbom_screens.rs`:

```rust
use ratatui::layout::{Alignment, Constraint, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, List, ListItem, ListState, Paragraph};
use ratatui::Frame;

use super::widgets::content_inset;
use super::{
    App, AMBER, BG_MAIN, BG_SELECTED, BORDER_SUBTLE, GREEN, RED, TEXT_BRIGHT, TEXT_DIM,
    TEXT_NORMAL,
};

// ═══════════════════════════════════════════════════════════════════════════
// SBOM export destination (bucket / KMS key / prefix)
// ═══════════════════════════════════════════════════════════════════════════

pub(super) fn draw_sbom_destination(f: &mut Frame, area: Rect, app: &App) {
    let inset = content_inset(area);

    let chunks = Layout::vertical([
        Constraint::Length(1), // title
        Constraint::Length(1), // subtitle
        Constraint::Length(1), // spacer
        Constraint::Length(3), // bucket
        Constraint::Length(3), // kms
        Constraint::Length(3), // prefix
        Constraint::Fill(1),   // note
    ])
    .split(inset);

    f.render_widget(
        Paragraph::new(Span::styled(
            "Inspector SBOM Export Destination",
            Style::default()
                .fg(TEXT_BRIGHT)
                .add_modifier(Modifier::BOLD),
        ))
        .alignment(Alignment::Center),
        chunks[0],
    );

    f.render_widget(
        Paragraph::new(Span::styled(
            "↑↓ to switch field, type to edit, Enter to discover repositories",
            Style::default().fg(TEXT_DIM),
        ))
        .alignment(Alignment::Center),
        chunks[1],
    );

    let fields = [
        ("S3 Bucket (required)", &app.sbom_bucket_input.value, 0usize),
        ("KMS Key ARN (required)", &app.sbom_kms_input.value, 1usize),
        ("Key Prefix (optional)", &app.sbom_prefix_input.value, 2usize),
    ];

    for (label, value, idx) in fields {
        let focused = app.sbom_dest_field == idx;
        let border_style = if focused {
            Style::default().fg(AMBER)
        } else {
            Style::default().fg(BORDER_SUBTLE)
        };
        let shown = if focused {
            format!("{value}▏")
        } else {
            value.to_string()
        };
        f.render_widget(
            Paragraph::new(Span::styled(shown, Style::default().fg(TEXT_NORMAL))).block(
                Block::bordered()
                    .border_type(BorderType::Rounded)
                    .border_style(border_style)
                    .style(Style::default().bg(BG_MAIN))
                    .title(Span::styled(label, Style::default().fg(TEXT_DIM))),
            ),
            chunks[3 + idx],
        );
    }

    f.render_widget(
        Paragraph::new(vec![
            Line::from(Span::styled(
                "Inspector writes the export into this bucket, then grabber downloads",
                Style::default().fg(TEXT_DIM),
            )),
            Line::from(Span::styled(
                "the SBOM for the newest scanned image of each repository you pick.",
                Style::default().fg(TEXT_DIM),
            )),
        ])
        .alignment(Alignment::Center),
        chunks[6],
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// Repository discovery (async work in progress)
// ═══════════════════════════════════════════════════════════════════════════

pub(super) fn draw_sbom_repo_discovery(f: &mut Frame, area: Rect, _app: &App) {
    let inset = content_inset(area);

    let chunks = Layout::vertical([
        Constraint::Fill(1),
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Fill(1),
    ])
    .split(inset);

    f.render_widget(
        Paragraph::new(Span::styled(
            "Discovering ECR repositories…",
            Style::default()
                .fg(TEXT_BRIGHT)
                .add_modifier(Modifier::BOLD),
        ))
        .alignment(Alignment::Center),
        chunks[1],
    );

    f.render_widget(
        Paragraph::new(Span::styled(
            "Calling ecr:DescribeRepositories for the first selected AWS account",
            Style::default().fg(TEXT_DIM),
        ))
        .alignment(Alignment::Center),
        chunks[2],
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// Repository picker
// ═══════════════════════════════════════════════════════════════════════════

pub(super) fn draw_sbom_repo_selection(f: &mut Frame, area: Rect, app: &App) {
    let inset = content_inset(area);

    let chunks = Layout::vertical([
        Constraint::Length(1), // title
        Constraint::Length(1), // subtitle
        Constraint::Length(1), // spacer
        Constraint::Length(3), // search
        Constraint::Fill(1),   // list
    ])
    .split(inset);

    f.render_widget(
        Paragraph::new(Span::styled(
            "Select ECR Repositories for SBOM Export",
            Style::default()
                .fg(TEXT_BRIGHT)
                .add_modifier(Modifier::BOLD),
        ))
        .alignment(Alignment::Center),
        chunks[0],
    );

    let selected_count = app.sbom_repo_selected.len();
    f.render_widget(
        Paragraph::new(Span::styled(
            format!(
                "Space to toggle, a = all, d = none, Enter to confirm — {selected_count} selected"
            ),
            Style::default().fg(TEXT_DIM),
        ))
        .alignment(Alignment::Center),
        chunks[1],
    );

    f.render_widget(
        Paragraph::new(Span::styled(
            format!("{}▏", app.sbom_repo_search.value),
            Style::default().fg(TEXT_NORMAL),
        ))
        .block(
            Block::bordered()
                .border_type(BorderType::Rounded)
                .border_style(Style::default().fg(BORDER_SUBTLE))
                .style(Style::default().bg(BG_MAIN))
                .title(Span::styled("Filter", Style::default().fg(TEXT_DIM))),
        ),
        chunks[3],
    );

    let list_area = chunks[4];
    let visible = app.visible_sbom_repos();

    if visible.is_empty() {
        let block = Block::bordered()
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(BORDER_SUBTLE))
            .style(Style::default().bg(BG_MAIN));
        let inner = block.inner(list_area);
        f.render_widget(block, list_area);

        let v = Layout::vertical([
            Constraint::Fill(1),
            Constraint::Length(1),
            Constraint::Fill(1),
        ])
        .split(inner);

        let (msg, style) = match app.sbom_discovery_error.as_deref() {
            Some(err) => (err.to_string(), Style::default().fg(RED)),
            None if app.sbom_repo_list.is_empty() => (
                "No ECR repositories found in this account/region.".to_string(),
                Style::default().fg(TEXT_DIM),
            ),
            None => (
                "No repositories match the filter.".to_string(),
                Style::default().fg(TEXT_DIM),
            ),
        };
        f.render_widget(
            Paragraph::new(Span::styled(msg, style)).alignment(Alignment::Center),
            v[1],
        );
        return;
    }

    let mut items: Vec<ListItem> = Vec::with_capacity(visible.len());
    for (cursor_pos, &real_idx) in visible.iter().enumerate() {
        let repo = &app.sbom_repo_list[real_idx];
        let at_cursor = cursor_pos == app.sbom_repo_cursor;
        let checked = app.sbom_repo_selected.contains(&real_idx);

        let checkbox = if checked { "[✓] " } else { "[ ] " };
        let checkbox_style = if checked {
            Style::default().fg(GREEN)
        } else {
            Style::default().fg(TEXT_DIM)
        };

        let name_style = if at_cursor {
            Style::default()
                .fg(AMBER)
                .add_modifier(Modifier::BOLD)
                .bg(BG_SELECTED)
        } else {
            Style::default()
                .fg(TEXT_BRIGHT)
                .add_modifier(Modifier::BOLD)
        };

        items.push(ListItem::new(Line::from(vec![
            Span::styled(checkbox, checkbox_style),
            Span::styled(format!("{:<40}", repo.name), name_style),
            Span::styled("  ", Style::default()),
            Span::styled(repo.uri.clone(), Style::default().fg(TEXT_DIM)),
        ])));
    }

    let mut state = ListState::default();
    state.select(Some(app.sbom_repo_cursor));

    let block = Block::bordered()
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(BORDER_SUBTLE))
        .style(Style::default().bg(BG_MAIN));

    f.render_stateful_widget(
        List::new(items)
            .highlight_style(Style::default())
            .highlight_symbol("")
            .block(block),
        list_area,
        &mut state,
    );
}
```

- [ ] **Step 3: Add the three `Screen` variants**

In `src/tui/state.rs`, inside `pub enum Screen`, immediately after the `JiraProjectSelection,` variant, insert:

```rust
    /// AWS-only: S3 bucket / KMS key / prefix for the Inspector SBOM export.
    SbomDestination,
    /// AWS-only: listing ECR repositories (async work; no key handling).
    SbomRepoDiscovery,
    /// AWS-only: pick which discovered repositories need SBOMs.
    SbomRepoSelection,
```

- [ ] **Step 4: Declare and dispatch the render module**

In `src/tui/ui/mod.rs`:

1. Add `mod sbom_screens;` to the module list, immediately after `mod results;`.
2. In `draw()`'s `match app.screen`, immediately after the `Screen::JiraProjectSelection => { … }` arm, insert:

```rust
        Screen::SbomDestination => sbom_screens::draw_sbom_destination(f, content, app),
        Screen::SbomRepoDiscovery => sbom_screens::draw_sbom_repo_discovery(f, content, app),
        Screen::SbomRepoSelection => sbom_screens::draw_sbom_repo_selection(f, content, app),
```

- [ ] **Step 5: Step indicator and footer hints**

In `src/tui/ui/frame.rs`:

1. After the `STEPS_TENABLE` constant, add the two SBOM step sequences:

```rust
// Feature::Collectors — AWS with the inspector-sbom collector selected
pub(super) const STEPS_PROVIDER_ACCOUNTS_SBOM: &[&str] = &[
    "Provider",
    "Account",
    "Dates",
    "Collectors",
    "SBOM Dest",
    "Repos",
    "Options",
    "Confirm",
    "Run",
];

pub(super) const STEPS_PROVIDER_LEGACY_SBOM: &[&str] = &[
    "Provider",
    "Profile",
    "Region",
    "Dates",
    "Collectors",
    "SBOM Dest",
    "Repos",
    "Options",
    "Confirm",
    "Run",
];
```

2. Change `screen_to_step`'s signature to take the SBOM flag, and use it. Replace the signature with:

```rust
pub(super) fn screen_to_step(
    screen: &Screen,
    has_accounts: bool,
    feature: &Feature,
    selected_provider: crate::providers::CloudProvider,
    sbom_selected: bool,
) -> Option<usize> {
```

Then inside the `Feature::Collectors` branch, replace the `} else if has_accounts {` arm's body with:

```rust
            } else if has_accounts {
                match screen {
                    Screen::ProviderSelection => Some(0),
                    Screen::SelectAccount => Some(1),
                    Screen::SetDates => Some(2),
                    Screen::SelectCollectors => Some(3),
                    Screen::SbomDestination => Some(4),
                    Screen::SbomRepoDiscovery | Screen::SbomRepoSelection => Some(5),
                    Screen::SetOptions => Some(if sbom_selected { 6 } else { 4 }),
                    Screen::Confirm => Some(if sbom_selected { 7 } else { 5 }),
                    Screen::Running => Some(if sbom_selected { 8 } else { 6 }),
                    Screen::ScanSelection => None,
                    _ => None,
                }
            } else {
                match screen {
                    Screen::ProviderSelection => Some(0),
                    Screen::SelectProfile => Some(1),
                    Screen::SelectRegion => Some(2),
                    Screen::SetDates => Some(3),
                    Screen::SelectCollectors => Some(4),
                    Screen::SbomDestination => Some(5),
                    Screen::SbomRepoDiscovery | Screen::SbomRepoSelection => Some(6),
                    Screen::SetOptions => Some(if sbom_selected { 7 } else { 5 }),
                    Screen::Confirm => Some(if sbom_selected { 8 } else { 6 }),
                    Screen::Running => Some(if sbom_selected { 9 } else { 7 }),
                    Screen::ScanSelection => None,
                    _ => None,
                }
            }
```

3. In `get_hints`, immediately after the `Screen::JiraProjectSelection => …` arm, insert:

```rust
        Screen::SbomDestination => vec![
            ("↑↓", "Switch Field"),
            ("⏎", "Discover Repos"),
            ("Esc", "Back"),
        ],
        Screen::SbomRepoDiscovery => vec![],
        Screen::SbomRepoSelection => vec![
            ("↑↓", "Navigate"),
            ("␣", "Toggle"),
            ("a", "All"),
            ("d", "None"),
            ("⏎", "Confirm"),
            ("Esc", "Back"),
        ],
```

4. Back in `src/tui/ui/mod.rs`, add `STEPS_PROVIDER_ACCOUNTS_SBOM` and `STEPS_PROVIDER_LEGACY_SBOM` to the `use self::frame::{…}` import list.

There is exactly one `screen_to_step` call site (`src/tui/ui/mod.rs:74`). Add the new fifth argument to it:

```rust
    let step_info = screen_to_step(
        &app.screen,
        app.has_accounts(),
        &app.selected_feature,
        app.selected_provider,
        app.sbom_selected(),
    );
```

Then replace the `Feature::Collectors` arm of the `steps` match immediately below it with:

```rust
        Feature::Collectors => {
            use crate::providers::CloudProvider;
            if app.selected_provider == CloudProvider::Tenable {
                STEPS_TENABLE
            } else if app.has_accounts() {
                if app.sbom_selected() {
                    STEPS_PROVIDER_ACCOUNTS_SBOM
                } else {
                    STEPS_PROVIDER_ACCOUNTS
                }
            } else if app.sbom_selected() {
                STEPS_PROVIDER_LEGACY_SBOM
            } else {
                STEPS_PROVIDER_LEGACY
            }
        }
```

The inner `use crate::providers::CloudProvider;` is already present in the existing arm — keep it.

- [ ] **Step 6: Event handling**

In `src/tui/events.rs`:

1. Add `SbomDiscoverRepos,` to `enum Action`.
2. In `event_loop`'s `match handle_key(...)`, add `Action::SbomDiscoverRepos => return Ok(()),` alongside the existing `Action::StigScan => return Ok(()),`.
3. In `handle_key`'s `match app.screen.clone()`, immediately after the `Screen::JiraProjectSelection => …` arm, insert:

```rust
        Screen::SbomDestination => return handle_sbom_destination(app, key),
        Screen::SbomRepoDiscovery => {}
        Screen::SbomRepoSelection => handle_sbom_repo_selection(app, key),
```

4. Add the two handlers, after `handle_jira_project_selection`:

```rust
fn handle_sbom_destination(app: &mut App, key: KeyCode) -> Action {
    let field = match app.sbom_dest_field {
        0 => &mut app.sbom_bucket_input,
        1 => &mut app.sbom_kms_input,
        _ => &mut app.sbom_prefix_input,
    };

    match key {
        KeyCode::Char(c) => field.insert(c),
        KeyCode::Backspace => field.backspace(),
        KeyCode::Left => field.move_left(),
        KeyCode::Right => field.move_right(),
        KeyCode::Up => {
            if app.sbom_dest_field > 0 {
                app.sbom_dest_field -= 1;
            }
        }
        KeyCode::Down | KeyCode::Tab => {
            if app.sbom_dest_field < 2 {
                app.sbom_dest_field += 1;
            }
        }
        KeyCode::Enter => {
            if app.sbom_bucket_input.value.trim().is_empty() {
                app.error_msg = Some("An S3 bucket is required for the SBOM export".into());
                return Action::Continue;
            }
            if app.sbom_kms_input.value.trim().is_empty() {
                app.error_msg = Some("A KMS key ARN is required for the SBOM export".into());
                return Action::Continue;
            }
            app.error_msg = None;
            app.sbom_discovery_error = None;
            app.screen = Screen::SbomRepoDiscovery;
            return Action::SbomDiscoverRepos;
        }
        KeyCode::Esc => app.prev_screen(),
        _ => {}
    }

    Action::Continue
}

fn handle_sbom_repo_selection(app: &mut App, key: KeyCode) {
    let visible = app.visible_sbom_repos();

    match key {
        KeyCode::Up => {
            if app.sbom_repo_cursor > 0 {
                app.sbom_repo_cursor -= 1;
            }
        }
        KeyCode::Down => {
            if app.sbom_repo_cursor + 1 < visible.len() {
                app.sbom_repo_cursor += 1;
            }
        }
        KeyCode::Char(' ') => {
            if let Some(&idx) = visible.get(app.sbom_repo_cursor) {
                if app.sbom_repo_selected.contains(&idx) {
                    app.sbom_repo_selected.remove(&idx);
                } else {
                    app.sbom_repo_selected.insert(idx);
                }
            }
        }
        KeyCode::Char('a') => {
            for idx in visible {
                app.sbom_repo_selected.insert(idx);
            }
        }
        KeyCode::Char('d') => app.sbom_repo_selected.clear(),
        KeyCode::Backspace => {
            app.sbom_repo_search.backspace();
            app.sbom_repo_cursor = 0;
        }
        KeyCode::Char(c) => {
            app.sbom_repo_search.insert(c);
            app.sbom_repo_cursor = 0;
        }
        KeyCode::Enter => {
            if app.validate_current() {
                app.next_screen();
            }
        }
        KeyCode::Esc => app.prev_screen(),
        _ => {}
    }
}
```

Note the ordering inside the `match`: `KeyCode::Char(' ')`, `'a'` and `'d'` are matched before the catch-all `KeyCode::Char(c)` search arm, so they act as commands rather than filter text. Repository names containing `a`/`d` are still reachable via the filter by typing any other character first, or by scrolling.

- [ ] **Step 7: Navigation and validation**

In `src/tui/app/nav.rs`:

1. In `next_screen`, replace the `Screen::SelectCollectors => { … }` arm with:

```rust
            Screen::SelectCollectors => {
                if self.selected_provider == CloudProvider::Tenable {
                    Screen::ScanSelection
                } else if self.selected_provider == CloudProvider::Jira
                    && self
                        .selected_collectors()
                        .iter()
                        .any(|k| k == "jira-issues")
                {
                    Screen::JiraProjectSelection
                } else if self.selected_provider == CloudProvider::Aws && self.sbom_selected() {
                    self.prefill_sbom_destination();
                    Screen::SbomDestination
                } else {
                    Screen::SetOptions
                }
            }
```

Read the existing arm first and preserve its exact Tenable/Jira conditions — only the AWS/SBOM branch is new.

2. In `next_screen`, immediately after the `Screen::JiraProjectSelection => Screen::SetOptions,` arm, insert:

```rust
            Screen::SbomDestination => Screen::SbomRepoDiscovery,
            Screen::SbomRepoDiscovery => Screen::SbomRepoSelection,
            Screen::SbomRepoSelection => {
                self.selected_sbom_repos = {
                    let mut names: Vec<String> = self
                        .sbom_repo_selected
                        .iter()
                        .filter_map(|&i| self.sbom_repo_list.get(i))
                        .map(|r| r.name.clone())
                        .collect();
                    names.sort();
                    names
                };
                Screen::SetOptions
            }
```

3. In `prev_screen`, immediately after the `Screen::JiraProjectSelection => Screen::SelectCollectors,` arm, insert:

```rust
            Screen::SbomDestination => Screen::SelectCollectors,
            Screen::SbomRepoDiscovery => Screen::SbomDestination,
            Screen::SbomRepoSelection => Screen::SbomDestination,
```

4. In `prev_screen`, replace the `Screen::SetOptions => match self.selected_feature { … }` arm's `Feature::Collectors` line with:

```rust
                Feature::Collectors => {
                    if self.selected_provider == CloudProvider::Aws && self.sbom_selected() {
                        Screen::SbomRepoSelection
                    } else {
                        Screen::SelectCollectors
                    }
                }
```

5. In `validate_current`, immediately before the final `_ => true,` arm, insert:

```rust
            Screen::SbomRepoSelection => {
                if self.sbom_repo_selected.is_empty() {
                    self.error_msg = Some(
                        "Select at least one repository (Space to toggle, 'a' for all)".into(),
                    );
                    return false;
                }
                true
            }
```

6. In `reset`, immediately after the `self.selected_was_scan_ids.clear();` line, insert:

```rust
        self.sbom_dest_field = 0;
        self.sbom_repo_cursor = 0;
        self.sbom_repo_selected.clear();
        self.sbom_repo_search.clear();
        self.sbom_repo_list.clear();
        self.selected_sbom_repos.clear();
        self.sbom_discovery_error = None;
```

7. Add the pre-fill helper to `impl App` in `src/tui/app/nav.rs`, after `reset`:

```rust
    /// Pre-fill the SBOM destination fields from the first selected AWS
    /// account, falling back to whatever `[defaults]` already put there.
    pub fn prefill_sbom_destination(&mut self) {
        let defaults = self.config_defaults.clone();
        let acct = self
            .selected_account_indices()
            .into_iter()
            .filter_map(|i| self.accounts.get(i))
            .find(|a| a.provider == CloudProvider::Aws)
            .cloned();

        if let Some(acct) = acct {
            if let Some(b) = acct.sbom_bucket_resolved(&defaults) {
                if !b.is_empty() {
                    self.sbom_bucket_input = crate::tui::state::TextInput::new(&b);
                }
            }
            if let Some(k) = acct.sbom_kms_key_resolved(&defaults) {
                if !k.is_empty() {
                    self.sbom_kms_input = crate::tui::state::TextInput::new(&k);
                }
            }
            if let Some(p) = acct.sbom_key_prefix_resolved(&defaults) {
                if !p.is_empty() {
                    self.sbom_prefix_input = crate::tui::state::TextInput::new(&p);
                }
            }
        }
    }
```

This relies on the `config_defaults` field added in Step 1. `Defaults` already derives `Clone`, and `Account` derives `Clone`, so both `.clone()` calls above compile as written — the clones also avoid holding an immutable borrow of `self.accounts` while assigning to `self.sbom_*_input`.

- [ ] **Step 8: Let the wizard hand control back for async discovery**

In `src/tui/mod.rs`, in `pub fn run(mut app: App)`, extend the terminal-exit condition to:

```rust
    if app.screen == Screen::Running
        || app.screen == Screen::Results
        || app.screen == Screen::SbomRepoDiscovery
        || app.screen == Screen::StigRemediationScanning
        || app.screen == Screen::StigRemediationApplying
    {
        Ok(Some(app))
    } else {
        Ok(None)
    }
```

- [ ] **Step 9: Verify the whole task**

Run:
```bash
cargo fmt
cargo clippy -- -D warnings
```
Expected: clean. (This is the first point in this task where a clean build is expected.)

Then confirm the wizard is navigable end-to-end. Launch the TUI, pick Collectors → AWS → an account → dates, search `sbom` in the collector picker, select **Inspector2 SBOM Export**, and press Enter:

```bash
cargo run
```
Expected: the "Inspector SBOM Export Destination" screen appears with the step indicator reading `SBOM Dest` (step 5 of 9 with accounts configured). Pressing Enter with an empty bucket shows the red banner "An S3 bucket is required for the SBOM export". Filling both required fields and pressing Enter shows "Discovering ECR repositories…" and then the picker (empty until Task 8 populates it — that is expected at this point). Esc from the picker returns to the destination screen; Esc again returns to the collector picker. Quit with Esc/`q`.

- [ ] **Step 10: Commit**

```bash
git add src/tui/
git commit -m "feat(sbom): add SBOM destination, discovery, and repository-picker screens to the TUI"
```

---

## Task 8: Wire discovery and the SBOM config into the TUI session

**Files:**
- Modify: `src/runner/tui_session.rs`

**Interfaces:**
- Consumes: `ecr_repos::list_repositories` (Task 4), `InspectorSbomConfig` (Task 3), `build_csv_collectors_with_sbom` (Task 6), the App fields and `Screen::SbomRepoDiscovery` (Task 7).
- Produces: nothing new; this is the integration point.

- [ ] **Step 1: Handle `Screen::SbomRepoDiscovery` in the session loop**

In `src/runner/tui_session.rs`, immediately before the existing `if app.screen == crate::tui::Screen::StigRemediationScanning {` block, insert:

```rust
        if app.screen == crate::tui::Screen::SbomRepoDiscovery {
            let mut terminal = setup_terminal()?;
            terminal.draw(|f| crate::tui::ui::draw(f, &app))?;

            // Discover from the first selected AWS account. The chosen
            // repository names then apply to every account/region in the run.
            let target = app
                .selected_account_indices()
                .into_iter()
                .filter_map(|i| app.accounts.get(i))
                .find(|a| a.provider == crate::providers::CloudProvider::Aws)
                .map(|a| {
                    (
                        a.profile.clone().unwrap_or_default(),
                        a.region.clone().unwrap_or_else(|| app.selected_region()),
                    )
                })
                .unwrap_or_else(|| {
                    (
                        app.profiles
                            .get(app.profile_cursor)
                            .cloned()
                            .unwrap_or_default(),
                        app.selected_region(),
                    )
                });

            let (profile, region) = target;
            let mut loader =
                aws_config::defaults(BehaviorVersion::latest()).region(Region::new(region.clone()));
            if !profile.is_empty() && profile != "default" {
                loader = loader.profile_name(&profile);
            }
            let discovery_config = loader.load().await;

            match crate::providers::aws::ecr_repos::list_repositories(&discovery_config).await {
                Ok(repos) => {
                    app.sbom_repo_list = repos;
                    app.sbom_repo_cursor = 0;
                    app.sbom_repo_selected.clear();
                    app.sbom_repo_search.clear();
                    app.sbom_discovery_error = None;
                }
                Err(e) => {
                    app.sbom_repo_list.clear();
                    app.sbom_discovery_error = Some(format!(
                        "ECR discovery failed for profile '{profile}' in {region}: {e:#}"
                    ));
                }
            }

            app.screen = crate::tui::Screen::SbomRepoSelection;
            restore_terminal(&mut terminal)?;
            continue;
        }
```

- [ ] **Step 2: Capture the SBOM config before the prep loop**

In `src/runner/tui_session.rs`, next to the existing `let inventory_types = app.selected_inventory_types();` line (in the block that captures state before entering the prep loop), add:

```rust
            // Capture the Inspector SBOM export settings before the prep loop.
            let sbom_run_config: Option<crate::providers::aws::inspector_sbom::InspectorSbomConfig> =
                if app.sbom_selected() {
                    let prefix = app.sbom_prefix_input.value.trim().to_string();
                    Some(
                        crate::providers::aws::inspector_sbom::InspectorSbomConfig {
                            bucket: app.sbom_bucket_input.value.trim().to_string(),
                            key_prefix: if prefix.is_empty() { None } else { Some(prefix) },
                            kms_key_arn: app.sbom_kms_input.value.trim().to_string(),
                            format: aws_sdk_inspector2::types::SbomReportFormat::Cyclonedx14,
                            repositories: app.selected_sbom_repos.clone(),
                        },
                    )
                } else {
                    None
                };
```

- [ ] **Step 3: Pass it into every regional/single-region CSV collector build**

There are two `collector_registry::build_csv_collectors(&regional_csv_keys, &rcfg)` / `build_csv_collectors(&names_ref, &work_config)` call sites that can produce `inspector-sbom` (the global-keys call site cannot — `inspector-sbom` is not in `GLOBAL_COLLECTOR_KEYS`). Change both to the SBOM-aware variant.

For the per-region call site, replace:

```rust
                                collector_registry::build_csv_collectors(&regional_csv_keys, &rcfg),
```

with:

```rust
                                collector_registry::build_csv_collectors_with_sbom(
                                    &regional_csv_keys,
                                    &rcfg,
                                    sbom_run_config
                                        .clone()
                                        .map(|c| (c, rdir.clone())),
                                ),
```

`rdir` is already bound on the line above the `regional_collectors.push((…))` call (`src/runner/tui_session.rs:625`, `let rdir = out_base.join(region_name).join(date_path_suffix());`), so it is in scope as written.

For the single-region call site, replace:

```rust
                    collector_registry::build_csv_collectors(&names_ref, &work_config)
```

with:

```rust
                    collector_registry::build_csv_collectors_with_sbom(
                        &names_ref,
                        &work_config,
                        sbom_run_config
                            .clone()
                            .map(|c| (c, out_base.clone())),
                    )
```

`out_base` is bound once per account at `src/runner/tui_session.rs:522` (`let out_base = output_path.clone().unwrap_or_else(|| PathBuf::from("."));`) and is therefore in scope at both call sites. The SBOM files land under the same account directory the CSVs go to.

- [ ] **Step 4: Verify**

Run:
```bash
cargo fmt
cargo clippy -- -D warnings
```
Expected: clean.

Then run the wizard against a real AWS account that has ECR repositories:
```bash
cargo run
```
Expected: after entering a bucket and KMS ARN, the repository picker lists every ECR repository in the account/region with its URI. Select two, confirm, finish the wizard, and let collection run. Expected on completion:
- `Inspector_SBOM_Export-*.csv` contains one row per selected repository, with a populated `Selected Digest`, `Selected Image Tags`, `Image Pushed At`, and `Local Path`.
- `SBOM/<region>/<repo>.cyclonedx.json` exists for each selected repository that had a scanned image.
- `SBOM/<region>/raw/` contains the per-image SBOMs.
- A repository Inspector has never scanned yields a row whose `Notes` reads `Inspector produced no SBOM for this repository — no scanned images` — the case that produced `ERROR: No downloaded SBOM matched current images` in the original shell test.

If discovery fails (e.g. expired SSO), the picker shows the red `ECR discovery failed for profile '…' in …` message rather than an empty list.

- [ ] **Step 5: Commit**

```bash
git add src/runner/tui_session.rs
git commit -m "feat(sbom): discover ECR repos in the TUI and pass the SBOM config into collection"
```

---

## Task 9: Documentation

**Files:**
- Modify: `README.md` (SBOM flag row, ~line 313)
- Modify: `docs/cli-reference.md` (SBOM flags section ~lines 530–545; collector table row ~line 762)

**Interfaces:**
- Consumes: the flags from Task 5 and the config keys from Task 1.
- Produces: nothing code-facing.

- [ ] **Step 1: Update the README flag row**

In `README.md`, replace the existing SBOM row:

```markdown
| `--sbom-bucket` / `--sbom-kms-key` / `--sbom-format` | — / — / `cyclonedx14` | Inspector V2 SBOM export destination + format (`cyclonedx14` or `spdx23`) for the `inspector-sbom` collector |
```

with:

```markdown
| `--sbom-bucket` / `--sbom-kms-key` / `--sbom-format` | — / — / `cyclonedx14` | Inspector V2 SBOM export destination + format (`cyclonedx14` or `spdx23`) for the `inspector-sbom` collector. Also settable as `sbom_bucket` / `sbom_kms_key` in `[defaults]` or an `[[account]]` block |
| `--sbom-key-prefix` | — | Key prefix inside `--sbom-bucket` |
| `--sbom-repos` / `--sbom-all-repos` | — / `false` | Scope the SBOM export to named ECR repositories, or to every repository in the region. Omit both to export the whole account. In the TUI these are chosen interactively from a discovered repository list |
```

- [ ] **Step 2: Rewrite the `docs/cli-reference.md` SBOM section**

Replace the SBOM flags section (the paragraph beginning "These flags configure the `inspector-sbom` collector", its table, the "When `--sbom-bucket` is omitted" sentence, and the example command) with:

```markdown
These flags configure the `inspector-sbom` collector, which triggers an AWS Inspector V2 SBOM export, polls until it completes, then downloads the results from S3. Required only when using key `inspector-sbom` in `--collectors`.

| Flag | Default | Description |
|---|---|---|
| `--sbom-bucket <BUCKET>` | _(required)_ | S3 bucket where Inspector should write the SBOM export |
| `--sbom-kms-key <ARN>` | _(required)_ | KMS key ARN used to encrypt the export in S3 |
| `--sbom-format <FORMAT>` | `cyclonedx14` | SBOM format: `cyclonedx14` or `spdx23` |
| `--sbom-key-prefix <PREFIX>` | — | Key prefix inside the bucket. Inspector appends `<FORMAT>_outputs_<report-id>/…` beneath it |
| `--sbom-repos <A,B,C>` | — | Comma-separated ECR repository names to export. Scopes the export via Inspector's `ecrRepositoryName` filter |
| `--sbom-all-repos` | `false` | Discover every ECR repository in the region and export all of them. Mutually exclusive with `--sbom-repos` |

`--sbom-bucket`, `--sbom-kms-key`, and `--sbom-key-prefix` can also be set as `sbom_bucket`, `sbom_kms_key`, and `sbom_key_prefix` in `[defaults]` or in an `[[account]]` block; the env vars `GRABBER_SBOM_BUCKET` and `GRABBER_SBOM_KMS_KEY` win over both. When no bucket or KMS key is resolved, the collector emits a `SKIPPED` row explaining what is missing instead of failing.

When neither `--sbom-repos` nor `--sbom-all-repos` is given, the export covers the whole account — the pre-existing behaviour.

### What lands on disk

For each in-scope repository the collector writes, relative to the run's output directory:

- `SBOM/<region>/<repo>.cyclonedx.json` — the SBOM for the **newest image that is both still in ECR and actually present in the export**. Inspector only exports SBOMs for images it has scanned, so this is frequently not the newest image in the repository.
- `SBOM/<region>/raw/<repo>_<digest>.cyclonedx.json` — every exported image for that repository, newest first, up to 25 per repository. Anything beyond the cap is counted in the CSV's `Notes` column.

The `Inspector_SBOM_Export-*.csv` evidence file carries one row per repository: `Repository`, `Report ID`, `Export Status`, `Format`, `Selected Digest`, `Selected Image Tags`, `Image Pushed At`, `Exported Images`, `Raw Downloaded`, `Local Path`, `Notes`. A repository Inspector has never scanned yields a row whose `Notes` explains that no SBOM was produced.

### Example

```bash
grabber --lookback 30 \
        --collectors inspector-sbom \
        --sbom-bucket my-sbom-exports \
        --sbom-kms-key arn:aws:kms:us-east-1:123456789012:key/abc-123 \
        --sbom-format cyclonedx14 \
        --sbom-repos webapp-base,websocket-server
```

### TUI flow

Selecting **Inspector2 SBOM Export** in the interactive collector picker adds two wizard steps after it:

1. **SBOM Dest** — S3 bucket, KMS key ARN, and optional key prefix, pre-filled from `[defaults]` / the first selected AWS account.
2. **Repos** — every ECR repository discovered in the first selected AWS account, filterable, with `Space` to toggle, `a` for all, `d` for none. At least one repository must be selected.

The chosen repository names apply to every account and region in the run.
```

- [ ] **Step 3: Update the collector table row**

In `docs/cli-reference.md`, replace:

```markdown
| `inspector-sbom` | CSV | Inspector2 SBOM export (requires `--sbom-bucket`, `--sbom-kms-key`) |
```

with:

```markdown
| `inspector-sbom` | CSV | Inspector2 SBOM export, per ECR repository (requires `--sbom-bucket`, `--sbom-kms-key`; scope with `--sbom-repos` / `--sbom-all-repos`) |
```

- [ ] **Step 4: Verify**

Run:
```bash
grep -n "sbom" README.md docs/cli-reference.md
```
Expected: every flag added in Task 5 (`--sbom-key-prefix`, `--sbom-repos`, `--sbom-all-repos`) and every config key from Task 1 (`sbom_bucket`, `sbom_kms_key`, `sbom_key_prefix`) appears, and no claim references a flag that does not exist in `cargo run -- --help`.

Cross-check the flag list against the binary:
```bash
cargo run -- --help 2>&1 | grep "sbom"
```
Expected: the documented set and the actual set match exactly.

- [ ] **Step 5: Commit**

```bash
git add README.md docs/cli-reference.md
git commit -m "docs(sbom): document per-repository SBOM export flags, config keys, and output layout"
```

---

## Notes on what this plan deliberately does not do

- **No per-account repository selection.** One repository list applies to the whole run (stated in Global Constraints). Repositories absent from a given account produce an explanatory CSV row rather than an error.
- **No SBOM format choice in the TUI.** The TUI hard-codes `cyclonedx14`; `--sbom-format` remains CLI-only. Adding a format toggle means another wizard field for a setting that rarely changes.
- **No S3 cleanup.** The export stays in the bucket. Lifecycle policy on the bucket is the right tool for that, not the collector.
- **No `fedramp_mapping()` change.** `filename_prefix()` stays `Inspector_SBOM_Export`, so the existing bundled FedRAMP control annotation continues to apply unchanged.
