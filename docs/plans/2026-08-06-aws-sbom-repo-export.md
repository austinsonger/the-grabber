# AWS SBOM Export — Per-Repository Selection Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the AWS `inspector-sbom` collector list every ECR repository it discovers, let the user pick which ones they need SBOMs for, scope the Inspector export to exactly those repositories, and land one clearly-named CycloneDX/SPDX file per repository representing the newest image Inspector actually exported.

**Architecture:** `inspector_sbom.rs` becomes a directory module. The Inspector export request gains `resource_filter_criteria.ecr_repository_name` so AWS itself scopes the export to the selected repositories. After the export succeeds the collector lists the export's S3 objects, recovers repository + image digest from each object *key* (the JSON body does not carry the repository name reliably), intersects those digests with live `ecr:DescribeImages` output, and picks the newest image present in both — because Inspector only exports SBOMs for images it has scanned, so the newest image in ECR is frequently absent from the export. Repository discovery and selection is surfaced as a three-screen TUI sub-flow (destination → discovery → repo picker) reusing the existing "exit the TUI, do async work, re-enter" pattern from `StigRemediationScanning`, and as `--sbom-repos` / `--sbom-all-repos` on the flag-driven CLI.

**Tech Stack:** Rust, tokio, `aws-sdk-inspector2` 1.x, `aws-sdk-ecr` 1.x, `aws-sdk-s3` 1.x, `ratatui` + `crossterm`, `clap`, `anyhow`, `chrono`.

## Global Constraints

- Work on `main`. Do **not** create a feature branch.
- **Verification gate per task** (revised 2026-08-06 after measuring the repo): `cargo fmt` clean, `cargo build` clean, `cargo test` clean, and **zero clippy warnings in the files the task modified**. Repo-wide `cargo clippy -- -D warnings` currently reports ~50 pre-existing warnings on rust 1.94 (`too_many_arguments`, `ptr_arg`, `type_complexity`, `dead_code`, doc formatting) in files this feature does not own — notably `src/runner/tui_runners.rs` and `src/runner/tui_session.rs`. Do **not** fix that debt as part of this plan, and do not treat it as a task failure. Check your own files with `cargo clippy --message-format=short 2>&1 | grep '<your file>'`.
- **Transient dead code is expected.** Definitions land before their callers (config keys in Task 1 are first read in Tasks 5 and 8; helpers in Tasks 2/4/6 gain callers in Tasks 3/5/7/8). Note unused-until-wired items in your report; do **not** add `#[allow(dead_code)]`. Task 8's verification confirms every one has acquired a real caller.
- No `unwrap()` / `expect()` in production code. Use `anyhow::Result` / `anyhow::Context`, `anyhow::bail!` for early exits.
- Imports grouped std → external crates → `crate::*`, blank line between groups.
- **Unit tests are required for every unit of logic that can be tested without AWS credentials.** Follow the repository's existing convention: an in-file `#[cfg(test)] mod tests { use super::*; … }` block, and `App::new(vec![])` as the TUI test harness (see `src/tui/app/mod.rs:418` and `src/tui/events.rs:806`). Code that only orchestrates AWS SDK calls (`ecr_repos::list_repositories`, the collector's `list_exported` / `list_ecr_images` / `download_object`) is exempt — there is no mocking layer in this codebase, and adding one is out of scope. Verification for every task is `cargo fmt`, `cargo clippy -- -D warnings`, `cargo test`, and the stated manual check.
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

- [ ] **Step 5: Add tests for `export_keys.rs`**

Append to `src/providers/aws/inspector_sbom/export_keys.rs`. The `REAL_KEY` constant is a verbatim key from a real export — do not alter it.

```rust
#[cfg(test)]
mod tests {
    use super::*;

    const REAL_KEY: &str = "CYCLONEDX_1_4_outputs_75fe89e2-aad1-4a7e-8240-44d70e687eeb/\
account=187940674018/resource=AWS_ECR_CONTAINER_IMAGE/\
arn:aws:ecr:us-east-1:187940674018:repository_webapp-legacyassets_\
sha256:1ffd88db3d0754bceaa663a63a789c6b57bce154af36c8a2f7210bfaed943660_CYCLONEDX_1_4.json";

    #[test]
    fn parses_a_real_export_key() {
        let parsed = parse_export_key(REAL_KEY).expect("real key should parse");
        assert_eq!(parsed.repository, "webapp-legacyassets");
        assert_eq!(
            parsed.digest,
            "sha256:1ffd88db3d0754bceaa663a63a789c6b57bce154af36c8a2f7210bfaed943660"
        );
        assert_eq!(parsed.key, REAL_KEY);
    }

    #[test]
    fn parses_repository_names_containing_underscores() {
        let key = "p/CYCLONEDX_1_4_outputs_r/arn:aws:ecr:us-east-1:1:repository_my_app_name_\
sha256:abc123_CYCLONEDX_1_4.json";
        let parsed = parse_export_key(key).expect("underscored repo should parse");
        assert_eq!(parsed.repository, "my_app_name");
        assert_eq!(parsed.digest, "sha256:abc123");
    }

    #[test]
    fn parses_namespaced_repository_names() {
        // ECR allows `/` in repository names; the parser must not treat it as
        // a key separator.
        let key = "CYCLONEDX_1_4_outputs_r/arn:aws:ecr:us-east-1:1:repository_team/service_\
sha256:def456_CYCLONEDX_1_4.json";
        let parsed = parse_export_key(key).expect("namespaced repo should parse");
        assert_eq!(parsed.repository, "team/service");
        assert_eq!(parsed.digest, "sha256:def456");
    }

    #[test]
    fn parses_spdx_keys() {
        let key = "arn:aws:ecr:us-east-1:1:repository_app_sha256:aa11_SPDX_2_3.json";
        let parsed = parse_export_key(key).expect("spdx key should parse");
        assert_eq!(parsed.repository, "app");
        assert_eq!(parsed.digest, "sha256:aa11");
    }

    #[test]
    fn rejects_non_ecr_and_malformed_keys() {
        // Lambda resources carry no `repository_` marker.
        assert!(parse_export_key(
            "CYCLONEDX_1_4_outputs_r/resource=AWS_LAMBDA_FUNCTION/arn:aws:lambda:x:1:function_f.json"
        )
        .is_none());
        // No digest segment.
        assert!(parse_export_key("repository_app_CYCLONEDX_1_4.json").is_none());
        // Empty repository name.
        assert!(parse_export_key("repository__sha256:aa11_CYCLONEDX_1_4.json").is_none());
        // Non-hex digest.
        assert!(parse_export_key("repository_app_sha256:zzzz_CYCLONEDX_1_4.json").is_none());
        // Digest not terminated by `_`.
        assert!(parse_export_key("repository_app_sha256:aa11").is_none());
    }

    #[test]
    fn belongs_to_report_matches_only_its_own_report() {
        assert!(belongs_to_report(
            REAL_KEY,
            "75fe89e2-aad1-4a7e-8240-44d70e687eeb"
        ));
        assert!(!belongs_to_report(REAL_KEY, "00000000-0000-0000-0000-000000000000"));
        // A report id appearing outside the `_outputs_<id>/` segment must not match.
        assert!(!belongs_to_report("prefix-abc/arn:...json", "abc"));
    }

    #[test]
    fn sanitizes_namespaced_repository_names() {
        assert_eq!(sanitize_repo_name("team/service"), "team_service");
        assert_eq!(sanitize_repo_name("plain"), "plain");
    }

    #[test]
    fn format_stem_maps_both_formats() {
        assert_eq!(format_stem(&SbomReportFormat::Cyclonedx14), "cyclonedx");
        assert_eq!(format_stem(&SbomReportFormat::Spdx23), "spdx");
    }
}
```

- [ ] **Step 6: Add tests for `repo_picker.rs`**

Append to `src/providers/aws/inspector_sbom/repo_picker.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn img(digest: &str, pushed: i64) -> EcrImage {
        EcrImage {
            digest: digest.to_string(),
            pushed_at_secs: pushed,
            tags: vec![],
        }
    }

    fn set(digests: &[&str]) -> HashSet<String> {
        digests.iter().map(|d| d.to_string()).collect()
    }

    #[test]
    fn picks_the_newest_image_that_was_actually_exported() {
        // The regression this whole feature exists for: the newest image in
        // ECR (`newest`) was never scanned, so it is absent from the export.
        let images = vec![img("newest", 300), img("middle", 200), img("oldest", 100)];
        let exported = set(&["middle", "oldest"]);

        let chosen = newest_exported(&images, &exported).expect("middle should be chosen");
        assert_eq!(chosen.digest, "middle");
    }

    #[test]
    fn returns_none_when_no_exported_digest_is_still_in_ecr() {
        let images = vec![img("a", 100)];
        assert!(newest_exported(&images, &set(&["gone"])).is_none());
    }

    #[test]
    fn returns_none_for_an_empty_export() {
        let images = vec![img("a", 100)];
        assert!(newest_exported(&images, &HashSet::new()).is_none());
    }

    #[test]
    fn images_without_a_push_timestamp_lose_to_timestamped_ones() {
        let images = vec![img("undated", 0), img("dated", 50)];
        let chosen = newest_exported(&images, &set(&["undated", "dated"])).expect("a pick");
        assert_eq!(chosen.digest, "dated");
    }

    #[test]
    fn orders_exported_digests_newest_first() {
        let images = vec![img("a", 100), img("b", 300), img("c", 200)];
        let ordered = exported_newest_first(&images, &set(&["a", "b", "c"]));
        assert_eq!(ordered, vec!["b", "c", "a"]);
    }

    #[test]
    fn orphaned_digests_sort_last_and_deterministically() {
        // `zz` and `yy` were exported but are no longer in ECR. They must come
        // after every live image, in a stable order across runs.
        let images = vec![img("live-old", 100), img("live-new", 200)];
        let ordered = exported_newest_first(&images, &set(&["live-old", "live-new", "zz", "yy"]));
        assert_eq!(ordered, vec!["live-new", "live-old", "yy", "zz"]);
    }

    #[test]
    fn ignores_live_images_that_were_not_exported() {
        let images = vec![img("exported", 100), img("not-exported", 200)];
        let ordered = exported_newest_first(&images, &set(&["exported"]));
        assert_eq!(ordered, vec!["exported"]);
    }
}
```

- [ ] **Step 7: Verify**

Run:
```bash
cargo fmt
cargo clippy -- -D warnings
cargo test inspector_sbom
```
Expected: build clean; all 15 tests in the two new modules pass (8 in `export_keys`, 7 in `repo_picker`). If `parses_a_real_export_key` fails, the line-continuation backslashes in `REAL_KEY` were mangled — the constant must contain no literal newlines or spaces.

- [ ] **Step 8: Commit**

```bash
git add src/providers/aws/inspector_sbom/
git commit -m "refactor(sbom): split inspector_sbom into a module with tested key-parsing and image-picking helpers"
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

- [ ] **Step 2: Harden the export-key anchor against a colliding key prefix**

Task 2's `parse_export_key` anchors on the first occurrence of `"repository_"`. The S3 key begins with the user-supplied `--sbom-key-prefix`, so a prefix that itself contains `repository_` (e.g. `sbom_key_prefix = "repository_backups"`) would anchor in the prefix and misparse every key into a wrong repository or a silent `None`. The ARN segment is always `:repository_`, so anchoring on that is unambiguous.

In `src/providers/aws/inspector_sbom/export_keys.rs`, change the anchor line inside `parse_export_key` from:

```rust
    let after_marker = key.split_once("repository_")?.1;
```

to:

```rust
    // Anchor on the ARN's `:repository_` segment, not a bare `repository_`:
    // the key begins with a user-supplied prefix that could contain the latter.
    let after_marker = key.split_once(":repository_")?.1;
```

Update the doc comment above `parse_export_key` if it names the old marker. Then add this test to that file's existing `#[cfg(test)] mod tests` block:

```rust
    #[test]
    fn a_key_prefix_containing_repository_does_not_confuse_the_anchor() {
        let key = "repository_backups/CYCLONEDX_1_4_outputs_r/\
arn:aws:ecr:us-east-1:1:repository_real-app_sha256:aa11_CYCLONEDX_1_4.json";
        let parsed = parse_export_key(key).expect("should anchor on the ARN segment");
        assert_eq!(parsed.repository, "real-app");
        assert_eq!(parsed.digest, "sha256:aa11");
    }
```

Check the existing tests still pass unchanged — the previously added cases all contain `:repository_`, except any that were written with a bare `repository_` at the very start of the string. If `rejects_non_ecr_and_malformed_keys` or another case used a bare `repository_...` with no leading colon, prefix those literals with `arn:aws:ecr:us-east-1:1` so they still exercise the intended branch rather than failing at the anchor. Do not weaken an assertion to make it pass.

- [ ] **Step 3: Fix the factory's now-incomplete struct literals**

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

- [ ] **Step 4: Add tests for the free functions**

Append to `src/providers/aws/inspector_sbom/mod.rs`:

```rust
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
            "app", "r-1", "Succeeded", "cyclonedx14", "sha256:aa", "latest", "2026-08-05T00:00:00+00:00",
            3, 2, "/tmp/app.cyclonedx.json", &notes,
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
```

Note: this deliberately does **not** restore the pre-refactor file's `sbom_format_parsing` test. That test asserted `SbomReportFormat::from("cyclonedx14").as_str() == "cyclonedx14"`, which only passes because an unrecognised string becomes an `Unknown` variant that echoes itself back. It documented a bug rather than a requirement. The two format tests above replace it, and Task 5 fixes the CLI path that bug affects.

Also note: `format_stem` in `export_keys.rs` matches on the enum variant (`SbomReportFormat::Spdx23 => "spdx", _ => "cyclonedx"`), not on `as_str()`. Keep it that way — matching `as_str()` against `"spdx23"` can never succeed.

- [ ] **Step 5: Verify**

Run:
```bash
cargo fmt
cargo build
cargo test inspector_sbom
cargo clippy --message-format=short 2>&1 | grep inspector_sbom
```
Expected: build clean; every test in the module passes (Task 2's fifteen, plus the new prefix-collision test, plus the seven added here); no clippy warnings naming an `inspector_sbom` file.

The two row-shape tests are the guard that matters most here: `headers()` and the row builders must stay the same length, or every downstream CSV is silently misaligned. If either fails with a length mismatch, fix the row builder — not the assertion.

- [ ] **Step 6: Commit**

```bash
git add src/providers/aws/inspector_sbom/ src/providers/aws/factory.rs
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
            let names = parse_sbom_repos(list);
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
            format: parse_sbom_format(&cli.sbom_format)?,
            repositories,
        };
        let sbom_out = cli.output.clone().unwrap_or_else(|| PathBuf::from("."));
        factory = factory.with_sbom_config(sbom_cfg, Some(sbom_out));
    }
```

If `anyhow::Context` is not already in scope in `cli_runners.rs`, add `Context` to its existing `use anyhow::{…};` line.

- [ ] **Step 3: Add the `parse_sbom_repos` and `parse_sbom_format` helpers and their tests**

Still in `src/runner/cli_runners.rs`, add both helpers at module level (outside any function):

```rust
/// Split a `--sbom-repos` value into repository names, trimming whitespace and
/// dropping empty entries. An all-empty input yields an empty Vec, which the
/// caller rejects.
fn parse_sbom_repos(list: &str) -> Vec<String> {
    list.split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

/// Map the user-facing `--sbom-format` spelling onto the SDK enum.
///
/// This must NOT use `SbomReportFormat::from(&str)`: that only recognises the
/// AWS wire values (`CYCLONEDX_1_4`, `SPDX_2_3`) and turns anything else into an
/// `Unknown` variant, which the Inspector API then rejects. The previous code
/// (`cli.sbom_format.as_str().into()`) had exactly that bug, so
/// `--sbom-format cyclonedx14` — the documented default — produced an invalid
/// request.
fn parse_sbom_format(value: &str) -> Result<aws_sdk_inspector2::types::SbomReportFormat> {
    use aws_sdk_inspector2::types::SbomReportFormat;

    match value.trim().to_lowercase().as_str() {
        "cyclonedx14" | "cyclonedx_1_4" | "cyclonedx" => Ok(SbomReportFormat::Cyclonedx14),
        "spdx23" | "spdx_2_3" | "spdx" => Ok(SbomReportFormat::Spdx23),
        other => anyhow::bail!(
            "unsupported --sbom-format '{other}': expected 'cyclonedx14' or 'spdx23'"
        ),
    }
}
```

This is a genuine bug fix, not a refactor — keep the doc comment explaining why, so nobody reintroduces `.into()`.

Then append the test module to the same file (or add these tests to its existing `#[cfg(test)] mod tests` block if one is already present):

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_a_plain_comma_list() {
        assert_eq!(
            parse_sbom_repos("webapp-base,websocket-server"),
            vec!["webapp-base", "websocket-server"]
        );
    }

    #[test]
    fn trims_whitespace_around_names() {
        assert_eq!(
            parse_sbom_repos(" webapp-base , websocket-server "),
            vec!["webapp-base", "websocket-server"]
        );
    }

    #[test]
    fn drops_empty_entries_from_trailing_and_doubled_commas() {
        assert_eq!(parse_sbom_repos("a,,b,"), vec!["a", "b"]);
    }

    #[test]
    fn preserves_namespaced_repository_names() {
        assert_eq!(parse_sbom_repos("team/service,other"), vec!["team/service", "other"]);
    }

    #[test]
    fn all_empty_input_yields_nothing_so_the_caller_can_reject_it() {
        assert!(parse_sbom_repos("").is_empty());
        assert!(parse_sbom_repos("  ").is_empty());
        assert!(parse_sbom_repos(", ,").is_empty());
    }

    #[test]
    fn single_name_needs_no_comma() {
        assert_eq!(parse_sbom_repos("solo"), vec!["solo"]);
    }

    #[test]
    fn parses_the_documented_format_spellings() {
        use aws_sdk_inspector2::types::SbomReportFormat;

        assert_eq!(
            parse_sbom_format("cyclonedx14").expect("cyclonedx14 is valid"),
            SbomReportFormat::Cyclonedx14
        );
        assert_eq!(
            parse_sbom_format("spdx23").expect("spdx23 is valid"),
            SbomReportFormat::Spdx23
        );
    }

    #[test]
    fn format_parsing_is_case_and_whitespace_tolerant() {
        use aws_sdk_inspector2::types::SbomReportFormat;

        assert_eq!(
            parse_sbom_format("  CycloneDX14 ").expect("valid"),
            SbomReportFormat::Cyclonedx14
        );
        assert_eq!(
            parse_sbom_format("SPDX_2_3").expect("valid"),
            SbomReportFormat::Spdx23
        );
    }

    #[test]
    fn format_parsing_rejects_unknown_values_instead_of_producing_unknown_variant() {
        // The bug this replaces: `"nonsense".into()` yielded Unknown("nonsense")
        // and failed only later, as an opaque AWS ValidationException.
        let err = parse_sbom_format("nonsense").expect_err("must be rejected");
        let msg = format!("{err}");
        assert!(msg.contains("nonsense"), "error should name the bad value: {msg}");
        assert!(msg.contains("cyclonedx14"), "error should list valid values: {msg}");
    }

    #[test]
    fn the_cli_default_format_parses() {
        // --sbom-format's clap default_value is "cyclonedx14"; if that stops
        // parsing, every default SBOM run breaks.
        assert!(parse_sbom_format("cyclonedx14").is_ok());
    }
}
```

- [ ] **Step 4: Verify**

Run:
```bash
cargo fmt
cargo clippy -- -D warnings
cargo test cli_runners
cargo run -- --help 2>&1 | grep -A 1 "sbom"
```
Expected: clippy clean on touched files; all ten tests in the new module pass (six `parse_sbom_repos`, four `parse_sbom_format`); `--sbom-bucket`, `--sbom-kms-key`, `--sbom-format`, `--sbom-key-prefix`, `--sbom-repos`, `--sbom-all-repos` all listed.

Also confirm the format fix end-to-end — a bad value must fail fast with a clear message rather than reaching AWS:
```bash
cargo run -- --lookback 1 --collectors inspector-sbom \
    --sbom-bucket b --sbom-kms-key k --sbom-format nonsense 2>&1 | tail -3
```
Expected: an error naming `nonsense` and listing the valid spellings.

Then confirm the mutual-exclusion guard fires without touching AWS:
```bash
cargo run -- --lookback 1 --collectors inspector-sbom \
    --sbom-repos a --sbom-all-repos 2>&1 | tail -3
```
Expected: an error containing `--sbom-repos and --sbom-all-repos are mutually exclusive`.

- [ ] **Step 5: Commit**

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

- [ ] **Step 9: Add tests for the new state, navigation, and key handling**

Append to the existing `#[cfg(test)] mod tests` block in `src/tui/events.rs` (harness convention: `App::new(vec![])`, as at `src/tui/events.rs:806`):

```rust
    fn make_sbom_app() -> App {
        use crate::providers::aws::ecr_repos::EcrRepoSummary;
        let mut app = App::new(vec![]);
        app.sbom_repo_list = ["alpha", "beta", "gamma"]
            .iter()
            .map(|n| EcrRepoSummary {
                name: (*n).to_string(),
                uri: format!("1.dkr.ecr.us-east-1.amazonaws.com/{n}"),
            })
            .collect();
        app.screen = Screen::SbomRepoSelection;
        app
    }

    #[test]
    fn sbom_destination_requires_a_bucket_before_discovery() {
        let mut app = App::new(vec![]);
        app.screen = Screen::SbomDestination;
        app.sbom_bucket_input.clear();
        app.sbom_kms_input.clear();

        assert!(matches!(
            handle_sbom_destination(&mut app, KeyCode::Enter),
            Action::Continue
        ));
        assert_eq!(app.screen, Screen::SbomDestination, "must not advance");
        assert!(app.error_msg.is_some(), "an error banner must be shown");
    }

    #[test]
    fn sbom_destination_requires_a_kms_key_before_discovery() {
        let mut app = App::new(vec![]);
        app.screen = Screen::SbomDestination;
        app.sbom_bucket_input = crate::tui::state::TextInput::new("my-bucket");
        app.sbom_kms_input.clear();

        assert!(matches!(
            handle_sbom_destination(&mut app, KeyCode::Enter),
            Action::Continue
        ));
        assert_eq!(app.screen, Screen::SbomDestination);
        assert!(app.error_msg.is_some());
    }

    #[test]
    fn sbom_destination_advances_to_discovery_when_both_fields_are_set() {
        let mut app = App::new(vec![]);
        app.screen = Screen::SbomDestination;
        app.sbom_bucket_input = crate::tui::state::TextInput::new("my-bucket");
        app.sbom_kms_input = crate::tui::state::TextInput::new("arn:aws:kms:us-east-1:1:key/abc");

        assert!(matches!(
            handle_sbom_destination(&mut app, KeyCode::Enter),
            Action::SbomDiscoverRepos
        ));
        assert_eq!(app.screen, Screen::SbomRepoDiscovery);
        assert!(app.error_msg.is_none());
    }

    #[test]
    fn sbom_destination_typing_lands_in_the_focused_field() {
        let mut app = App::new(vec![]);
        app.screen = Screen::SbomDestination;
        app.sbom_bucket_input.clear();
        app.sbom_kms_input.clear();
        app.sbom_prefix_input.clear();

        app.sbom_dest_field = 0;
        handle_sbom_destination(&mut app, KeyCode::Char('b'));
        assert_eq!(app.sbom_bucket_input.value, "b");

        handle_sbom_destination(&mut app, KeyCode::Down);
        assert_eq!(app.sbom_dest_field, 1);
        handle_sbom_destination(&mut app, KeyCode::Char('k'));
        assert_eq!(app.sbom_kms_input.value, "k");
        assert_eq!(app.sbom_bucket_input.value, "b", "bucket must be untouched");
    }

    #[test]
    fn sbom_dest_field_clamps_at_both_ends() {
        let mut app = App::new(vec![]);
        app.screen = Screen::SbomDestination;
        app.sbom_dest_field = 0;
        handle_sbom_destination(&mut app, KeyCode::Up);
        assert_eq!(app.sbom_dest_field, 0);

        app.sbom_dest_field = 2;
        handle_sbom_destination(&mut app, KeyCode::Down);
        assert_eq!(app.sbom_dest_field, 2);
    }

    #[test]
    fn space_toggles_the_repository_under_the_cursor() {
        let mut app = make_sbom_app();
        handle_sbom_repo_selection(&mut app, KeyCode::Char(' '));
        assert!(app.sbom_repo_selected.contains(&0));

        handle_sbom_repo_selection(&mut app, KeyCode::Char(' '));
        assert!(app.sbom_repo_selected.is_empty(), "space must toggle off");
    }

    #[test]
    fn a_selects_all_visible_and_d_clears() {
        let mut app = make_sbom_app();
        handle_sbom_repo_selection(&mut app, KeyCode::Char('a'));
        assert_eq!(app.sbom_repo_selected.len(), 3);

        handle_sbom_repo_selection(&mut app, KeyCode::Char('d'));
        assert!(app.sbom_repo_selected.is_empty());
    }

    #[test]
    fn a_selects_only_the_filtered_subset() {
        let mut app = make_sbom_app();
        app.sbom_repo_search = crate::tui::state::TextInput::new("bet");
        handle_sbom_repo_selection(&mut app, KeyCode::Char('a'));

        assert_eq!(app.sbom_repo_selected.len(), 1);
        assert!(app.sbom_repo_selected.contains(&1), "only `beta` is visible");
    }

    #[test]
    fn cursor_clamps_within_the_visible_list() {
        let mut app = make_sbom_app();
        for _ in 0..10 {
            handle_sbom_repo_selection(&mut app, KeyCode::Down);
        }
        assert_eq!(app.sbom_repo_cursor, 2, "3 repos means max cursor 2");

        for _ in 0..10 {
            handle_sbom_repo_selection(&mut app, KeyCode::Up);
        }
        assert_eq!(app.sbom_repo_cursor, 0);
    }

    #[test]
    fn typing_filters_and_resets_the_cursor() {
        let mut app = make_sbom_app();
        handle_sbom_repo_selection(&mut app, KeyCode::Down);
        assert_eq!(app.sbom_repo_cursor, 1);

        handle_sbom_repo_selection(&mut app, KeyCode::Char('g'));
        assert_eq!(app.sbom_repo_search.value, "g");
        assert_eq!(app.sbom_repo_cursor, 0, "cursor resets on filter change");
        assert_eq!(app.visible_sbom_repos(), vec![2], "only `gamma` matches");
    }

    #[test]
    fn enter_with_nothing_selected_is_refused() {
        let mut app = make_sbom_app();
        handle_sbom_repo_selection(&mut app, KeyCode::Enter);

        assert_eq!(app.screen, Screen::SbomRepoSelection, "must not advance");
        assert!(app.error_msg.is_some());
        assert!(app.selected_sbom_repos.is_empty());
    }

    #[test]
    fn enter_commits_selected_names_sorted_and_advances() {
        let mut app = make_sbom_app();
        app.sbom_repo_selected.insert(2);
        app.sbom_repo_selected.insert(0);

        handle_sbom_repo_selection(&mut app, KeyCode::Enter);

        assert_eq!(app.screen, Screen::SetOptions);
        assert_eq!(app.selected_sbom_repos, vec!["alpha", "gamma"]);
    }
```

Then append to the existing `#[cfg(test)] mod tests` block in `src/tui/app/mod.rs`:

```rust
    #[test]
    fn sbom_is_not_selected_by_default() {
        let app = make_app();
        assert!(
            !app.sbom_selected(),
            "inspector-sbom must be opt-in, or every AWS run gains two wizard screens"
        );
    }

    #[test]
    fn sbom_selected_follows_the_collector_selection() {
        let mut app = make_app();
        let idx = app
            .collector_items
            .iter()
            .position(|(k, _, _)| *k == "inspector-sbom")
            .expect("inspector-sbom is in the AWS menu");

        app.collector_selected.insert(idx);
        assert!(app.sbom_selected());
    }

    #[test]
    fn visible_sbom_repos_filters_case_insensitively() {
        use crate::providers::aws::ecr_repos::EcrRepoSummary;
        let mut app = make_app();
        app.sbom_repo_list = ["Alpha", "beta"]
            .iter()
            .map(|n| EcrRepoSummary {
                name: (*n).to_string(),
                uri: String::new(),
            })
            .collect();

        assert_eq!(app.visible_sbom_repos(), vec![0, 1], "empty filter shows all");

        app.sbom_repo_search = crate::tui::state::TextInput::new("ALPHA");
        assert_eq!(app.visible_sbom_repos(), vec![0]);

        app.sbom_repo_search = crate::tui::state::TextInput::new("zzz");
        assert!(app.visible_sbom_repos().is_empty());
    }

    #[test]
    fn sbom_flow_navigation_round_trips() {
        let mut app = make_app();
        let idx = app
            .collector_items
            .iter()
            .position(|(k, _, _)| *k == "inspector-sbom")
            .expect("inspector-sbom is in the AWS menu");
        app.collector_selected.insert(idx);
        app.screen = Screen::SelectCollectors;

        app.next_screen();
        assert_eq!(app.screen, Screen::SbomDestination);

        app.screen = Screen::SbomRepoSelection;
        app.sbom_repo_selected.insert(0);
        app.sbom_repo_list = vec![crate::providers::aws::ecr_repos::EcrRepoSummary {
            name: "only".to_string(),
            uri: String::new(),
        }];
        app.next_screen();
        assert_eq!(app.screen, Screen::SetOptions);

        // Back out of SetOptions returns to the picker, not the collector list.
        app.prev_screen();
        assert_eq!(app.screen, Screen::SbomRepoSelection);
        app.prev_screen();
        assert_eq!(app.screen, Screen::SbomDestination);
        app.prev_screen();
        assert_eq!(app.screen, Screen::SelectCollectors);
    }

    #[test]
    fn without_sbom_selected_collectors_goes_straight_to_options() {
        let mut app = make_app();
        app.screen = Screen::SelectCollectors;
        app.next_screen();
        assert_eq!(app.screen, Screen::SetOptions);
    }

    #[test]
    fn reset_clears_sbom_selection_state() {
        let mut app = make_app();
        app.sbom_repo_selected.insert(0);
        app.selected_sbom_repos = vec!["x".to_string()];
        app.sbom_discovery_error = Some("boom".to_string());
        app.sbom_repo_cursor = 2;

        app.reset();

        assert!(app.sbom_repo_selected.is_empty());
        assert!(app.selected_sbom_repos.is_empty());
        assert!(app.sbom_discovery_error.is_none());
        assert_eq!(app.sbom_repo_cursor, 0);
    }
```

`Screen` and `KeyCode` are already in scope in both test modules via `use super::*;`. If `Screen` is not, add `use crate::tui::state::Screen;` to the test module. `Screen` derives `PartialEq`, so `assert_eq!` on it compiles; add `Debug` to its derive list if the assertion fails to compile for want of it (it already derives `Debug`).

- [ ] **Step 10: Verify the whole task**

Run:
```bash
cargo fmt
cargo clippy -- -D warnings
cargo test
```
Expected: clippy clean; all tests pass, including the 19 added here. (This is the first point in this task where a clean build is expected.)

`sbom_is_not_selected_by_default` is the regression guard for Step 1's `hardcoded_optins` change — if it fails, `"inspector-sbom"` was not added to that array.

Then confirm the wizard is navigable end-to-end. Launch the TUI, pick Collectors → AWS → an account → dates, search `sbom` in the collector picker, select **Inspector2 SBOM Export**, and press Enter:

```bash
cargo run
```
Expected: the "Inspector SBOM Export Destination" screen appears with the step indicator reading `SBOM Dest` (step 5 of 9 with accounts configured). Pressing Enter with an empty bucket shows the red banner "An S3 bucket is required for the SBOM export". Filling both required fields and pressing Enter shows "Discovering ECR repositories…" and then the picker (empty until Task 8 populates it — that is expected at this point). Esc from the picker returns to the destination screen; Esc again returns to the collector picker. Quit with Esc/`q`.

- [ ] **Step 11: Commit**

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
