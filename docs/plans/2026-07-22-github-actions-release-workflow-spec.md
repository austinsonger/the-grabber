# Spec: GitHub Actions Release Build & Cross-Repo Distribution

**Status:** Draft
**Author:** Austin Songer
**Date:** 2026-07-22
**Type:** Feature spec (PRD) — implementation plan to follow

---

## Problem Statement

Any other repo that wants to use the `grabber` binary in its own GitHub Action currently has to check out this repo and run `cargo build --release` from scratch on every workflow run, costing several minutes of compile time per run for a binary that changes infrequently. There is no published, versioned artifact of `grabber` and no CI in this repo at all (`.github/workflows/` does not exist yet).

## Goals

1. **Publish versioned, prebuilt `grabber` binaries as GitHub Releases**, built for the platforms GitHub-hosted runners actually use (Linux x86_64, macOS Intel, macOS Apple Silicon), so a consuming workflow can download a binary instead of compiling one.
2. **Make the trigger explicit and deliberate.** Releases are cut by hand (`workflow_dispatch`) with an operator-supplied version — no build fires automatically on every push.
3. **Make releases reproducible.** Commit `Cargo.lock` and build with `--locked` so a given version tag always resolves the same dependency graph.
4. **Make consumption a one-line step.** Publish a reusable composite action in this repo (`.github/actions/setup-grabber`) that another repo's workflow can `uses:` to download the right binary for its runner and put it on `PATH`, with no manual OS/arch branching in the consumer's own YAML.
5. **No new auth burden.** This repo is public; the composite action must work with just the consumer's default `GITHUB_TOKEN` — no PAT, no secret setup in the consuming repo.

## Non-Goals

1. **No automatic releases on tag push or merge to main.** *Rationale: explicit operator choice per the design conversation — avoids surprise releases and lets version numbers be deliberate.*
2. **No Windows binaries.** GitHub-hosted runners for the target consumer use case are Linux/macOS; Windows support can be added later if needed. *Rationale: YAGNI — no current consumer needs it.*
3. **No `--all-features` build (no `azure`/`gcp`).** The published binary matches the same default feature set `cargo build --release` produces locally today (`tenable`, `okta`, `jira`, `elastic`). *Rationale: matches current local/documented build; azure/gcp support can be a separate release variant later if requested.*
4. **No checksum/signing manifest for release assets.** *Rationale: out of scope for this pass; the existing `--sign` HMAC feature in the binary itself is unrelated and unaffected.*
5. **No changes to the existing evidence-collection CI/test suite** — there isn't one; this spec only adds the release workflow and the consumer-side composite action.

## Requirements

### P0 — Release workflow

- **P0.1** — New workflow `.github/workflows/release.yml`, trigger `workflow_dispatch` only, with a required string input `version` (e.g. `v1.1.0`).
- **P0.2** — Validate `version` matches `^v[0-9]+\.[0-9]+\.[0-9]+$` before doing any build work; fail fast with a clear error otherwise.
- **P0.3** — Build matrix, one job per target:
  | Runner | Target triple |
  |---|---|
  | `ubuntu-latest` | `x86_64-unknown-linux-gnu` |
  | `macos-13` | `x86_64-apple-darwin` |
  | `macos-14` | `aarch64-apple-darwin` |
- **P0.4** — Each build job: checkout at the ref the workflow was dispatched against, install the Rust toolchain with the job's target added, cache with `Swatinem/rust-cache`, run `cargo build --release --locked` with default features (no `--features`/`--all-features` flag), package the resulting `target/release/grabber` binary into `grabber-<target-triple>.tar.gz`, upload it as a build artifact named after the target triple.
- **P0.5** — A `publish` job, depending on all build jobs, downloads all three artifacts, creates the git tag `${{ inputs.version }}` at the dispatched commit, and creates a GitHub Release at that tag with all three tarballs attached and `--generate-notes` for auto-generated release notes.
- **P0.6** — If a release or tag for `version` already exists, the `publish` job must fail with a clear error rather than silently overwriting it.

### P0 — Cargo.lock reproducibility

- **P0.7** — Remove the `Cargo.lock` entry from `.gitignore` and commit the current `Cargo.lock` to the repo.
- **P0.8** — Release builds use `cargo build --release --locked` (already covered by P0.4); local development workflows (`cargo check`, `cargo build`, `cargo test`) are unaffected and continue to work as before.

### P0 — Consumer-side composite action

- **P0.9** — New composite action at `.github/actions/setup-grabber/action.yml` with one input, `version` (default `latest`).
- **P0.10** — The action maps `runner.os` (`Linux`/`macOS`) + `runner.arch` (`X64`/`ARM64`) to the matching target triple from the P0.3 table, and fails with a clear, actionable error for any unsupported combination (e.g. `Windows`).
- **P0.11** — The action downloads the matching `grabber-<target-triple>.tar.gz` asset from the `austinsonger/the-grabber` release identified by `version` using the GitHub CLI (`gh release download`), authenticated with the invoking workflow's own `${{ github.token }}` (works because this repo is public — no PAT required).
- **P0.12** — The action extracts the tarball, `chmod +x`s the `grabber` binary, and adds its containing directory to `$GITHUB_PATH` so subsequent steps in the consuming workflow can call `grabber` directly.

### P1 — Documentation

- **P1.1** — README section explaining how to cut a release: Actions tab → "Release" workflow → "Run workflow" → enter a `vX.Y.Z` version.
- **P1.2** — README snippet showing the one-step consumer usage:
  ```yaml
  - uses: austinsonger/the-grabber/.github/actions/setup-grabber@main
    with:
      version: v1.1.0
  - run: grabber --help
  ```

## Design Notes

- **Why `workflow_dispatch` only, not tag-triggered:** confirmed in design discussion — the operator wants every release to be a deliberate act, not a side effect of pushing a tag or merging to main.
- **Why GitHub Releases over Actions artifacts:** Actions artifacts expire (default 90 days), are awkward to fetch cross-repo, and require extra API plumbing for a consumer in a different repo. Release assets are permanent, versioned, and directly downloadable with `gh release download` or a plain URL.
- **Why a composite action instead of just documenting the download command:** keeps the OS/arch-detection and download logic in one place (this repo) rather than copy-pasted into every consuming repo's workflow; if the packaging format or target list changes later, only the composite action needs updating.
- **Why commit `Cargo.lock` now:** this is the first time the repo ships a binary artifact to other repos/consumers rather than just being built locally by whoever checks it out — reproducibility starts to matter once other pipelines depend on a specific version behaving consistently.

## Out of Scope / Follow-ups (not part of this implementation)

- Windows target support.
- `--all-features` (azure/gcp) release variant.
- Checksum file (`checksums.txt`) or signing of release assets.
- Tag-push or main-push triggered releases.
