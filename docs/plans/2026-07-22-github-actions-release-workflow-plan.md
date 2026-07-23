# GitHub Actions Release Workflow Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Publish versioned, prebuilt `grabber` binaries as GitHub Releases via a manually-triggered workflow, so other repos can fetch a ready-to-run binary through a one-step composite action instead of compiling from scratch.

**Architecture:** A `workflow_dispatch`-only workflow (`.github/workflows/release.yml`) builds `grabber` natively on three GitHub-hosted runners (Linux x86_64, macOS Intel, macOS Apple Silicon) with `cargo build --release --locked`, packages each binary as a `.tar.gz`, and publishes them all to one GitHub Release tagged with an operator-supplied version. A companion composite action (`.github/actions/setup-grabber/action.yml`) lets any consuming repo download the right tarball for its own runner and add `grabber` to `PATH` in one step, authenticated with nothing more than the consumer's own default `GITHUB_TOKEN` (this repo is public).

**Tech Stack:** GitHub Actions (`workflow_dispatch`, matrix builds, composite actions), `dtolnay/rust-toolchain`, `Swatinem/rust-cache`, `actions/upload-artifact`/`download-artifact` v4, GitHub CLI (`gh release create` / `gh release download`), Cargo.

## Global Constraints

- Version input must match `^v[0-9]+\.[0-9]+\.[0-9]+$` (e.g. `v1.1.0`) — validated before any build runs.
- Build targets, exactly these three, no others (no Windows in this pass):
  | Runner | Target triple |
  |---|---|
  | `ubuntu-latest` | `x86_64-unknown-linux-gnu` |
  | `macos-13` | `x86_64-apple-darwin` |
  | `macos-14` | `aarch64-apple-darwin` |
- Release builds use `cargo build --release --locked` with **default Cargo features only** — never pass `--features` or `--all-features` (no azure/gcp in the shipped binary).
- If a release/tag for the requested version already exists, the workflow must fail loudly, not overwrite it.
- This repo (`austinsonger/the-grabber`) is public — the composite action must authenticate only with the consumer's own `${{ github.token }}`, no PAT.
- No test-writing steps in this plan — this is CI/infra configuration, not application code; each task's own validation step (YAML syntax check, local `cargo` check) stands in for a test suite.
- Work happens directly on `main`, committed after each task.

---

### Task 1: Commit `Cargo.lock` for reproducible release builds

**Files:**
- Modify: `.gitignore:10` (remove the `Cargo.lock` entry)
- Create (git-add existing file): `Cargo.lock` (already present on disk, currently untracked)

**Interfaces:**
- Consumes: nothing from other tasks.
- Produces: a committed `Cargo.lock` that Task 2's `cargo build --release --locked` depends on being present and current.

- [ ] **Step 1: Remove `Cargo.lock` from `.gitignore`**

Open `.gitignore` and delete the line that reads exactly:
```
Cargo.lock
```
(it is currently line 10, on its own line).

- [ ] **Step 2: Verify the on-disk lock file is current**

Run:
```bash
cargo metadata --locked --format-version 1 > /dev/null
```
Expected: exits with status 0 and no `error: the lock file needs to be updated` message. If it fails, run `cargo generate-lockfile` once (no `--locked`) to refresh it, then re-run the command above to confirm it now passes.

- [ ] **Step 3: Stage and commit**

```bash
git add .gitignore Cargo.lock
git commit -m "build: commit Cargo.lock for reproducible release builds"
```

---

### Task 2: Add the release build-and-publish workflow

**Files:**
- Create: `.github/workflows/release.yml`

**Interfaces:**
- Consumes: `Cargo.lock` committed in Task 1.
- Produces: on `workflow_dispatch`, a GitHub Release tagged `${{ inputs.version }}` with three assets attached — `grabber-x86_64-unknown-linux-gnu.tar.gz`, `grabber-x86_64-apple-darwin.tar.gz`, `grabber-aarch64-apple-darwin.tar.gz` — each a gzipped tarball containing a top-level directory `grabber-<target-triple>/` holding the executable `grabber`. Task 3's composite action depends on this exact naming and layout.

- [ ] **Step 1: Write the workflow file**

Create `.github/workflows/release.yml`:

```yaml
name: Release

on:
  workflow_dispatch:
    inputs:
      version:
        description: "Release version (e.g. v1.1.0)"
        required: true
        type: string

permissions:
  contents: write

jobs:
  validate:
    name: Validate version input
    runs-on: ubuntu-latest
    steps:
      - name: Check version format
        run: |
          if [[ ! "${{ inputs.version }}" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            echo "::error::version '${{ inputs.version }}' must match vX.Y.Z (e.g. v1.1.0)"
            exit 1
          fi

  build:
    name: Build (${{ matrix.target }})
    needs: validate
    strategy:
      fail-fast: false
      matrix:
        include:
          - os: ubuntu-latest
            target: x86_64-unknown-linux-gnu
          - os: macos-13
            target: x86_64-apple-darwin
          - os: macos-14
            target: aarch64-apple-darwin
    runs-on: ${{ matrix.os }}
    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Install Rust toolchain
        uses: dtolnay/rust-toolchain@stable
        with:
          targets: ${{ matrix.target }}

      - name: Cache cargo/target
        uses: Swatinem/rust-cache@v2
        with:
          key: ${{ matrix.target }}

      - name: Build release binary
        run: cargo build --release --locked --target ${{ matrix.target }}

      - name: Package binary
        run: |
          set -euo pipefail
          staging="grabber-${{ matrix.target }}"
          mkdir -p "$staging"
          cp "target/${{ matrix.target }}/release/grabber" "$staging/"
          tar -czf "${staging}.tar.gz" "$staging"

      - name: Upload artifact
        uses: actions/upload-artifact@v4
        with:
          name: grabber-${{ matrix.target }}
          path: grabber-${{ matrix.target }}.tar.gz
          if-no-files-found: error

  publish:
    name: Publish release
    needs: build
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Fail if version already exists
        env:
          GH_TOKEN: ${{ github.token }}
        run: |
          if gh release view "${{ inputs.version }}" --repo "${{ github.repository }}" >/dev/null 2>&1; then
            echo "::error::release ${{ inputs.version }} already exists"
            exit 1
          fi

      - name: Download build artifacts
        uses: actions/download-artifact@v4
        with:
          path: dist
          pattern: grabber-*
          merge-multiple: true

      - name: Create release
        env:
          GH_TOKEN: ${{ github.token }}
        run: |
          gh release create "${{ inputs.version }}" \
            --repo "${{ github.repository }}" \
            --target "${{ github.sha }}" \
            --title "${{ inputs.version }}" \
            --generate-notes \
            dist/*.tar.gz
```

- [ ] **Step 2: Validate YAML syntax**

Run:
```bash
python3 -c "import yaml; yaml.safe_load(open('.github/workflows/release.yml'))" && echo OK
```
Expected: prints `OK` with no exception. If `python3`/`pyyaml` isn't available, use `ruby -ryaml -e "YAML.load_file('.github/workflows/release.yml'); puts 'OK'"` instead — either confirms the file parses as valid YAML.

- [ ] **Step 3: Commit**

```bash
git add .github/workflows/release.yml
git commit -m "ci: add manual release workflow to build and publish grabber binaries"
```

---

### Task 3: Add the `setup-grabber` composite action for consuming repos

**Files:**
- Create: `.github/actions/setup-grabber/action.yml`

**Interfaces:**
- Consumes: the release asset naming/layout produced by Task 2 (`grabber-<target-triple>.tar.gz` containing `grabber-<target-triple>/grabber`).
- Produces: a reusable step, `uses: austinsonger/the-grabber/.github/actions/setup-grabber@main`, with input `version` (default `latest`) and output `binary-path`; on success, `grabber` is on `PATH` for later steps in the calling job.

- [ ] **Step 1: Write the composite action**

Create `.github/actions/setup-grabber/action.yml`:

```yaml
name: "Setup grabber"
description: "Download a prebuilt grabber release binary and add it to PATH"

inputs:
  version:
    description: "Release version to install (e.g. v1.1.0), or 'latest'"
    required: false
    default: "latest"

outputs:
  binary-path:
    description: "Absolute path to the installed grabber binary"
    value: ${{ steps.install.outputs.binary-path }}

runs:
  using: "composite"
  steps:
    - name: Resolve target triple
      id: target
      shell: bash
      run: |
        set -euo pipefail
        os="${{ runner.os }}"
        arch="${{ runner.arch }}"
        case "$os-$arch" in
          Linux-X64)   triple="x86_64-unknown-linux-gnu" ;;
          macOS-X64)   triple="x86_64-apple-darwin" ;;
          macOS-ARM64) triple="aarch64-apple-darwin" ;;
          *)
            echo "::error::setup-grabber has no published binary for $os/$arch"
            exit 1
            ;;
        esac
        echo "triple=$triple" >> "$GITHUB_OUTPUT"

    - name: Download and install grabber
      id: install
      shell: bash
      env:
        GH_TOKEN: ${{ github.token }}
      run: |
        set -euo pipefail
        triple="${{ steps.target.outputs.triple }}"
        version="${{ inputs.version }}"
        dest="$RUNNER_TEMP/grabber-install"
        mkdir -p "$dest"

        if [ "$version" = "latest" ]; then
          gh release download \
            --repo austinsonger/the-grabber \
            --pattern "grabber-${triple}.tar.gz" \
            --dir "$dest" \
            --clobber
        else
          gh release download "$version" \
            --repo austinsonger/the-grabber \
            --pattern "grabber-${triple}.tar.gz" \
            --dir "$dest" \
            --clobber
        fi

        tar -xzf "$dest/grabber-${triple}.tar.gz" -C "$dest"
        chmod +x "$dest/grabber-${triple}/grabber"

        echo "$dest/grabber-${triple}" >> "$GITHUB_PATH"
        echo "binary-path=$dest/grabber-${triple}/grabber" >> "$GITHUB_OUTPUT"
```

Note the `if`/`else` on `version`: `gh release download latest` would look for a release literally *tagged* `latest`, which never exists here — omitting the tag argument entirely is how `gh` fetches the most recent release, so the two branches are not interchangeable.

- [ ] **Step 2: Validate YAML syntax**

Run:
```bash
python3 -c "import yaml; yaml.safe_load(open('.github/actions/setup-grabber/action.yml'))" && echo OK
```
Expected: prints `OK`.

- [ ] **Step 3: Commit**

```bash
git add .github/actions/setup-grabber/action.yml
git commit -m "ci: add setup-grabber composite action for consuming repos"
```

---

### Task 4: Document releases and consumer usage in the README

**Files:**
- Modify: `README.md:903-905`

**Interfaces:**
- Consumes: the workflow name/trigger from Task 2 and the composite action path/inputs from Task 3 (documented, not executed).
- Produces: nothing consumed by other tasks — this is the terminal documentation task.

- [ ] **Step 1: Insert a new "Releases & Prebuilt Binaries" section**

In `README.md`, find this exact text (the end of the `## Azure / GCP` section, right before `## Troubleshooting`):

```markdown
Both providers are compiled behind opt-in Cargo features (`--features azure`, `--features gcp`). They are stubs today — factory scaffolding exists in `src/providers/{azure,gcp}/` but no collectors ship yet. Enabling the feature will surface an empty provider in the TUI account picker; use `config.example.toml` as a reference for adding an `[[account]]` block when collectors land.

---

## Troubleshooting
```

Replace it with:

```markdown
Both providers are compiled behind opt-in Cargo features (`--features azure`, `--features gcp`). They are stubs today — factory scaffolding exists in `src/providers/{azure,gcp}/` but no collectors ship yet. Enabling the feature will surface an empty provider in the TUI account picker; use `config.example.toml` as a reference for adding an `[[account]]` block when collectors land.

---

## Releases & Prebuilt Binaries

Prebuilt `grabber` binaries for Linux (x86_64) and macOS (Intel + Apple Silicon) are published as GitHub Releases — no need to `cargo build` from source in every downstream CI pipeline.

**Cutting a release (maintainers):** go to the **Actions** tab → **Release** workflow → **Run workflow**, enter a version (e.g. `v1.1.0`), and run it. This builds all three platform binaries and publishes them as release `v1.1.0` with a `.tar.gz` per platform attached. Releases are built with the default Cargo feature set (`tenable`, `okta`, `jira`, `elastic`) — no `azure`/`gcp`.

**Using the binary from another repo's GitHub Action:**

```yaml
- uses: austinsonger/the-grabber/.github/actions/setup-grabber@main
  with:
    version: v1.1.0   # or omit to use "latest"
- run: grabber --help
```

This downloads the binary matching the runner's OS/architecture, adds it to `PATH`, and requires no extra authentication — the repo is public and the action uses the calling workflow's own `GITHUB_TOKEN`.

---

## Troubleshooting
```

- [ ] **Step 2: Verify the edit landed correctly**

Run:
```bash
grep -n "## Releases & Prebuilt Binaries" README.md
```
Expected: one match, positioned before the `## Troubleshooting` line.

- [ ] **Step 3: Commit**

```bash
git add README.md
git commit -m "docs: document release process and setup-grabber consumer usage"
```

---

## Post-Plan Manual Verification (not automatable in this session)

Once all four tasks are committed and pushed to `main`:

1. Go to the **Actions** tab → **Release** → **Run workflow**, enter `v1.1.0` (or the next appropriate version), and run it.
2. Confirm all three `build` matrix jobs succeed and the `publish` job creates a release with three `.tar.gz` assets attached.
3. From any other repo, add the `setup-grabber` step from the README snippet and confirm `grabber --help` runs without a `cargo build` step.

This cannot be verified from the local session — it requires a real `workflow_dispatch` run on GitHub, which only you can trigger.
