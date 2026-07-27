# The Grabber — Desktop GUI Application Specification

> **Status:** Draft  
> **Date:** 2026-07-27  
> **Author:** Agent (Kimi Code CLI)  
> **Target:** Cross-platform desktop GUI for The Grabber, reusing the existing Rust collector core.

---

## 1. Overview

The Grabber today ships as a Rust CLI/TUI application. It collects security-compliance evidence from AWS, Okta, Jira, Tenable, Jamf, GitHub, and Elastic, and produces CSV, JSON, XLSX, and OSCAL artifacts. The TUI (`ratatui`) already implements a wizard for account selection, date ranges, collectors, and options.

This spec defines a **native desktop GUI** that:

- Provides the same end-to-end workflows as the TUI but with a mouse-driven, accessible, rich UI.
- Reuses the existing async Rust collector engine, providers, and output logic.
- Adds a **secure credential vault** so users can enter, store, and manage cloud-provider credentials inside the app.
- Adds quality-of-life features: persistent recent runs, in-app log tail, file previews, drag-and-drop export, and one-click signing/verification.
- Builds into signed, installable packages for macOS, Windows, and Linux.

---

## 2. Goals & Non-Goals

### Goals

- **Feature parity** with the existing TUI wizard: Collectors, Inventory, POA&M, and STIG remediation.
- **Backend reuse** — the GUI must call into the existing Rust logic (`src/providers`, `src/runner`, `src/inventory_orchestrator`, `src/poam`, etc.) rather than reimplementing collectors.
- **Secure credential management** — enter, encrypt, and retrieve credentials for AWS, Okta, Jira, Tenable, Jamf, GitHub, and Elastic without leaving the app.
- **Cross-platform** packages: `.app`/`.dmg` (macOS), `.msi`/`.exe` (Windows), `.AppImage`/`.deb` (Linux).
- **Offline-first** — all collection happens locally; the GUI is a client to the local core.
- **Security-hardened** — secrets encrypted at rest, no secrets in frontend state, no network exposure, and signing verification shipped in-app.

### Non-Goals

- Replacing the CLI/TUI. The GUI is an additional distribution target.
- Cloud/SaaS hosting or multi-user server features.
- Rewriting collectors in JavaScript/TypeScript.
- Mobile apps (out of scope for this spec).

---

## 3. Target Framework

### Recommended: Tauri v2

Use **[Tauri](https://tauri.app/)** with a Rust backend and a web frontend.

**Why Tauri fits this project:**

- The heavy lifting (AWS SDK, async collection, CSV/JSON/XLSX writing, signing) stays in Rust and is exposed to the GUI via Tauri commands.
- The frontend can be built with familiar web technologies (recommended: **React + TypeScript** or **Svelte + TypeScript**), enabling rich components: tables, calendars, trees, search, wizards.
- Native OS webview keeps binary size small compared to Electron and aligns with the project’s security focus.
- Tauri’s `Channel`/`Event` APIs let the backend stream collector progress to the UI in real time.
- Strong packaging story out of the box.

### Alternative: egui

If the team wants a **pure-Rust** stack and is willing to build more custom widgets, [egui](https://www.egui.rs/) is a viable alternative. Trade-offs: fewer ready-made complex components (data grids, date pickers), more Rust UI code, smaller binary, no JS attack surface.

### Decision

**Proceed with Tauri v2 + React/TypeScript.** Document egui as the fallback if frontend staffing or security review requires a pure-Rust UI.

---

## 4. High-Level Architecture

```text
┌─────────────────────────────────────────────────────────────┐
│                     Desktop GUI (Tauri)                     │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────┐  │
│  │  React/TS    │  │  IPC Layer   │  │  Native Dialogs  │  │
│  │  Wizard UI   │◄─┤  Commands &  │◄─┤  File picker,    │  │
│  │  Preview     │  │  Events      │  │  Notifications   │  │
│  └──────────────┘  └──────────────┘  └──────────────────┘  │
└──────────────────────────┬──────────────────────────────────┘
                           │ Tauri commands + events
┌──────────────────────────▼──────────────────────────────────┐
│                    grabber-core (Rust lib)                  │
│  Reuses existing modules:                                   │
│  • src/app_config.rs      • src/providers/                  │
│  • src/runner/            • src/inventory_orchestrator/     │
│  • src/poam/              • src/audit_log.rs                │
│  • src/signing.rs         • src/zip_bundle.rs               │
│  • src/credentials/       (NEW secure credential vault)     │
└─────────────────────────────────────────────────────────────┘
```

### Crate Layout

```text
the-grabber/
├── Cargo.toml                 # workspace root
├── src/                       # existing CLI/TUI source
│   └── credentials/           # NEW — credential vault module
├── crates/
│   ├── tenable-rs/            # existing
│   ├── okta-rs/               # existing
│   ├── ...
│   └── grabber-core/          # NEW — library wrapper around src/* logic
└── grabber-desktop/           # NEW — Tauri app
    ├── src-tauri/
    │   ├── Cargo.toml
    │   ├── tauri.conf.json
    │   └── src/
    │       ├── main.rs
    │       ├── lib.rs
    │       ├── commands/      # Tauri command handlers
    │       ├── state.rs       # Shared engine / runtime state
    │       └── error.rs
    └── src/
        ├── App.tsx
        ├── screens/           # wizard screens
        ├── components/        # reusable UI
        └── api/               # typed IPC client
```

> **Note:** If extracting `grabber-core` into a separate crate is too invasive for the first milestone, the Tauri crate can depend on the main `the-grabber` crate with `lib = true` enabled in `Cargo.toml` (add a `[lib]` section exposing a stable API).

---

## 5. Credential Vault

Users enter and store cloud-provider credentials inside the desktop app. The vault is **mandatory for GUI use** and is the source of truth for how the engine authenticates to each provider.

### 5.1 Storage Strategy

- **Secrets** (passwords, API tokens, AWS secret keys) are stored in the **OS credential store**:
  - macOS: Keychain (`keyring` crate or Tauri stronghold)
  - Windows: Windows Credential Locker
  - Linux: Secret Service API / libsecret (GNOME Keyring, KWallet fallback)
- **Metadata** (name, provider, kind, created/updated timestamps, non-secret identifiers) is stored in an app-local encrypted database or JSON file.
- **Encryption at rest:** use AES-256-GCM for the metadata store. The encryption key is itself protected by the OS keyring so the vault is unlocked automatically when the user is logged in.
- **Optional master password:** for additional hardening, the user may opt to require a master password on app launch. The password derives the key via Argon2id.

### 5.2 Supported Credential Types

| Provider | Credential Kinds | Stored Secrets |
|----------|------------------|----------------|
| **AWS** | SSO profile, Access key pair, Existing profile reference | SSO start URL / account / role; or access key ID + secret key + optional session token |
| **Okta** | API token, OAuth client | Domain + SSWS token, or client ID + client secret |
| **Jira** | API token, Basic auth, OAuth | Host + user email + token, or username + password |
| **Tenable** | API keys, Token | Access key + secret key, or URL + token |
| **Jamf** | API token, Basic auth | Host + token, or username + password |
| **GitHub** | PAT (classic/fine-grained), GitHub Enterprise token | Base URL + token |
| **Elastic** | API key, Basic auth, Certificate | Hosts + key or username/password + CA/trust settings |

### 5.3 Credential Model

```rust
pub struct CredentialEntry {
    pub id: Uuid,
    pub name: String,
    pub provider: CloudProvider,
    pub kind: CredentialKind,
    pub metadata: CredentialMetadata,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

pub enum CredentialKind {
    AwsSso { start_url: String, account_id: String, role_name: String, region: String, session_name: String },
    AwsAccessKey { access_key_id: String },                 // secret key stored in OS keyring
    AwsProfileReference { profile_name: String },            // uses ~/.aws/config, no secret stored
    ApiToken { domain: String },                             // token stored in OS keyring
    BasicAuth { host: String, username: String },            // password stored in OS keyring
    OAuth { domain: String, client_id: String },             // client secret stored in OS keyring
}
```

### 5.4 AWS Integration Modes

1. **SSO profile (recommended):** the app writes the SSO profile block to `~/.aws/config` when the credential is saved, so `aws sso login` continues to work outside the app. The SSO token itself is managed by the AWS CLI/SDK session cache.
2. **Access key pair:** the app can either:
   - Inject credentials directly into the SDK config at runtime (no file write), or
   - Write the `[profile]` to `~/.aws/credentials` on demand, encrypted in transit to disk.
   Default: **in-memory injection only** to keep keys out of plain text files.
3. **Existing profile reference:** for users who prefer to keep managing `~/.aws/config` manually.

### 5.5 Account-to-Credential Mapping

`config.toml` is extended so each `[[account]]` references a credential by ID:

```toml
[[account]]
name          = "Production"
account_id    = "123456789012"
credential_id = "cred-uuid-here"   # NEW
region        = "us-east-1"
output_dir    = "./evidence-output/production"
```

Backward compatibility: if `credential_id` is absent, fall back to the existing `profile` field.

---

## 6. Backend API Surface (Tauri Commands)

The Rust side exposes a typed, narrow API. All long-running work returns progress via Tauri events, not blocking command returns.

### 6.1 Credential Vault Commands

```rust
#[tauri::command]
async fn list_credentials() -> Result<Vec<CredentialMetaDto>, GuiError>;

#[tauri::command]
async fn get_credential(id: Uuid) -> Result<CredentialDto, GuiError>;

#[tauri::command]
async fn create_credential(dto: CredentialDto) -> Result<CredentialMetaDto, GuiError>;

#[tauri::command]
async fn update_credential(id: Uuid, dto: CredentialDto) -> Result<CredentialMetaDto, GuiError>;

#[tauri::command]
async fn delete_credential(id: Uuid) -> Result<(), GuiError>;

#[tauri::command]
async fn test_credential(id: Uuid) -> Result<CredentialTestResult, GuiError>;

#[tauri::command]
async fn import_aws_profiles() -> Result<Vec<CredentialMetaDto>, GuiError>;

#[tauri::command]
async fn export_aws_config() -> Result<(), GuiError>;

#[tauri::command]
async fn lock_vault() -> Result<(), GuiError>;

#[tauri::command]
async fn unlock_vault(password: Option<String>) -> Result<(), GuiError>;
```

### 6.2 Configuration

```rust
#[tauri::command]
async fn load_config() -> Result<AppConfigDto, GuiError>;

#[tauri::command]
async fn save_config(config: AppConfigDto) -> Result<(), GuiError>;

#[tauri::command]
async fn list_aws_profiles() -> Result<Vec<String>, GuiError>;

#[tauri::command]
async fn test_account(account_name: String) -> Result<IdentityInfo, GuiError>;
```

### 6.3 Discovery

```rust
#[tauri::command]
async fn list_providers() -> Vec<ProviderMeta>;

#[tauri::command]
async fn list_collectors(provider: CloudProvider) -> Vec<CollectorMeta>;

#[tauri::command]
async fn list_inventory_types() -> Vec<InventoryTypeMeta>;

#[tauri::command]
async fn discover_regions(credential_id: Uuid) -> Result<Vec<String>, GuiError>;
```

### 6.4 Collection Runs

```rust
#[tauri::command]
async fn start_collection(
    request: CollectionRequest,
    app: AppHandle,
) -> Result<RunId, GuiError>;

#[tauri::command]
async fn cancel_collection(run_id: RunId) -> Result<(), GuiError>;
```

Progress is emitted as Tauri events:

```rust
app.emit("collection:progress", ProgressEvent {
    run_id,
    account: "Production",
    collector: "iam-users",
    status: "running", // queued | running | success | empty | error | timeout
    records: 42,
    message: Option<String>,
});
```

### 6.5 Inventory & POA&M

```rust
#[tauri::command]
async fn start_inventory(request: InventoryRequest, app: AppHandle) -> Result<RunId, GuiError>;

#[tauri::command]
async fn start_poam(request: PoamRequest, app: AppHandle) -> Result<RunId, GuiError>;

#[tauri::command]
async fn start_stig_remediation(request: StigRequest, app: AppHandle) -> Result<RunId, GuiError>;
```

### 6.6 Results & Packaging

```rust
#[tauri::command]
async fn list_run_artifacts(run_id: RunId) -> Result<Vec<ArtifactMeta>, GuiError>;

#[tauri::command]
async fn preview_artifact(path: PathBuf, limit: usize) -> Result<ArtifactPreview, GuiError>;

#[tauri::command]
async fn open_in_folder(path: PathBuf) -> Result<(), GuiError>;

#[tauri::command]
async fn sign_output(run_id: RunId) -> Result<SigningManifest, GuiError>;

#[tauri::command]
async fn verify_manifest(manifest_path: PathBuf, key_hex: String) -> Result<VerifyResult, GuiError>;
```

### 6.7 Misc

```rust
#[tauri::command]
async fn tail_log(lines: usize) -> Result<String, GuiError>;

#[tauri::command]
async fn export_zip(run_id: RunId, destination: PathBuf) -> Result<PathBuf, GuiError>;
```

---

## 7. Frontend Screen-by-Screen Design

Map the existing TUI screens (`src/tui/state.rs`, `src/tui/ui/*.rs`) to GUI wizard panes.

### 7.1 Welcome / Dashboard

- Logo/branding from `src/tui/ui/theme.rs` (`LOGO`).
- "New Collection", "New Inventory", "New POA&M", "Verify Signature" big buttons.
- Recent runs list (read from GUI state file): date, type, account, status, quick actions.
- One-click "Open output folder" and "Manage credentials".

### 7.2 Credential Vault

- Table of stored credentials: name, provider, kind, last tested, status.
- "Add credential" opens a provider-specific form:
  - AWS: SSO vs access key vs existing profile.
  - Token providers: domain + token + optional advanced options.
  - Basic-auth providers: host + username + password.
- "Test" button per credential (calls provider health/identity endpoint).
- "Import from AWS config" parses `~/.aws/config` and `~/.aws/credentials` into vault entries.
- Unlock prompt if master password is enabled.

### 7.3 Feature Selection

- Cards: **Collect Evidence**, **Asset Inventory**, **POA&M Reconciliation**, **STIG Remediation**.
- Mirrors `Feature` enum in `src/tui/state.rs`.

### 7.4 Account & Provider Selection

- Load `config.toml` accounts into a table: name, provider, account ID, credential, region.
- Multi-select with checkboxes.
- Each account row links to its credential; missing credentials show a warning.
- "Test credentials" button per account.
- "Add account" opens a modal that edits `config.toml` and selects/ creates a credential.

### 7.5 Region / Profile

- Region selector with "Discover regions" button (uses `src/aws_loader.rs` and the selected credential).
- Credential dropdown per account.
- Global-services hint (IAM, Route53, CloudFront) shown when multi-region is selected.

### 7.6 Date Range

- Calendar pickers for start/end.
- Quick chips: 7d, 30d, 90d, 1y.
- Validation: start ≤ end, both ≤ today.

### 7.7 Collector Selection

- Search box + category tree (reuse categories in `src/tui/menus/aws.rs` and other provider menus).
- Per-collector metadata: description, output format, estimated cost/time hint if available.
- Bulk actions: select all, select none, reset to defaults.
- Filter by provider.

### 7.8 Options

- Output directory picker.
- Checkboxes: `--zip`, `--sign`, `--write_run_manifest`, `--write_chain_of_custody`, `--include_raw`.
- Signing key input (optional 64-char hex).
- Audit artifact preview toggle.

### 7.9 Confirm

- Summary card: accounts, regions, date range, collector count, options.
- "Start" / "Back".

### 7.10 Running

- Live progress table: account → collector → status → records → elapsed.
- Log tail pane (streams `evidence-collection.log`).
- Cancel button.
- Estimated completion heuristics (optional future enhancement).

### 7.11 Results

- Artifact list with icons for CSV/JSON/XLSX/ZIP.
- Preview pane for CSV/JSON (first N rows).
- Buttons: Open folder, Export ZIP, Sign now, Verify, Run again.
- Run manifest summary (success/empty/error/timeout counts).

---

## 8. Data Model / DTOs

The frontend uses DTOs that are a stable subset of the internal Rust types. Keep them versioned loosely (e.g. `AppConfigDto v1`).

```typescript
interface CredentialMetaDto {
  id: string;
  name: string;
  provider: 'aws' | 'okta' | 'jira' | 'tenable' | 'jamf' | 'github' | 'elastic';
  kind: string;
  last_tested_at?: string;
  status: 'unknown' | 'ok' | 'error';
}

interface CredentialDto {
  id?: string;
  name: string;
  provider: string;
  kind: string;
  // provider-kind-specific fields; optional secrets are write-only
  domain?: string;
  host?: string;
  access_key_id?: string;
  secret_access_key?: string;
  session_token?: string;
  start_url?: string;
  account_id?: string;
  role_name?: string;
  region?: string;
  session_name?: string;
  token?: string;
  username?: string;
  password?: string;
  client_id?: string;
  client_secret?: string;
  profile_name?: string;
}

interface AccountDto {
  name: string;
  provider: 'aws' | 'okta' | 'jira' | 'tenable' | 'jamf' | 'github' | 'elastic';
  account_id?: string;
  credential_id?: string;
  profile?: string;            // legacy fallback
  region: string;
  output_dir?: string;
  collectors?: CollectorRulesDto;
}

interface CollectionRequest {
  accounts: string[];           // account names
  feature: 'collectors';
  start_date?: string;          // YYYY-MM-DD
  end_date?: string;
  lookback?: string;            // e.g. "90d"
  collectors?: string[];        // keys; null = defaults
  regions?: string[];           // null = single default
  all_regions: boolean;
  options: RunOptionsDto;
}

interface RunOptionsDto {
  output_dir: string;
  zip: boolean;
  sign: boolean;
  signing_key?: string;
  write_run_manifest: boolean;
  write_chain_of_custody: boolean;
  include_raw: boolean;
}

interface ProgressEvent {
  run_id: string;
  account: string;
  region?: string;
  collector: string;
  status: 'queued' | 'running' | 'success' | 'empty' | 'error' | 'timeout';
  records: number;
  message?: string;
}

interface ArtifactMeta {
  path: string;
  filename: string;
  kind: 'csv' | 'json' | 'xlsx' | 'zip' | 'manifest' | 'log';
  size_bytes: number;
}
```

Rust equivalents live in `grabber-desktop/src-tauri/src/dto.rs` and map to/from existing `AppConfig`, `CredentialEntry`, and `audit_log` types.

---

## 9. Reusing Existing Rust Code

### 9.1 Core engine abstraction

Introduce a thin `Engine` struct that wraps today’s runner functions:

```rust
pub struct Engine {
    pub config: AppConfig,
    pub credential_vault: CredentialVault,
    pub runtime: Arc<tokio::runtime::Runtime>,
}

impl Engine {
    pub async fn collect(&self, req: CollectionRequest, progress: ProgressSink) -> Result<RunSummary>;
    pub async fn inventory(&self, req: InventoryRequest, progress: ProgressSink) -> Result<RunSummary>;
    pub async fn poam(&self, req: PoamRequest, progress: ProgressSink) -> Result<RunSummary>;
    pub async fn stig(&self, req: StigRequest, progress: ProgressSink) -> Result<RunSummary>;
}
```

`ProgressSink` is a trait that forwards to the Tauri `AppHandle` event emitter.

### 9.2 Adapter pattern for CLI flags

The existing CLI is driven by `src/cli.rs`. Build a `From<CollectionRequest> for Cli` adapter so the GUI can reuse `run_standard_cli` and `run_inventory_cli` without duplicating orchestration logic.

### 9.3 Cancellation

Use `tokio_util::sync::CancellationToken`. Pass the token into the engine; long-running collectors should check `token.is_cancelled()` between pages/requests. The current timeout logic stays unchanged.

### 9.4 State persistence

- **Config:** reuse `src/app_config.rs` (`load_config` / `save_config`).
- **Credentials:** managed by the new `src/credentials/` module.
- **GUI state:** add `~/.config/the-grabber/gui-state.json` for recent runs, window geometry, and last-used options.
- **Logs:** continue writing `evidence-collection.log`; the GUI tails it with `tail_log`.

---

## 10. Security & Hardening

| Concern | Mitigation |
|---------|------------|
| Cloud credentials | Entered through the GUI and stored in the OS keyring / encrypted vault. Never held in frontend state. |
| Credential metadata | Encrypted at rest (AES-256-GCM). |
| Master password | Optional Argon2id-derived key to unlock the vault on launch. |
| AWS access keys | Prefer SSO; access keys injected into SDK config in memory by default, with optional sync to `~/.aws/credentials`. |
| IPC surface | Whitelist commands; validate all paths (no traversal); reject absolute paths outside output/config dirs. |
| Frontend code integrity | Build frontend in production mode; disable devtools in release builds; enable CSP in `tauri.conf.json`. |
| Secrets in logs | Sanitize command DTOs before writing to `CHAIN-OF-CUSTODY` (already done for CLI args). |
| File picker safety | Use Tauri’s secure dialog API; validate selected directory is writable before run. |
| Memory safety | Zeroize ephemeral secret strings where possible (`zeroize` crate). |
| Code signing | macOS/Windows packages signed with project certificates; evidence signing uses HMAC-SHA256 unchanged. |

---

## 11. Build, Test & Distribution

### New commands

```bash
# Fast check of the whole workspace including desktop crate
cargo check --workspace

# Run the desktop app in dev mode
cd grabber-desktop && npm install && npm run tauri dev

# Build release packages for the current platform
cd grabber-desktop && npm run tauri build

# Lint everything
cargo clippy --workspace -- -D warnings

# Format
cargo fmt
```

### CI/CD

Extend `.github/workflows/` (existing workflows in `.github/workflows/`) with `desktop-release.yml`:

1. Build Tauri on `macos-latest`, `windows-latest`, `ubuntu-latest`.
2. Run `cargo test --workspace`.
3. Run frontend unit tests.
4. Build signed artifacts:
   - macOS: `TheGrabber.app`, `TheGrabber_<version>_x64.dmg`, `TheGrabber_<version>_aarch64.dmg`
   - Windows: `TheGrabber_<version>_x64_en-US.msi`
   - Linux: `the-grabber_<version>_amd64.deb`, `TheGrabber_<version>_amd64.AppImage`
5. Attach to GitHub Releases.

### Notarization (macOS)

Add `APPLE_SIGNING_IDENTITY`, `APPLE_ID`, `APPLE_TEAM_ID`, and `APPLE_PASSWORD` repository secrets. Tauri handles notarization via `tauri.conf.json` signing config.

---

## 12. Implementation Roadmap

### Milestone 0 — Foundation (1–2 weeks)

- [ ] Add `[lib]` to `the-grabber/Cargo.toml` exposing a minimal stable API, OR create `crates/grabber-core`.
- [ ] Define DTOs and `Engine` wrapper.
- [ ] Scaffold `grabber-desktop` Tauri v2 + React/TypeScript project.
- [ ] Implement `load_config`, `save_config`, `list_aws_profiles` commands.

### Milestone 1 — Credential Vault (1–2 weeks)

- [ ] Implement `src/credentials/` module with OS keyring storage + encrypted metadata store.
- [ ] Add DTOs and Tauri commands for CRUD, test, import from AWS config.
- [ ] Build credential vault screen with provider-specific forms.
- [ ] Wire AWS SDK config builder to read from vault (SSO, access key, profile reference).
- [ ] Optional master password unlock flow.

### Milestone 2 — Configuration & Account Management (1 week)

- [ ] Welcome screen with recent runs.
- [ ] Account selection table linking to vault credentials.
- [ ] Add/edit account modal writing to `config.toml`.
- [ ] Region/profile selection screen using stored credentials.

### Milestone 3 — Collector Wizard (1–2 weeks)

- [ ] Feature selection screen.
- [ ] Date range picker.
- [ ] Collector selection tree with search and categories.
- [ ] Options screen (output dir, zip, sign, audit artifacts).
- [ ] Confirm screen.

### Milestone 4 — Run & Progress (1–2 weeks)

- [ ] `start_collection` command + progress event stream.
- [ ] Running screen with live table and log tail.
- [ ] Cancel support.
- [ ] Results screen with artifact list.

### Milestone 5 — Inventory, POA&M, STIG (2 weeks)

- [ ] Inventory request flow + asset-type selector.
- [ ] POA&M request flow with year/month picker.
- [ ] STIG remediation checklist screen.
- [ ] Preview artifacts (CSV/JSON).

### Milestone 6 — Packaging & Polish (1 week)

- [ ] Theming aligned with `src/tui/ui/theme.rs` (dark palette, cyan accents).
- [ ] Signed release builds for all three platforms.
- [ ] Update `README.md` and `docs/cli-reference.md` with GUI install instructions.
- [ ] Add desktop-specific tests for DTO round-trips and IPC handlers.

---

## 13. Open Questions / Decisions for the Team

1. **Frontend stack:** React + TypeScript (recommended) or Svelte/Vue?
2. **Core crate split:** Add `[lib]` to the main crate, or create a separate `crates/grabber-core`?
3. **Vault lock mode:** OS keyring auto-unlock only, or require an optional master password on launch?
4. **AWS access-key behavior:** In-memory SDK injection only, or allow writing to `~/.aws/credentials`?
5. **Update channel:** Should the GUI auto-check for updates on startup (Tauri updater plugin)?
6. **Telemetry:** Any anonymous crash reporting? Default to **no** for security tooling.
7. **Window chrome:** Native OS frame or custom title bar? Recommend native for accessibility.
8. **Minimum OS versions:** macOS 11+, Windows 10 1809+, Ubuntu 20.04+?
9. **Open-source license:** Confirm license before publishing packages.

---

## 14. References

- `src/main.rs` — runtime entry point
- `src/cli.rs` — CLI flag definitions
- `src/app_config.rs` — TOML config model
- `src/tui/state.rs`, `src/tui/app/mod.rs`, `src/tui/ui/*.rs` — existing wizard screens
- `src/tui/ui/theme.rs` — color palette and logo
- `src/providers/mod.rs` — provider factory trait
- `src/evidence.rs` — collector traits
- `src/runner/*.rs` — dispatch, multi-account, multi-region, output paths
- `src/audit_log.rs`, `src/signing.rs`, `src/zip_bundle.rs` — audit, signing, packaging
- `README.md`, `docs/cli-reference.md`, `docs/implementation-plan.md`
