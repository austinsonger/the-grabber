# Non-AWS Provider CLI Flags Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give Okta, Tenable, Elastic, and GitHub a complete headless CLI surface — a mode flag, credential overrides, a comma-separated key list, and one opt-in boolean flag per collector — so all 50 non-AWS collectors are runnable from a terminal without the TUI.

**Architecture:** Four `clap::Args` structs (one per provider) live in a new `src/cli_providers.rs` and are `#[command(flatten)]`-ed into the existing `Cli`. A new `src/runner/provider_cli/` directory module owns the headless run path: `mod.rs` holds shared account/window/output/artifact plumbing, and one file per provider builds the client and drives that provider's `ProviderFactory` through the *existing* `collect_ops` runners. `main.rs` gains one dispatch branch. No TUI code, no collector code, and no factory code changes.

**Tech Stack:** Rust 2021, `clap` v4 derive, `anyhow`, `tokio`, the existing `okta-rs` / `tenable-rs` / `elastic-rs` / `github-rs` path-dependency crates.

## Global Constraints

- **No unit tests.** Per standing project preference, this plan ships production code only. Every task's verification step is `cargo clippy -- -D warnings` plus a `cargo run -- --help` / real-invocation smoke check. Do not add `#[cfg(test)]` modules.
- **Work on `main`.** Do not create a feature branch.
- `cargo clippy -- -D warnings` must be clean and `cargo fmt` must have been run before every commit.
- Errors use `anyhow::Result` / `anyhow::Context`; use `anyhow::bail!` for early exits. **No `unwrap()` / `expect()` in production code** except where a value was just proven `Some` on the preceding line (match the `.expect("checked above to be Some")` idiom already in `tui_session.rs`).
- Imports grouped std → external crates → `crate::*`, blank line between groups.
- Every provider block that touches a provider crate must be behind `#[cfg(feature = "<provider>")]`, with a `#[cfg(not(feature = "..."))]` counterpart that `bail!`s. The flag structs themselves are **never** feature-gated — `--okta` must always parse so the error message can be a clean bail rather than "unexpected argument".
- Child modules must be written **before** the parent `mod.rs` that declares them (a `PostToolUse` hook runs `cargo check` after every write; declaring a module that does not exist yet breaks the tree).
- Collector keys are the canonical source of truth and live in `src/tui/menus/<provider>.rs`. The key lists in this plan were copied from those files verbatim — do not invent keys.
- Author commits as "Austin Songer" `<asonger.pixel@gmail.com>`. No co-author trailers, no "Generated with" lines.

---

## Current State (what the plan is fixing)

- `OktaProviderFactory`, `TenableProviderFactory`, `ElasticProviderFactory`, and `GithubProviderFactory` are constructed in exactly one place: `src/runner/tui_session.rs` (lines ~726, ~846, ~1196, ~1300). Nothing else in the binary ever builds them.
- `run_standard_cli` (`src/runner/cli_runners.rs:245`) only ever builds `AwsProviderFactory`, so `--collectors okta-users` today silently collects nothing.
- `docs/cli-reference.md:445` states this outright: *"Non-AWS providers (Okta, Jira, Tenable, Elastic, GitHub) are TUI-only today."* That line becomes false in Task 7.
- **Okta STIG:** a read-only STIG scan is already a normal collector (`okta-stig-compliance` → `OktaStigComplianceCollector`, which calls `stig::evaluate_all`). It therefore needs **no special flag** — `--okta-stig-compliance` covers it. STIG *remediation* (`stig::remediate::apply`, which mutates the live tenant) is deliberately **out of scope** and stays TUI-only behind its interactive confirm screen.
- Jira is deliberately **out of scope** for this plan.

## File Structure

**Create:**
- `src/cli_providers.rs` — the four `clap::Args` structs, the four canonical collector-key tables, and each struct's `resolve_collectors()`. Pure data + validation; no I/O, no provider crates.
- `src/runner/provider_cli/mod.rs` — dispatch, mutual-exclusion guards, and shared helpers: `accounts_for`, `resolve_window`, `provider_output_dir`, `finish_provider_run`.
- `src/runner/provider_cli/okta.rs` — Okta credential resolution + run loop.
- `src/runner/provider_cli/tenable.rs` — Tenable credential resolution + run loop (also owns `--tenable-scan-ids` / `--tenable-was-scan-ids`).
- `src/runner/provider_cli/elastic.rs` — Elastic credential resolution + run loop.
- `src/runner/provider_cli/github.rs` — GitHub credential resolution + run loop.

**Modify:**
- `src/cli.rs` — add four `#[command(flatten)]` fields to `Cli` (~6 lines).
- `src/main.rs` — add `mod cli_providers;` and one dispatch branch (~5 lines).
- `src/runner/mod.rs` — add `pub mod provider_cli;` (1 line).
- `docs/cli-reference.md` — new "Provider Modes" section; correct the TUI-only claim at line 445.
- `README.md` — provider CLI flag tables.

**Not touched:** every `src/providers/**` collector and factory, all of `src/tui/`, `src/runner/collect_ops.rs`, `src/runner/multi_account.rs`.

---

### Task 1: Provider flag structs

**Files:**
- Create: `src/cli_providers.rs`
- Modify: `src/cli.rs:347` (append flatten fields to the `Cli` struct, just before its closing brace)
- Modify: `src/main.rs:1-20` (module declaration list)

**Interfaces:**
- Produces: `pub struct OktaFlags`, `TenableFlags`, `ElasticFlags`, `GithubFlags`, each with `pub fn resolve_collectors(&self) -> anyhow::Result<Vec<String>>`. Produces `pub const OKTA_COLLECTOR_KEYS: &[&str]` (25 entries), `TENABLE_COLLECTOR_KEYS` (5), `ELASTIC_COLLECTOR_KEYS` (10), `GITHUB_COLLECTOR_KEYS` (10). Produces `Cli` fields `pub okta: OktaFlags`, `pub tenable: TenableFlags`, `pub elastic: ElasticFlags`, `pub github: GithubFlags`.
- Consumes: nothing.

**Why field names carry the provider prefix:** clap derives each argument's internal ID from the *field name*. Four flattened structs each containing a field named `enabled` or `account` would panic at runtime with a duplicate-ID error. Naming fields `okta_enabled` / `tenable_account` / … makes IDs unique **and** lets bare `#[arg(long)]` auto-derive the kebab-case long name (`okta_users` → `--okta-users`), so no explicit `long = "..."` string is needed except where the flag name differs from the field name.

- [ ] **Step 1: Write `src/cli_providers.rs` — header and Okta**

```rust
//! Headless-CLI flag groups for the non-AWS providers.
//!
//! Each provider gets a `clap::Args` struct that is `#[command(flatten)]`-ed
//! into [`crate::cli::Cli`]: a mode flag (`--okta`), credential overrides, a
//! comma-separated `--<provider>-collectors` key list, and one opt-in boolean
//! per collector. The individual flags and the key list are additive; an empty
//! selection means "every collector for this provider".
//!
//! Field names are provider-prefixed on purpose. clap derives an argument's
//! internal ID from the field name, so four flattened structs each with a field
//! named `enabled` would collide at runtime. The prefix also lets bare
//! `#[arg(long)]` auto-derive the kebab-case long name (`okta_users` →
//! `--okta-users`).
//!
//! The key tables below are the CLI's canonical copy of the selector keys in
//! `src/tui/menus/<provider>.rs`. Adding a collector means adding it in three
//! places: the provider's `factory.rs`, that provider's TUI menu, and here.

use std::collections::HashSet;

use anyhow::Result;
use clap::Args;

/// Every Okta collector key, in TUI menu order (`src/tui/menus/okta.rs`).
pub const OKTA_COLLECTOR_KEYS: &[&str] = &[
    "okta-users",
    "okta-groups",
    "okta-group-members",
    "okta-apps",
    "okta-shared-groups",
    "okta-publisher-groups",
    "okta-policies",
    "okta-signin-widget",
    "okta-session-policy",
    "okta-password-policy",
    "okta-factors",
    "okta-shared-account-broker",
    "okta-stig-compliance",
    "okta-deprovisioning",
    "okta-auto-provisioning",
    "okta-hris-config",
    "okta-offboarding-sla",
    "okta-contractor-deprov",
    "okta-transfer-diff",
    "okta-access-reviews",
    "okta-prod-recert",
    "okta-group-changes",
    "okta-risk-suspend",
    "okta-threat-insight",
    "okta-system-log",
];

/// Merge an explicit `--<provider>-collectors` list with the individual boolean
/// flags, dedup while preserving first-seen order, reject unknown keys, and
/// fall back to the full set when nothing was selected.
fn resolve_keys(
    provider: &str,
    explicit: Option<&Vec<String>>,
    toggles: &[(bool, &str)],
    all: &[&str],
) -> Result<Vec<String>> {
    let mut selected: Vec<String> = Vec::new();

    if let Some(keys) = explicit {
        for key in keys {
            let key = key.trim().to_ascii_lowercase();
            if key.is_empty() {
                continue;
            }
            if !all.contains(&key.as_str()) {
                anyhow::bail!(
                    "--{provider}-collectors: unknown key '{key}'. Valid keys: {}",
                    all.join(", ")
                );
            }
            selected.push(key);
        }
    }

    for (on, key) in toggles {
        if *on {
            selected.push((*key).to_string());
        }
    }

    let mut seen = HashSet::new();
    selected.retain(|k| seen.insert(k.clone()));

    if selected.is_empty() {
        Ok(all.iter().map(|s| (*s).to_string()).collect())
    } else {
        Ok(selected)
    }
}

/// Okta headless-CLI flags.
#[derive(Args, Debug)]
#[command(next_help_heading = "Okta")]
pub struct OktaFlags {
    /// Run the Okta evidence workflow non-interactively.
    /// Reads accounts from okta-config.toml / config.toml, or falls back to
    /// --okta-domain / --okta-api-token (or OKTA_DOMAIN / OKTA_API_TOKEN).
    #[arg(long = "okta", default_value_t = false)]
    pub okta_enabled: bool,

    /// Limit the run to the [[account]] with this `name` (case-insensitive).
    #[arg(long)]
    pub okta_account: Option<String>,

    /// Okta tenant base URL, e.g. https://acme.okta.com.
    /// Highest precedence: overrides config.toml and OKTA_DOMAIN.
    #[arg(long)]
    pub okta_domain: Option<String>,

    /// Okta API token (SSWS). Overrides config.toml and OKTA_API_TOKEN.
    #[arg(long)]
    pub okta_api_token: Option<String>,

    /// Collector keys to run (comma-separated). Additive with the individual
    /// --okta-* collector flags. Omit both to run all 25 Okta collectors.
    #[arg(long, value_delimiter = ',')]
    pub okta_collectors: Option<Vec<String>>,

    /// Okta: collect Users.
    #[arg(long, default_value_t = false)]
    pub okta_users: bool,

    /// Okta: collect Groups.
    #[arg(long, default_value_t = false)]
    pub okta_groups: bool,

    /// Okta: collect Group Members.
    #[arg(long, default_value_t = false)]
    pub okta_group_members: bool,

    /// Okta: collect Applications.
    #[arg(long, default_value_t = false)]
    pub okta_apps: bool,

    /// Okta: collect Shared Group Inventory.
    #[arg(long, default_value_t = false)]
    pub okta_shared_groups: bool,

    /// Okta: collect Publisher Groups.
    #[arg(long, default_value_t = false)]
    pub okta_publisher_groups: bool,

    /// Okta: collect Policies.
    #[arg(long, default_value_t = false)]
    pub okta_policies: bool,

    /// Okta: collect Sign-In Widget Config.
    #[arg(long, default_value_t = false)]
    pub okta_signin_widget: bool,

    /// Okta: collect Session Policy.
    #[arg(long, default_value_t = false)]
    pub okta_session_policy: bool,

    /// Okta: collect Password Policy.
    #[arg(long, default_value_t = false)]
    pub okta_password_policy: bool,

    /// Okta: collect MFA Factors.
    #[arg(long, default_value_t = false)]
    pub okta_factors: bool,

    /// Okta: collect Shared-Account Broker config.
    #[arg(long, default_value_t = false)]
    pub okta_shared_account_broker: bool,

    /// Okta: run the read-only DISA STIG compliance evaluation.
    #[arg(long, default_value_t = false)]
    pub okta_stig_compliance: bool,

    /// Okta: collect Deprovisioning Timeliness.
    #[arg(long, default_value_t = false)]
    pub okta_deprovisioning: bool,

    /// Okta: collect Automated Provisioning events.
    #[arg(long, default_value_t = false)]
    pub okta_auto_provisioning: bool,

    /// Okta: collect HRIS Integration Config.
    #[arg(long, default_value_t = false)]
    pub okta_hris_config: bool,

    /// Okta: collect Offboarding SLA.
    #[arg(long, default_value_t = false)]
    pub okta_offboarding_sla: bool,

    /// Okta: collect Contractor Deprovisioning.
    #[arg(long, default_value_t = false)]
    pub okta_contractor_deprov: bool,

    /// Okta: collect Transfer Access Diff.
    #[arg(long, default_value_t = false)]
    pub okta_transfer_diff: bool,

    /// Okta: collect Access Certification campaigns.
    #[arg(long, default_value_t = false)]
    pub okta_access_reviews: bool,

    /// Okta: collect Prod Access Recertification.
    #[arg(long, default_value_t = false)]
    pub okta_prod_recert: bool,

    /// Okta: collect Group Membership Changes.
    #[arg(long, default_value_t = false)]
    pub okta_group_changes: bool,

    /// Okta: collect Risk-Account Suspend timing.
    #[arg(long, default_value_t = false)]
    pub okta_risk_suspend: bool,

    /// Okta: collect ThreatInsight Detections.
    #[arg(long, default_value_t = false)]
    pub okta_threat_insight: bool,

    /// Okta: collect System Log events.
    #[arg(long, default_value_t = false)]
    pub okta_system_log: bool,
}

impl OktaFlags {
    /// Collector keys for this run. Empty selection = every Okta collector.
    pub fn resolve_collectors(&self) -> Result<Vec<String>> {
        let toggles = [
            (self.okta_users, "okta-users"),
            (self.okta_groups, "okta-groups"),
            (self.okta_group_members, "okta-group-members"),
            (self.okta_apps, "okta-apps"),
            (self.okta_shared_groups, "okta-shared-groups"),
            (self.okta_publisher_groups, "okta-publisher-groups"),
            (self.okta_policies, "okta-policies"),
            (self.okta_signin_widget, "okta-signin-widget"),
            (self.okta_session_policy, "okta-session-policy"),
            (self.okta_password_policy, "okta-password-policy"),
            (self.okta_factors, "okta-factors"),
            (self.okta_shared_account_broker, "okta-shared-account-broker"),
            (self.okta_stig_compliance, "okta-stig-compliance"),
            (self.okta_deprovisioning, "okta-deprovisioning"),
            (self.okta_auto_provisioning, "okta-auto-provisioning"),
            (self.okta_hris_config, "okta-hris-config"),
            (self.okta_offboarding_sla, "okta-offboarding-sla"),
            (self.okta_contractor_deprov, "okta-contractor-deprov"),
            (self.okta_transfer_diff, "okta-transfer-diff"),
            (self.okta_access_reviews, "okta-access-reviews"),
            (self.okta_prod_recert, "okta-prod-recert"),
            (self.okta_group_changes, "okta-group-changes"),
            (self.okta_risk_suspend, "okta-risk-suspend"),
            (self.okta_threat_insight, "okta-threat-insight"),
            (self.okta_system_log, "okta-system-log"),
        ];
        resolve_keys(
            "okta",
            self.okta_collectors.as_ref(),
            &toggles,
            OKTA_COLLECTOR_KEYS,
        )
    }
}
```

- [ ] **Step 2: Append Tenable, Elastic, and GitHub to `src/cli_providers.rs`**

Append to the same file, after the Okta block:

```rust
/// Every Tenable collector key, in TUI menu order (`src/tui/menus/tenable.rs`).
pub const TENABLE_COLLECTOR_KEYS: &[&str] = &[
    "tenable-vulns",
    "tenable-was",
    "tenable-pci-asv",
    "tenable-assets",
    "tenable-compliance",
];

/// Tenable headless-CLI flags.
#[derive(Args, Debug)]
#[command(next_help_heading = "Tenable")]
pub struct TenableFlags {
    /// Run the Tenable evidence workflow non-interactively.
    #[arg(long = "tenable", default_value_t = false)]
    pub tenable_enabled: bool,

    /// Limit the run to the [[account]] with this `name` (case-insensitive).
    #[arg(long)]
    pub tenable_account: Option<String>,

    /// Tenable base URL. Omit for Tenable.io (https://cloud.tenable.com);
    /// set for Tenable.sc or the FedRAMP cloud. Overrides config.toml.
    #[arg(long)]
    pub tenable_url: Option<String>,

    /// Tenable API access key. Overrides config.toml and TENABLE_ACCESS_KEY.
    #[arg(long)]
    pub tenable_access_key: Option<String>,

    /// Tenable API secret key. Overrides config.toml and TENABLE_SECRET_KEY.
    #[arg(long)]
    pub tenable_secret_key: Option<String>,

    /// Numeric scan IDs to scope the run to (comma-separated).
    /// Mirrors the TUI scan-selection screen. Omit to cover all scans.
    #[arg(long, value_delimiter = ',')]
    pub tenable_scan_ids: Option<Vec<i64>>,

    /// Web App Scanning config IDs to scope --tenable-was to (comma-separated).
    /// Omit to include every WAS scan.
    #[arg(long, value_delimiter = ',')]
    pub tenable_was_scan_ids: Option<Vec<String>>,

    /// Collector keys to run (comma-separated). Additive with the individual
    /// flags. Omit both to run all 5 Tenable collectors.
    #[arg(long, value_delimiter = ',')]
    pub tenable_collectors: Option<Vec<String>>,

    /// Tenable: collect Vulnerability Findings.
    #[arg(long, default_value_t = false)]
    pub tenable_vulns: bool,

    /// Tenable: collect Web App Scanning findings.
    #[arg(long, default_value_t = false)]
    pub tenable_was: bool,

    /// Tenable: collect PCI ASV Compliance.
    #[arg(long, default_value_t = false)]
    pub tenable_pci_asv: bool,

    /// Tenable: collect Asset Inventory.
    #[arg(long, default_value_t = false)]
    pub tenable_assets: bool,

    /// Tenable: collect Compliance Findings.
    #[arg(long, default_value_t = false)]
    pub tenable_compliance: bool,
}

impl TenableFlags {
    /// Collector keys for this run. Empty selection = every Tenable collector.
    pub fn resolve_collectors(&self) -> Result<Vec<String>> {
        let toggles = [
            (self.tenable_vulns, "tenable-vulns"),
            (self.tenable_was, "tenable-was"),
            (self.tenable_pci_asv, "tenable-pci-asv"),
            (self.tenable_assets, "tenable-assets"),
            (self.tenable_compliance, "tenable-compliance"),
        ];
        resolve_keys(
            "tenable",
            self.tenable_collectors.as_ref(),
            &toggles,
            TENABLE_COLLECTOR_KEYS,
        )
    }
}

/// Every Elastic collector key, in TUI menu order (`src/tui/menus/elastic.rs`).
pub const ELASTIC_COLLECTOR_KEYS: &[&str] = &[
    "elastic-rules",
    "elastic-exceptions",
    "elastic-alerts",
    "elastic-cases",
    "elastic-connectors",
    "elastic-users",
    "elastic-roles",
    "elastic-agents",
    "elastic-fim",
    "elastic-ilm",
];

/// Elastic Security headless-CLI flags.
#[derive(Args, Debug)]
#[command(next_help_heading = "Elastic Security")]
pub struct ElasticFlags {
    /// Run the Elastic Security evidence workflow non-interactively.
    #[arg(long = "elastic", default_value_t = false)]
    pub elastic_enabled: bool,

    /// Limit the run to the [[account]] with this `name` (case-insensitive).
    #[arg(long)]
    pub elastic_account: Option<String>,

    /// Kibana base URL. Overrides config.toml and ELASTIC_KIBANA_URL.
    #[arg(long)]
    pub elastic_kibana_url: Option<String>,

    /// Elasticsearch base URL. Overrides config.toml and ELASTIC_ES_URL.
    #[arg(long)]
    pub elastic_es_url: Option<String>,

    /// Elastic API key (the base64 "Encoded" value). Overrides config.toml
    /// and ELASTIC_API_KEY.
    #[arg(long)]
    pub elastic_api_key: Option<String>,

    /// Collector keys to run (comma-separated). Additive with the individual
    /// flags. Omit both to run all 10 Elastic collectors.
    #[arg(long, value_delimiter = ',')]
    pub elastic_collectors: Option<Vec<String>>,

    /// Elastic: collect Detection Rules Inventory.
    #[arg(long, default_value_t = false)]
    pub elastic_rules: bool,

    /// Elastic: collect Exception List Items.
    #[arg(long, default_value_t = false)]
    pub elastic_exceptions: bool,

    /// Elastic: collect Security Alerts.
    #[arg(long, default_value_t = false)]
    pub elastic_alerts: bool,

    /// Elastic: collect Cases.
    #[arg(long, default_value_t = false)]
    pub elastic_cases: bool,

    /// Elastic: collect Alerting Connectors.
    #[arg(long, default_value_t = false)]
    pub elastic_connectors: bool,

    /// Elastic: collect Security Users.
    #[arg(long, default_value_t = false)]
    pub elastic_users: bool,

    /// Elastic: collect Security Roles.
    #[arg(long, default_value_t = false)]
    pub elastic_roles: bool,

    /// Elastic: collect Fleet Agents Inventory.
    #[arg(long, default_value_t = false)]
    pub elastic_agents: bool,

    /// Elastic: collect File Integrity Monitoring config.
    #[arg(long, default_value_t = false)]
    pub elastic_fim: bool,

    /// Elastic: collect ILM Retention Policies.
    #[arg(long, default_value_t = false)]
    pub elastic_ilm: bool,
}

impl ElasticFlags {
    /// Collector keys for this run. Empty selection = every Elastic collector.
    pub fn resolve_collectors(&self) -> Result<Vec<String>> {
        let toggles = [
            (self.elastic_rules, "elastic-rules"),
            (self.elastic_exceptions, "elastic-exceptions"),
            (self.elastic_alerts, "elastic-alerts"),
            (self.elastic_cases, "elastic-cases"),
            (self.elastic_connectors, "elastic-connectors"),
            (self.elastic_users, "elastic-users"),
            (self.elastic_roles, "elastic-roles"),
            (self.elastic_agents, "elastic-agents"),
            (self.elastic_fim, "elastic-fim"),
            (self.elastic_ilm, "elastic-ilm"),
        ];
        resolve_keys(
            "elastic",
            self.elastic_collectors.as_ref(),
            &toggles,
            ELASTIC_COLLECTOR_KEYS,
        )
    }
}

/// Every GitHub collector key, in TUI menu order (`src/tui/menus/github.rs`).
pub const GITHUB_COLLECTOR_KEYS: &[&str] = &[
    "github-members",
    "github-teams",
    "github-team-members",
    "github-security-settings",
    "github-repos",
    "github-branch-protection",
    "github-audit-log",
    "github-dependabot-alerts",
    "github-secret-scanning-alerts",
    "github-code-scanning-alerts",
];

/// GitHub headless-CLI flags.
#[derive(Args, Debug)]
#[command(next_help_heading = "GitHub")]
pub struct GithubFlags {
    /// Run the GitHub evidence workflow non-interactively.
    #[arg(long = "github", default_value_t = false)]
    pub github_enabled: bool,

    /// Limit the run to the [[account]] with this `name` (case-insensitive).
    #[arg(long)]
    pub github_account: Option<String>,

    /// GitHub organization login. Overrides config.toml and GITHUB_ORG.
    #[arg(long)]
    pub github_org: Option<String>,

    /// GitHub token (PAT or app token). Overrides config.toml and GITHUB_TOKEN.
    #[arg(long)]
    pub github_token: Option<String>,

    /// GitHub API base URL. Defaults to https://api.github.com; set for
    /// GitHub Enterprise Server. Overrides config.toml and GITHUB_BASE_URL.
    #[arg(long)]
    pub github_base_url: Option<String>,

    /// Collector keys to run (comma-separated). Additive with the individual
    /// flags. Omit both to run all 10 GitHub collectors.
    #[arg(long, value_delimiter = ',')]
    pub github_collectors: Option<Vec<String>>,

    /// GitHub: collect Org Members.
    #[arg(long, default_value_t = false)]
    pub github_members: bool,

    /// GitHub: collect Org Teams.
    #[arg(long, default_value_t = false)]
    pub github_teams: bool,

    /// GitHub: collect Team Membership.
    #[arg(long, default_value_t = false)]
    pub github_team_members: bool,

    /// GitHub: collect Org Security Settings.
    #[arg(long, default_value_t = false)]
    pub github_security_settings: bool,

    /// GitHub: collect Repositories.
    #[arg(long, default_value_t = false)]
    pub github_repos: bool,

    /// GitHub: collect Branch Protection rules.
    #[arg(long, default_value_t = false)]
    pub github_branch_protection: bool,

    /// GitHub: collect the Org Audit Log.
    #[arg(long, default_value_t = false)]
    pub github_audit_log: bool,

    /// GitHub: collect Dependabot Alerts.
    #[arg(long, default_value_t = false)]
    pub github_dependabot_alerts: bool,

    /// GitHub: collect Secret Scanning Alerts.
    #[arg(long, default_value_t = false)]
    pub github_secret_scanning_alerts: bool,

    /// GitHub: collect Code Scanning Alerts.
    #[arg(long, default_value_t = false)]
    pub github_code_scanning_alerts: bool,
}

impl GithubFlags {
    /// Collector keys for this run. Empty selection = every GitHub collector.
    pub fn resolve_collectors(&self) -> Result<Vec<String>> {
        let toggles = [
            (self.github_members, "github-members"),
            (self.github_teams, "github-teams"),
            (self.github_team_members, "github-team-members"),
            (self.github_security_settings, "github-security-settings"),
            (self.github_repos, "github-repos"),
            (self.github_branch_protection, "github-branch-protection"),
            (self.github_audit_log, "github-audit-log"),
            (self.github_dependabot_alerts, "github-dependabot-alerts"),
            (
                self.github_secret_scanning_alerts,
                "github-secret-scanning-alerts",
            ),
            (
                self.github_code_scanning_alerts,
                "github-code-scanning-alerts",
            ),
        ];
        resolve_keys(
            "github",
            self.github_collectors.as_ref(),
            &toggles,
            GITHUB_COLLECTOR_KEYS,
        )
    }
}
```

- [ ] **Step 3: Declare the module in `src/main.rs`**

Add `mod cli_providers;` to the module list, keeping it alphabetical. The list currently starts:

```rust
mod app_config;
mod audit_log;
mod aws_loader;
mod cli;
mod evidence;
```

becomes:

```rust
mod app_config;
mod audit_log;
mod aws_loader;
mod cli;
mod cli_providers;
mod evidence;
```

- [ ] **Step 4: Flatten the four structs into `Cli`**

In `src/cli.rs`, add the import to the existing `crate::*` import group:

```rust
use crate::cli_providers::{ElasticFlags, GithubFlags, OktaFlags, TenableFlags};
use crate::inventory_core::INVENTORY_ITEMS;
```

Then append these fields to the `Cli` struct, immediately after `pub sbom_format: String,` and before the struct's closing brace (`src/cli.rs:346`):

```rust
    // ------- Non-AWS provider modes -------
    #[command(flatten)]
    pub okta: OktaFlags,

    #[command(flatten)]
    pub tenable: TenableFlags,

    #[command(flatten)]
    pub elastic: ElasticFlags,

    #[command(flatten)]
    pub github: GithubFlags,
```

- [ ] **Step 5: Verify the flags parse and appear in help**

```bash
cargo fmt
cargo clippy -- -D warnings
cargo run -- --help
```

Expected: clean clippy; `--help` shows four new headed sections ("Okta", "Tenable", "Elastic Security", "GitHub"). Confirm `--okta-users`, `--okta-stig-compliance`, `--tenable-scan-ids`, `--elastic-alerts`, and `--github-audit-log` are all listed.

A duplicate-argument-ID bug shows up as a **runtime panic** on any invocation, not a compile error — so also run:

```bash
cargo run -- --okta --okta-users --github-members 2>&1 | head -5
```

Expected: no panic. It will fail later (nothing dispatches `--okta` yet, so it falls through to the TUI); the point of this check is only that clap built the command successfully.

- [ ] **Step 6: Commit**

```bash
git add src/cli_providers.rs src/cli.rs src/main.rs
git commit -m "feat(cli): add flag groups for Okta, Tenable, Elastic, and GitHub"
```

---

### Task 2: Shared provider CLI plumbing and dispatch

**Files:**
- Create: `src/runner/provider_cli/mod.rs`
- Modify: `src/runner/mod.rs:1-9`
- Modify: `src/main.rs:41-75`

**Interfaces:**
- Consumes: `Cli` and its `okta`/`tenable`/`elastic`/`github` flag fields (Task 1).
- Produces:
  - `pub fn provider_mode_selected(cli: &Cli) -> bool`
  - `pub async fn run_provider_cli(cli: &Cli) -> anyhow::Result<()>`
  - `pub(crate) fn accounts_for(provider: CloudProvider, name: Option<&str>) -> Vec<Account>`
  - `pub(crate) fn resolve_window(cli: &Cli) -> anyhow::Result<CollectParams>`
  - `pub(crate) fn provider_output_dir(cli: &Cli, name: &str, account_output_dir: Option<&str>) -> PathBuf`
  - `pub(crate) fn finish_provider_run(cli, timestamp, account_id, params, outcomes, output_dir) -> anyhow::Result<()>` — exact signature in Step 1 below. Tasks 3–6 call all five.

**Note on the child-module declarations:** `mod.rs` written in this task declares `mod okta; mod tenable; mod elastic; mod github;` — but those files do not exist until Tasks 3–6, and the `cargo check` hook would fail. So in this task `mod.rs` is written **without** those declarations and with a `run_provider_cli` that bails with "not yet implemented" for each provider. Tasks 3–6 each add their own `mod` line and swap their bail for a real call. This keeps the tree compiling after every single write.

- [ ] **Step 1: Write `src/runner/provider_cli/mod.rs`**

```rust
//! Headless CLI path for the non-AWS providers.
//!
//! `run_standard_cli` is AWS-only: it builds an `AwsProviderFactory` and
//! nothing else. This module is its counterpart for Okta, Tenable, Elastic,
//! and GitHub — resolve accounts from the merged config (or from CLI/env
//! credentials when there is no config), build the provider client, hand the
//! selected keys to that provider's `ProviderFactory`, and drive the resulting
//! collectors through the same `collect_ops` runners the AWS path uses.
//!
//! Output layout matches the TUI: `{base}/{account name}/{YYYY}/{MM-MMM}/`.

use std::path::PathBuf;

use anyhow::{Context, Result};
use chrono::Utc;

use crate::app_config::{self, Account};
use crate::audit_log;
use crate::cli::Cli;
use crate::evidence::CollectParams;
use crate::providers::CloudProvider;
use crate::runner::output::date_path_suffix;

/// Days of history used when a provider run specifies no window flags.
/// Okta, GitHub, and Elastic all have time-windowed collectors (system log,
/// audit log, alerts) that would otherwise export their full retained history.
const DEFAULT_PROVIDER_LOOKBACK_DAYS: i64 = 30;

/// True when exactly one non-AWS provider mode flag was passed.
pub fn provider_mode_selected(cli: &Cli) -> bool {
    cli.okta.okta_enabled
        || cli.tenable.tenable_enabled
        || cli.elastic.elastic_enabled
        || cli.github.github_enabled
}

/// Entry point for `--okta` / `--tenable` / `--elastic` / `--github`.
pub async fn run_provider_cli(cli: &Cli) -> Result<()> {
    let modes = [
        (cli.okta.okta_enabled, "--okta"),
        (cli.tenable.tenable_enabled, "--tenable"),
        (cli.elastic.elastic_enabled, "--elastic"),
        (cli.github.github_enabled, "--github"),
    ];
    let active: Vec<&str> = modes
        .iter()
        .filter(|(on, _)| *on)
        .map(|(_, name)| *name)
        .collect();
    if active.len() > 1 {
        anyhow::bail!(
            "{} are mutually exclusive — run one provider per invocation",
            active.join(" and ")
        );
    }

    if cli.inventory {
        anyhow::bail!("--inventory is AWS-only and cannot be combined with a provider mode flag");
    }
    if cli.poam {
        anyhow::bail!("--poam cannot be combined with a provider mode flag");
    }
    if cli.collectors.is_some() {
        anyhow::bail!(
            "--collectors selects AWS collectors; use --<provider>-collectors \
             (e.g. --okta-collectors okta-users) with a provider mode flag"
        );
    }
    if cli.all_regions || cli.regions.is_some() {
        anyhow::bail!("--all-regions/--regions are AWS-only and do not apply to provider modes");
    }

    if cli.okta.okta_enabled {
        anyhow::bail!("--okta is not wired up yet");
    }
    if cli.tenable.tenable_enabled {
        anyhow::bail!("--tenable is not wired up yet");
    }
    if cli.elastic.elastic_enabled {
        anyhow::bail!("--elastic is not wired up yet");
    }
    if cli.github.github_enabled {
        anyhow::bail!("--github is not wired up yet");
    }

    Ok(())
}

/// Accounts of `provider` from the merged config (config.toml plus the sibling
/// `*-config.toml` files), optionally narrowed to one by `name`.
/// Returns an empty vec when no config file exists — callers fall back to
/// CLI-flag/env credentials in that case.
pub(crate) fn accounts_for(provider: CloudProvider, name: Option<&str>) -> Vec<Account> {
    let Some(cfg) = app_config::load_config() else {
        return Vec::new();
    };
    cfg.account
        .into_iter()
        .filter(|a| a.provider == provider)
        .filter(|a| match name {
            Some(n) => a.name.eq_ignore_ascii_case(n),
            None => true,
        })
        .collect()
}

/// Build the collection window from `--lookback` or `--start-date`/`--end-date`.
/// Defaults to the last [`DEFAULT_PROVIDER_LOOKBACK_DAYS`] days and says so on
/// stderr, so a bare `grabber --okta` never silently exports full history.
pub(crate) fn resolve_window(cli: &Cli) -> Result<CollectParams> {
    let today = Utc::now().date_naive();

    let (start_date, end_date) = if let Some(ref lb) = cli.lookback {
        if cli.start_date.is_some() || cli.end_date.is_some() {
            anyhow::bail!("--lookback cannot be combined with --start-date or --end-date");
        }
        (crate::cli::parse_lookback(lb)?, today)
    } else if let Some(ref start) = cli.start_date {
        let end = cli
            .end_date
            .as_deref()
            .context("--end-date is required when --start-date is provided")?;
        (
            chrono::NaiveDate::parse_from_str(start, "%Y-%m-%d").context("Invalid --start-date")?,
            chrono::NaiveDate::parse_from_str(end, "%Y-%m-%d").context("Invalid --end-date")?,
        )
    } else {
        let start = today - chrono::Duration::days(DEFAULT_PROVIDER_LOOKBACK_DAYS);
        eprintln!(
            "No window flags given — defaulting to the last {} days ({} → {}). \
             Pass --lookback or --start-date/--end-date to override.",
            DEFAULT_PROVIDER_LOOKBACK_DAYS, start, today
        );
        (start, today)
    };

    Ok(CollectParams {
        start_time: start_date
            .and_hms_opt(0, 0, 0)
            .context("invalid start-of-day time")?
            .and_utc(),
        end_time: end_date
            .and_hms_opt(23, 59, 59)
            .context("invalid end-of-day time")?
            .and_utc(),
        filter: cli.filter.clone(),
        include_raw: cli.include_raw,
    })
}

/// Output directory for one provider account, matching the TUI layout.
///
/// `--output` wins and gets the account name appended. Otherwise the account's
/// own `output_dir` is used as-is (it already names the provider, e.g.
/// `./evidence-output/okta`). With neither, files land under `./{name}/`.
/// The `{YYYY}/{MM-MMM}` date hierarchy is appended in every case.
pub(crate) fn provider_output_dir(
    cli: &Cli,
    name: &str,
    account_output_dir: Option<&str>,
) -> PathBuf {
    let base = match (
        cli.output.as_ref(),
        account_output_dir.map(str::trim).filter(|s| !s.is_empty()),
    ) {
        (Some(out), _) => out.join(name),
        (None, Some(dir)) => PathBuf::from(dir),
        (None, None) => PathBuf::from(".").join(name),
    };
    base.join(date_path_suffix())
}

/// Post-run artifacts shared by every provider: run manifest, zip, signing.
///
/// Chain-of-custody is intentionally skipped — `CustodyEntry` is built around
/// an `AwsIdentity` (account id, caller ARN, user id) that has no meaning for
/// these providers. `--write-chain-of-custody` warns instead of failing.
pub(crate) fn finish_provider_run(
    cli: &Cli,
    timestamp: &str,
    account_id: &str,
    params: &CollectParams,
    outcomes: Vec<audit_log::CollectorOutcome>,
    output_dir: &PathBuf,
) -> Result<()> {
    if cli.write_run_manifest {
        let manifest = audit_log::RunManifest::build(
            timestamp,
            account_id,
            "",
            &params.start_time.format("%Y-%m-%d").to_string(),
            &params.end_time.format("%Y-%m-%d").to_string(),
            outcomes,
        );
        match audit_log::write_run_manifest(output_dir, &manifest) {
            Ok(p) => eprintln!("Run manifest written: {}", p.display()),
            Err(e) => eprintln!("WARN: could not write run manifest: {e}"),
        }
    }

    if cli.write_chain_of_custody {
        eprintln!(
            "WARN: --write-chain-of-custody is AWS-only (the custody record is keyed \
             on an AWS caller identity) — skipping for this provider run."
        );
    }

    if cli.zip {
        let zip_name = format!("Evidence-{}.zip", timestamp);
        let zip_path = std::path::Path::new(&zip_name);
        match crate::zip_bundle::bundle_dir(output_dir, zip_path) {
            Ok(()) => eprintln!("Zip bundle written: {}", zip_name),
            Err(e) => eprintln!("Zip bundle failed: {e}"),
        }
    }

    if cli.sign {
        let key = match &cli.signing_key {
            Some(hex) => crate::signing::SigningKey::from_hex(hex)?,
            None => crate::signing::SigningKey::generate()?,
        };
        let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
        let files = crate::signing::collect_dir_files(output_dir);
        match crate::signing::sign_files(&files, timestamp, &key, &cwd) {
            Ok((manifest_path, key_path)) => {
                eprintln!("Signing manifest: {}", manifest_path.display());
                eprintln!(
                    "Signing key file: {} (move to secure storage)",
                    key_path.display()
                );
                eprintln!("Signing key (hex): {}", key.to_hex());
            }
            Err(e) => eprintln!("Signing failed: {e}"),
        }
    }

    Ok(())
}
```

- [ ] **Step 2: Declare the module in `src/runner/mod.rs`**

The file becomes:

```rust
pub mod cli_runners;
pub mod collect_ops;
pub mod collector_registry;
pub mod failure_classifier;
pub mod multi_account;
pub mod multi_region_cli;
pub mod output;
pub mod provider_cli;
pub mod tui_runners;
pub mod tui_session;
```

- [ ] **Step 3: Dispatch from `src/main.rs`**

Update the import line:

```rust
use crate::runner::cli_runners::{run_inventory_cli, run_poam_cli, run_standard_cli};
use crate::runner::provider_cli::{provider_mode_selected, run_provider_cli};
use crate::runner::tui_session::run_tui_session;
```

Then insert the branch in `async_main`, immediately after the verify-manifest block and **before** the `if cli.inventory` check (so the guards inside `run_provider_cli` produce the good error message rather than inventory mode silently winning):

```rust
    if provider_mode_selected(&cli) {
        return run_provider_cli(&cli).await;
    }

    if cli.inventory {
        return run_inventory_cli(&cli).await;
    }
```

- [ ] **Step 4: Verify dispatch and guards**

```bash
cargo fmt
cargo clippy -- -D warnings
cargo run -- --okta 2>&1 | tail -3
cargo run -- --okta --github 2>&1 | tail -3
cargo run -- --okta --inventory 2>&1 | tail -3
cargo run -- --okta --collectors iam-users 2>&1 | tail -3
```

Expected, in order: `--okta is not wired up yet`; `--okta and --github are mutually exclusive — run one provider per invocation`; `--inventory is AWS-only and cannot be combined with a provider mode flag`; `--collectors selects AWS collectors; use --<provider>-collectors …`. Critically, none of these should launch the TUI.

- [ ] **Step 5: Commit**

```bash
git add src/runner/provider_cli/mod.rs src/runner/mod.rs src/main.rs
git commit -m "feat(cli): add provider CLI dispatch and shared run plumbing"
```

---

### Task 3: Okta headless runner

**Files:**
- Create: `src/runner/provider_cli/okta.rs`
- Modify: `src/runner/provider_cli/mod.rs` (add `mod okta;`, replace the Okta bail)

**Interfaces:**
- Consumes: `super::{accounts_for, finish_provider_run, provider_output_dir, resolve_window}` (Task 2); `cli.okta.resolve_collectors()` (Task 1); `crate::providers::okta::factory::OktaProviderFactory::new(client, tenant_name, selected)`; `okta_rs::OktaClient::new(&domain, &token)`; `Account::okta_domain_resolved()` / `okta_api_token_resolved()`.
- Produces: `pub(super) async fn run(cli: &Cli) -> anyhow::Result<()>`.

**Credential precedence** (highest first): `--okta-domain` / `--okta-api-token` → `OKTA_DOMAIN` / `OKTA_API_TOKEN` env → `config.toml` value. The `*_resolved()` helpers on `Account` already implement the env-over-TOML half, so the runner only layers the CLI flag on top.

- [ ] **Step 1: Write `src/runner/provider_cli/okta.rs`**

```rust
//! `--okta`: headless Okta evidence collection.

use anyhow::Result;
use chrono::Utc;

use crate::cli::Cli;

#[cfg(feature = "okta")]
pub(super) async fn run(cli: &Cli) -> Result<()> {
    use crate::providers::CloudProvider;
    use crate::providers::ProviderFactory as _;
    use crate::runner::collect_ops::{
        run_csv_collectors, run_json_collectors, run_json_inv_collectors,
    };

    let selected = cli.okta.resolve_collectors()?;
    let params = super::resolve_window(cli)?;
    eprintln!("Okta collectors: {}", selected.join(", "));

    // (tenant name, domain, api token, per-account output_dir)
    let mut targets: Vec<(String, String, String, Option<String>)> = Vec::new();

    let accounts = super::accounts_for(CloudProvider::Okta, cli.okta.okta_account.as_deref());
    if accounts.is_empty() {
        let name = cli
            .okta
            .okta_account
            .clone()
            .unwrap_or_else(|| "Okta".to_string());
        let domain = cli
            .okta
            .okta_domain
            .clone()
            .or_else(|| std::env::var("OKTA_DOMAIN").ok())
            .filter(|s| !s.trim().is_empty());
        let token = cli
            .okta
            .okta_api_token
            .clone()
            .or_else(|| std::env::var("OKTA_API_TOKEN").ok())
            .filter(|s| !s.trim().is_empty());
        match (domain, token) {
            (Some(d), Some(t)) => targets.push((name, d, t, None)),
            _ => anyhow::bail!(
                "No Okta account found. Add an [[account]] with provider = \"okta\" to \
                 okta-config.toml, or pass --okta-domain and --okta-api-token \
                 (or set OKTA_DOMAIN and OKTA_API_TOKEN)."
            ),
        }
    } else {
        for acct in &accounts {
            let domain = cli
                .okta
                .okta_domain
                .clone()
                .or_else(|| acct.okta_domain_resolved());
            let token = cli
                .okta
                .okta_api_token
                .clone()
                .or_else(|| acct.okta_api_token_resolved());
            match (domain, token) {
                (Some(d), Some(t)) => {
                    targets.push((acct.name.clone(), d, t, acct.output_dir.clone()))
                }
                (None, _) => eprintln!(
                    "  ✗ Okta '{}' — missing okta_domain (or OKTA_DOMAIN env) — skipping",
                    acct.name
                ),
                (_, None) => eprintln!(
                    "  ✗ Okta '{}' — missing okta_api_token (or OKTA_API_TOKEN env) — skipping",
                    acct.name
                ),
            }
        }
        if targets.is_empty() {
            anyhow::bail!("No Okta account had usable credentials.");
        }
    }

    let timestamp = Utc::now().format("%Y-%m-%d-%H%M%S").to_string();
    let dates = Some((params.start_time.timestamp(), params.end_time.timestamp()));

    for (name, domain, token, account_output_dir) in targets {
        eprintln!("=== Okta '{}' → {} ===", name, domain);

        let client = okta_rs::OktaClient::new(&domain, &token)
            .map_err(|e| anyhow::anyhow!("Okta '{name}' — client build failed: {e}"))?;

        let factory = crate::providers::okta::factory::OktaProviderFactory::new(
            client,
            name.clone(),
            selected.clone(),
        );
        let csv_cols = factory.csv_collectors();
        let json_inv_cols = factory.json_collectors();
        let evidence_cols = factory.evidence_collectors();
        if csv_cols.is_empty() && json_inv_cols.is_empty() && evidence_cols.is_empty() {
            anyhow::bail!("No Okta collectors matched the selected keys.");
        }

        let output_dir = super::provider_output_dir(cli, &name, account_output_dir.as_deref());
        eprintln!("  Output: {}", output_dir.display());

        let mut outcomes = Vec::new();
        outcomes
            .extend(run_json_collectors(&evidence_cols, &params, "", &output_dir, &timestamp).await?);
        outcomes.extend(
            run_json_inv_collectors(&json_inv_cols, &name, "", &output_dir, &timestamp).await?,
        );
        outcomes.extend(
            run_csv_collectors(&csv_cols, &name, "", &output_dir, dates, &timestamp).await?,
        );

        super::finish_provider_run(cli, &timestamp, &name, &params, outcomes, &output_dir)?;
    }

    Ok(())
}

#[cfg(not(feature = "okta"))]
pub(super) async fn run(_cli: &Cli) -> Result<()> {
    anyhow::bail!("--okta requires a build with the `okta` feature enabled")
}
```

- [ ] **Step 2: Wire it into `src/runner/provider_cli/mod.rs`**

Add the module declaration at the top of the file, immediately after the doc comment and before the `use` block:

```rust
mod okta;
```

Then replace the Okta bail in `run_provider_cli`:

```rust
    if cli.okta.okta_enabled {
        return okta::run(cli).await;
    }
```

- [ ] **Step 3: Verify**

```bash
cargo fmt
cargo clippy -- -D warnings
cargo run -- --okta --okta-collectors okta-bogus 2>&1 | tail -3
cargo run -- --okta --okta-users --okta-groups --okta-domain https://example.okta.com --okta-api-token bad 2>&1 | head -20
```

Expected: the first prints `--okta-collectors: unknown key 'okta-bogus'. Valid keys: okta-users, …`. The second prints `Okta collectors: okta-users, okta-groups`, the default-window notice, `=== Okta 'Okta' → https://example.okta.com ===`, an output path, and then per-collector auth failures from the API — proving the whole pipeline runs end to end.

If a real Okta tenant is configured, do the true smoke test and confirm CSVs land in the dated directory:

```bash
cargo run -- --okta --okta-users --lookback 7d -o /tmp/okta-cli-smoke
find /tmp/okta-cli-smoke -name '*.csv'
```

- [ ] **Step 4: Commit**

```bash
git add src/runner/provider_cli/okta.rs src/runner/provider_cli/mod.rs
git commit -m "feat(cli): add headless --okta collection mode"
```

---

### Task 4: Tenable headless runner

**Files:**
- Create: `src/runner/provider_cli/tenable.rs`
- Modify: `src/runner/provider_cli/mod.rs` (add `mod tenable;`, replace the Tenable bail)

**Interfaces:**
- Consumes: the same four `super::` helpers; `cli.tenable.resolve_collectors()`; `tenable_rs::TenableClient::from_url(&base_url, &access_key, &secret_key) -> Result<(TenableClient, _)>`; `tenable_rs::TenableFlavor::for_url(&base_url)` with `.label()`; `Account::tenable_url_resolved() -> String` (already defaults to the Tenable.io URL), `tenable_access_key_resolved()`, `tenable_secret_key_resolved()`; `TenableProviderFactory::new(client, site_name, selected, selected_scan_ids, selected_was_scan_ids)`.
- Produces: `pub(super) async fn run(cli: &Cli) -> anyhow::Result<()>`.

**On scan IDs:** `--tenable-scan-ids` and `--tenable-was-scan-ids` replace the TUI's scan-selection screen. Empty is the correct default for both — `was.rs:81` only filters when its list is non-empty, and `vulnerabilities.rs` documents that the export API is UUID-keyed and ignores the integer selection entirely.

- [ ] **Step 1: Write `src/runner/provider_cli/tenable.rs`**

```rust
//! `--tenable`: headless Tenable evidence collection.

use anyhow::Result;
use chrono::Utc;

use crate::cli::Cli;

#[cfg(feature = "tenable")]
pub(super) async fn run(cli: &Cli) -> Result<()> {
    use crate::providers::CloudProvider;
    use crate::providers::ProviderFactory as _;
    use crate::runner::collect_ops::{
        run_csv_collectors, run_json_collectors, run_json_inv_collectors,
    };

    let selected = cli.tenable.resolve_collectors()?;
    let params = super::resolve_window(cli)?;
    eprintln!("Tenable collectors: {}", selected.join(", "));

    let scan_ids = cli.tenable.tenable_scan_ids.clone().unwrap_or_default();
    let was_scan_ids = cli.tenable.tenable_was_scan_ids.clone().unwrap_or_default();

    // (site name, base url, access key, secret key, per-account output_dir)
    let mut targets: Vec<(String, String, String, String, Option<String>)> = Vec::new();

    let accounts = super::accounts_for(
        CloudProvider::Tenable,
        cli.tenable.tenable_account.as_deref(),
    );
    if accounts.is_empty() {
        let name = cli
            .tenable
            .tenable_account
            .clone()
            .unwrap_or_else(|| "Tenable".to_string());
        let base_url = cli
            .tenable
            .tenable_url
            .clone()
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| "https://cloud.tenable.com".to_string());
        let access_key = cli
            .tenable
            .tenable_access_key
            .clone()
            .or_else(|| std::env::var("TENABLE_ACCESS_KEY").ok())
            .filter(|s| !s.trim().is_empty());
        let secret_key = cli
            .tenable
            .tenable_secret_key
            .clone()
            .or_else(|| std::env::var("TENABLE_SECRET_KEY").ok())
            .filter(|s| !s.trim().is_empty());
        match (access_key, secret_key) {
            (Some(a), Some(s)) => targets.push((name, base_url, a, s, None)),
            _ => anyhow::bail!(
                "No Tenable account found. Add an [[account]] with provider = \"tenable\" to \
                 tenable-config.toml, or pass --tenable-access-key and --tenable-secret-key \
                 (or set TENABLE_ACCESS_KEY and TENABLE_SECRET_KEY)."
            ),
        }
    } else {
        for acct in &accounts {
            let base_url = cli
                .tenable
                .tenable_url
                .clone()
                .filter(|s| !s.trim().is_empty())
                .unwrap_or_else(|| acct.tenable_url_resolved());
            let access_key = cli
                .tenable
                .tenable_access_key
                .clone()
                .or_else(|| acct.tenable_access_key_resolved());
            let secret_key = cli
                .tenable
                .tenable_secret_key
                .clone()
                .or_else(|| acct.tenable_secret_key_resolved());
            match (access_key, secret_key) {
                (Some(a), Some(s)) => targets.push((
                    acct.name.clone(),
                    base_url,
                    a,
                    s,
                    acct.output_dir.clone(),
                )),
                _ => {
                    let flavor = tenable_rs::TenableFlavor::for_url(&base_url);
                    eprintln!(
                        "  ✗ Tenable '{}' — missing access/secret key for {} — skipping. {}",
                        acct.name,
                        flavor.label(),
                        flavor.api_keys_hint()
                    );
                }
            }
        }
        if targets.is_empty() {
            anyhow::bail!("No Tenable account had usable credentials.");
        }
    }

    let timestamp = Utc::now().format("%Y-%m-%d-%H%M%S").to_string();
    let dates = Some((params.start_time.timestamp(), params.end_time.timestamp()));

    for (name, base_url, access_key, secret_key, account_output_dir) in targets {
        let flavor = tenable_rs::TenableFlavor::for_url(&base_url);
        eprintln!("=== Tenable '{}' → {} ({}) ===", name, base_url, flavor.label());

        let (client, _) = tenable_rs::TenableClient::from_url(&base_url, &access_key, &secret_key)
            .map_err(|e| anyhow::anyhow!("Tenable '{name}' — client build failed: {e}"))?;

        let factory = crate::providers::tenable::factory::TenableProviderFactory::new(
            client,
            name.clone(),
            selected.clone(),
            scan_ids.clone(),
            was_scan_ids.clone(),
        );
        let csv_cols = factory.csv_collectors();
        let json_inv_cols = factory.json_collectors();
        let evidence_cols = factory.evidence_collectors();
        if csv_cols.is_empty() && json_inv_cols.is_empty() && evidence_cols.is_empty() {
            anyhow::bail!("No Tenable collectors matched the selected keys.");
        }

        let output_dir = super::provider_output_dir(cli, &name, account_output_dir.as_deref());
        eprintln!("  Output: {}", output_dir.display());

        let mut outcomes = Vec::new();
        outcomes
            .extend(run_json_collectors(&evidence_cols, &params, "", &output_dir, &timestamp).await?);
        outcomes.extend(
            run_json_inv_collectors(&json_inv_cols, &name, "", &output_dir, &timestamp).await?,
        );
        outcomes.extend(
            run_csv_collectors(&csv_cols, &name, "", &output_dir, dates, &timestamp).await?,
        );

        super::finish_provider_run(cli, &timestamp, &name, &params, outcomes, &output_dir)?;
    }

    Ok(())
}

#[cfg(not(feature = "tenable"))]
pub(super) async fn run(_cli: &Cli) -> Result<()> {
    anyhow::bail!("--tenable requires a build with the `tenable` feature enabled")
}
```

- [ ] **Step 2: Wire it into `src/runner/provider_cli/mod.rs`**

Add `mod tenable;` beneath `mod okta;`, then replace the Tenable bail:

```rust
    if cli.tenable.tenable_enabled {
        return tenable::run(cli).await;
    }
```

- [ ] **Step 3: Verify**

```bash
cargo fmt
cargo clippy -- -D warnings
cargo run -- --tenable --tenable-collectors tenable-bogus 2>&1 | tail -3
cargo run -- --tenable --tenable-assets --tenable-access-key bad --tenable-secret-key bad 2>&1 | head -20
cargo run -- --tenable --tenable-was --tenable-was-scan-ids abc,def --tenable-access-key bad --tenable-secret-key bad 2>&1 | head -10
```

Expected: unknown-key rejection first; then `Tenable collectors: tenable-assets`, the endpoint line naming the Tenable.io flavor, and API auth failures per collector. The third confirms the WAS scan-ID list parses as strings without a panic.

- [ ] **Step 4: Commit**

```bash
git add src/runner/provider_cli/tenable.rs src/runner/provider_cli/mod.rs
git commit -m "feat(cli): add headless --tenable collection mode"
```

---

### Task 5: Elastic headless runner

**Files:**
- Create: `src/runner/provider_cli/elastic.rs`
- Modify: `src/runner/provider_cli/mod.rs` (add `mod elastic;`, replace the Elastic bail)

**Interfaces:**
- Consumes: the same four `super::` helpers; `cli.elastic.resolve_collectors()`; `elastic_rs::ElasticClient::new(&kibana_url, &es_url, &api_key)`; `Account::elastic_kibana_url_resolved()`, `elastic_es_url_resolved()`, `elastic_api_key_resolved()`; `ElasticProviderFactory::new(client, deployment_name, selected)`.
- Produces: `pub(super) async fn run(cli: &Cli) -> anyhow::Result<()>`.

- [ ] **Step 1: Write `src/runner/provider_cli/elastic.rs`**

```rust
//! `--elastic`: headless Elastic Security evidence collection.

use anyhow::Result;
use chrono::Utc;

use crate::cli::Cli;

#[cfg(feature = "elastic")]
pub(super) async fn run(cli: &Cli) -> Result<()> {
    use crate::providers::CloudProvider;
    use crate::providers::ProviderFactory as _;
    use crate::runner::collect_ops::{
        run_csv_collectors, run_json_collectors, run_json_inv_collectors,
    };

    let selected = cli.elastic.resolve_collectors()?;
    let params = super::resolve_window(cli)?;
    eprintln!("Elastic collectors: {}", selected.join(", "));

    // (deployment name, kibana url, es url, api key, per-account output_dir)
    let mut targets: Vec<(String, String, String, String, Option<String>)> = Vec::new();

    let accounts = super::accounts_for(
        CloudProvider::Elastic,
        cli.elastic.elastic_account.as_deref(),
    );
    if accounts.is_empty() {
        let name = cli
            .elastic
            .elastic_account
            .clone()
            .unwrap_or_else(|| "Elastic".to_string());
        let kibana_url = cli
            .elastic
            .elastic_kibana_url
            .clone()
            .or_else(|| std::env::var("ELASTIC_KIBANA_URL").ok())
            .filter(|s| !s.trim().is_empty());
        let es_url = cli
            .elastic
            .elastic_es_url
            .clone()
            .or_else(|| std::env::var("ELASTIC_ES_URL").ok())
            .filter(|s| !s.trim().is_empty());
        let api_key = cli
            .elastic
            .elastic_api_key
            .clone()
            .or_else(|| std::env::var("ELASTIC_API_KEY").ok())
            .filter(|s| !s.trim().is_empty());
        match (kibana_url, es_url, api_key) {
            (Some(k), Some(e), Some(a)) => targets.push((name, k, e, a, None)),
            _ => anyhow::bail!(
                "No Elastic account found. Add an [[account]] with provider = \"elastic\" to \
                 elastic-config.toml, or pass --elastic-kibana-url, --elastic-es-url and \
                 --elastic-api-key (or set ELASTIC_KIBANA_URL, ELASTIC_ES_URL, ELASTIC_API_KEY)."
            ),
        }
    } else {
        for acct in &accounts {
            let kibana_url = cli
                .elastic
                .elastic_kibana_url
                .clone()
                .or_else(|| acct.elastic_kibana_url_resolved());
            let es_url = cli
                .elastic
                .elastic_es_url
                .clone()
                .or_else(|| acct.elastic_es_url_resolved());
            let api_key = cli
                .elastic
                .elastic_api_key
                .clone()
                .or_else(|| acct.elastic_api_key_resolved());
            match (kibana_url, es_url, api_key) {
                (Some(k), Some(e), Some(a)) => {
                    targets.push((acct.name.clone(), k, e, a, acct.output_dir.clone()))
                }
                (None, _, _) => eprintln!(
                    "  ✗ Elastic '{}' — missing elastic_kibana_url (or ELASTIC_KIBANA_URL env) — skipping",
                    acct.name
                ),
                (_, None, _) => eprintln!(
                    "  ✗ Elastic '{}' — missing elastic_es_url (or ELASTIC_ES_URL env) — skipping",
                    acct.name
                ),
                (_, _, None) => eprintln!(
                    "  ✗ Elastic '{}' — missing elastic_api_key (or ELASTIC_API_KEY env) — skipping",
                    acct.name
                ),
            }
        }
        if targets.is_empty() {
            anyhow::bail!("No Elastic account had usable credentials.");
        }
    }

    let timestamp = Utc::now().format("%Y-%m-%d-%H%M%S").to_string();
    let dates = Some((params.start_time.timestamp(), params.end_time.timestamp()));

    for (name, kibana_url, es_url, api_key, account_output_dir) in targets {
        eprintln!("=== Elastic '{}' → {} ===", name, kibana_url);

        let client = elastic_rs::ElasticClient::new(&kibana_url, &es_url, &api_key)
            .map_err(|e| anyhow::anyhow!("Elastic '{name}' — client build failed: {e}"))?;

        let factory = crate::providers::elastic::factory::ElasticProviderFactory::new(
            client,
            name.clone(),
            selected.clone(),
        );
        let csv_cols = factory.csv_collectors();
        let json_inv_cols = factory.json_collectors();
        let evidence_cols = factory.evidence_collectors();
        if csv_cols.is_empty() && json_inv_cols.is_empty() && evidence_cols.is_empty() {
            anyhow::bail!("No Elastic collectors matched the selected keys.");
        }

        let output_dir = super::provider_output_dir(cli, &name, account_output_dir.as_deref());
        eprintln!("  Output: {}", output_dir.display());

        let mut outcomes = Vec::new();
        outcomes
            .extend(run_json_collectors(&evidence_cols, &params, "", &output_dir, &timestamp).await?);
        outcomes.extend(
            run_json_inv_collectors(&json_inv_cols, &name, "", &output_dir, &timestamp).await?,
        );
        outcomes.extend(
            run_csv_collectors(&csv_cols, &name, "", &output_dir, dates, &timestamp).await?,
        );

        super::finish_provider_run(cli, &timestamp, &name, &params, outcomes, &output_dir)?;
    }

    Ok(())
}

#[cfg(not(feature = "elastic"))]
pub(super) async fn run(_cli: &Cli) -> Result<()> {
    anyhow::bail!("--elastic requires a build with the `elastic` feature enabled")
}
```

- [ ] **Step 2: Wire it into `src/runner/provider_cli/mod.rs`**

Add `mod elastic;` beneath `mod tenable;`, then replace the Elastic bail:

```rust
    if cli.elastic.elastic_enabled {
        return elastic::run(cli).await;
    }
```

- [ ] **Step 3: Verify**

```bash
cargo fmt
cargo clippy -- -D warnings
cargo run -- --elastic --elastic-collectors elastic-bogus 2>&1 | tail -3
cargo run -- --elastic --elastic-rules --elastic-kibana-url https://kb.example.com \
    --elastic-es-url https://es.example.com --elastic-api-key bad 2>&1 | head -20
```

Expected: unknown-key rejection, then `Elastic collectors: elastic-rules`, the endpoint line, an output path, and a connection/auth failure from the collector.

- [ ] **Step 4: Commit**

```bash
git add src/runner/provider_cli/elastic.rs src/runner/provider_cli/mod.rs
git commit -m "feat(cli): add headless --elastic collection mode"
```

---

### Task 6: GitHub headless runner

**Files:**
- Create: `src/runner/provider_cli/github.rs`
- Modify: `src/runner/provider_cli/mod.rs` (add `mod github;`, replace the GitHub bail)

**Interfaces:**
- Consumes: the same four `super::` helpers; `cli.github.resolve_collectors()`; `github_rs::GithubClient::new(&base_url, &token, &org)` — note the argument order is (base_url, token, org); `Account::github_org_resolved()`, `github_token_resolved()`, `github_base_url_resolved() -> String` (already defaults to the public API URL); `GithubProviderFactory::new(client, org_name, selected)`.
- Produces: `pub(super) async fn run(cli: &Cli) -> anyhow::Result<()>`.

- [ ] **Step 1: Write `src/runner/provider_cli/github.rs`**

```rust
//! `--github`: headless GitHub organization evidence collection.

use anyhow::Result;
use chrono::Utc;

use crate::cli::Cli;

#[cfg(feature = "github")]
pub(super) async fn run(cli: &Cli) -> Result<()> {
    use crate::providers::CloudProvider;
    use crate::providers::ProviderFactory as _;
    use crate::runner::collect_ops::{
        run_csv_collectors, run_json_collectors, run_json_inv_collectors,
    };

    let selected = cli.github.resolve_collectors()?;
    let params = super::resolve_window(cli)?;
    eprintln!("GitHub collectors: {}", selected.join(", "));

    // (account name, org, token, base url, per-account output_dir)
    let mut targets: Vec<(String, String, String, String, Option<String>)> = Vec::new();

    let accounts =
        super::accounts_for(CloudProvider::Github, cli.github.github_account.as_deref());
    if accounts.is_empty() {
        let name = cli
            .github
            .github_account
            .clone()
            .unwrap_or_else(|| "GitHub".to_string());
        let org = cli
            .github
            .github_org
            .clone()
            .or_else(|| std::env::var("GITHUB_ORG").ok())
            .filter(|s| !s.trim().is_empty());
        let token = cli
            .github
            .github_token
            .clone()
            .or_else(|| std::env::var("GITHUB_TOKEN").ok())
            .filter(|s| !s.trim().is_empty());
        let base_url = cli
            .github
            .github_base_url
            .clone()
            .or_else(|| std::env::var("GITHUB_BASE_URL").ok())
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| "https://api.github.com".to_string());
        match (org, token) {
            (Some(o), Some(t)) => targets.push((name, o, t, base_url, None)),
            _ => anyhow::bail!(
                "No GitHub account found. Add an [[account]] with provider = \"github\" to \
                 github-config.toml, or pass --github-org and --github-token \
                 (or set GITHUB_ORG and GITHUB_TOKEN)."
            ),
        }
    } else {
        for acct in &accounts {
            let org = cli
                .github
                .github_org
                .clone()
                .or_else(|| acct.github_org_resolved());
            let token = cli
                .github
                .github_token
                .clone()
                .or_else(|| acct.github_token_resolved());
            let base_url = cli
                .github
                .github_base_url
                .clone()
                .filter(|s| !s.trim().is_empty())
                .unwrap_or_else(|| acct.github_base_url_resolved());
            match (org, token) {
                (Some(o), Some(t)) => {
                    targets.push((acct.name.clone(), o, t, base_url, acct.output_dir.clone()))
                }
                (None, _) => eprintln!(
                    "  ✗ GitHub '{}' — missing github_org (or GITHUB_ORG env) — skipping",
                    acct.name
                ),
                (_, None) => eprintln!(
                    "  ✗ GitHub '{}' — missing github_token (or GITHUB_TOKEN env) — skipping",
                    acct.name
                ),
            }
        }
        if targets.is_empty() {
            anyhow::bail!("No GitHub account had usable credentials.");
        }
    }

    let timestamp = Utc::now().format("%Y-%m-%d-%H%M%S").to_string();
    let dates = Some((params.start_time.timestamp(), params.end_time.timestamp()));

    for (name, org, token, base_url, account_output_dir) in targets {
        eprintln!("=== GitHub '{}' → {} ({}) ===", name, org, base_url);

        let client = github_rs::GithubClient::new(&base_url, &token, &org)
            .map_err(|e| anyhow::anyhow!("GitHub '{name}' — client build failed: {e}"))?;

        let factory = crate::providers::github::factory::GithubProviderFactory::new(
            client,
            org.clone(),
            selected.clone(),
        );
        let csv_cols = factory.csv_collectors();
        let json_inv_cols = factory.json_collectors();
        let evidence_cols = factory.evidence_collectors();
        if csv_cols.is_empty() && json_inv_cols.is_empty() && evidence_cols.is_empty() {
            anyhow::bail!("No GitHub collectors matched the selected keys.");
        }

        let output_dir = super::provider_output_dir(cli, &name, account_output_dir.as_deref());
        eprintln!("  Output: {}", output_dir.display());

        let mut outcomes = Vec::new();
        outcomes
            .extend(run_json_collectors(&evidence_cols, &params, "", &output_dir, &timestamp).await?);
        outcomes.extend(
            run_json_inv_collectors(&json_inv_cols, &org, "", &output_dir, &timestamp).await?,
        );
        outcomes
            .extend(run_csv_collectors(&csv_cols, &org, "", &output_dir, dates, &timestamp).await?);

        super::finish_provider_run(cli, &timestamp, &name, &params, outcomes, &output_dir)?;
    }

    Ok(())
}

#[cfg(not(feature = "github"))]
pub(super) async fn run(_cli: &Cli) -> Result<()> {
    anyhow::bail!("--github requires a build with the `github` feature enabled")
}
```

Note the `account_id` argument to the CSV/JSON runners is `org`, not `name` — GitHub output filenames are keyed on the org login, matching how `GithubProviderFactory::account_id()` returns `org_name`.

- [ ] **Step 2: Wire it into `src/runner/provider_cli/mod.rs`**

Add `mod github;` beneath `mod elastic;`, then replace the GitHub bail:

```rust
    if cli.github.github_enabled {
        return github::run(cli).await;
    }
```

At this point every branch in `run_provider_cli` returns, so the trailing `Ok(())` becomes unreachable-but-harmless; leave it as the fallthrough for the "no mode selected" case (`provider_mode_selected` guards against that, but the function stays total).

- [ ] **Step 3: Verify all four providers plus a no-default-features build**

```bash
cargo fmt
cargo clippy -- -D warnings
cargo run -- --github --github-collectors github-bogus 2>&1 | tail -3
cargo run -- --github --github-members --github-org acme --github-token bad 2>&1 | head -20
cargo build --no-default-features 2>&1 | tail -3
```

Expected: unknown-key rejection; then `GitHub collectors: github-members`, the endpoint line, and a 401 from the API. The `--no-default-features` build must compile — that is what proves the `#[cfg(not(feature = "..."))]` stubs are correct.

Then confirm the feature-off error path actually fires:

```bash
cargo run --no-default-features -- --github --github-members 2>&1 | tail -2
```

Expected: `--github requires a build with the `github` feature enabled`.

- [ ] **Step 4: Commit**

```bash
git add src/runner/provider_cli/github.rs src/runner/provider_cli/mod.rs
git commit -m "feat(cli): add headless --github collection mode"
```

---

### Task 7: Documentation

**Files:**
- Modify: `docs/cli-reference.md` (Table of Contents ~line 8; new section after "Inventory Mode"; the stale claim at line 445)
- Modify: `README.md` (CLI flag tables, near the inventory table at line 308)

**Interfaces:**
- Consumes: the final flag names from Tasks 1–6. Before writing, run `cargo run -- --help` and copy the flag names from the output rather than from this plan, so the docs match what actually shipped.

- [ ] **Step 1: Correct the stale TUI-only claim**

In `docs/cli-reference.md:445`, the sentence currently reads:

> Non-AWS keys are namespaced with their provider prefix (`okta-*`, `jira-*`, `tenable-*`, `elastic-*`, `github-*`) — see the provider sections in the main [README](../README.md) for the canonical lists. Non-AWS providers (Okta, Jira, Tenable, Elastic, GitHub) are TUI-only today; `--collectors` only affects the AWS headless CLI path.

Replace the second sentence:

> Non-AWS keys are namespaced with their provider prefix (`okta-*`, `jira-*`, `tenable-*`, `elastic-*`, `github-*`) — see the provider sections in the main [README](../README.md) for the canonical lists. `--collectors` only affects the AWS headless CLI path; Okta, Tenable, Elastic, and GitHub have their own mode flags and per-collector flags (see [Provider Modes](#provider-modes)). Jira remains TUI-only.

- [ ] **Step 2: Add the "Provider Modes" section to `docs/cli-reference.md`**

Add `- [Provider Modes](#provider-modes)` to the Table of Contents after the Inventory Mode entry, and insert this section after the Inventory Mode section (before "POA&M Mode"):

````markdown
---

## Provider Modes

Okta, Tenable, Elastic Security, and GitHub each have a mode flag that runs that
provider's collectors headlessly. The four are mutually exclusive — run one
provider per invocation. They cannot be combined with `--inventory`, `--poam`,
`--collectors`, `--all-regions`, or `--regions`.

| Provider | Mode flag | Collectors | Key list flag |
|---|---|---|---|
| Okta | `--okta` | 25 | `--okta-collectors` |
| Tenable | `--tenable` | 5 | `--tenable-collectors` |
| Elastic Security | `--elastic` | 10 | `--elastic-collectors` |
| GitHub | `--github` | 10 | `--github-collectors` |

### Selecting collectors

Every collector has an opt-in boolean flag named after its key
(`--okta-users`, `--tenable-assets`, `--elastic-alerts`,
`--github-audit-log`, …). Individual flags and the `--<provider>-collectors`
key list are **additive**, exactly like the inventory asset-type flags. Passing
neither runs every collector for that provider. Unknown keys are rejected with
the valid list.

```bash
# Every Okta collector, last 30 days (the default window)
grabber --okta

# Two collectors via individual flags
grabber --okta --okta-users --okta-groups

# The same two via the key list
grabber --okta --okta-collectors okta-users,okta-groups

# Mixed — results in okta-users, okta-groups, okta-apps
grabber --okta --okta-collectors okta-users,okta-groups --okta-apps
```

### Credentials

Precedence is **CLI flag → environment variable → `config.toml`**. Accounts come
from the merged config (`config.toml` plus `okta-config.toml`,
`tenable-config.toml`, `elastic-config.toml`, `github-config.toml`); with no
config file at all, the CLI flags or env vars alone are enough to run.
`--<provider>-account <name>` narrows a multi-account config to one entry.
Accounts missing credentials are skipped with a `✗` line; the run continues
against the rest.

| Provider | Flags | Environment variables |
|---|---|---|
| Okta | `--okta-domain`, `--okta-api-token` | `OKTA_DOMAIN`, `OKTA_API_TOKEN` |
| Tenable | `--tenable-url`, `--tenable-access-key`, `--tenable-secret-key` | `TENABLE_ACCESS_KEY`, `TENABLE_SECRET_KEY` |
| Elastic | `--elastic-kibana-url`, `--elastic-es-url`, `--elastic-api-key` | `ELASTIC_KIBANA_URL`, `ELASTIC_ES_URL`, `ELASTIC_API_KEY` |
| GitHub | `--github-org`, `--github-token`, `--github-base-url` | `GITHUB_ORG`, `GITHUB_TOKEN`, `GITHUB_BASE_URL` |

`--tenable-url` defaults to `https://cloud.tenable.com`; `--github-base-url`
defaults to `https://api.github.com` (set it for GitHub Enterprise Server).

### Time window

Provider modes accept `--lookback` or `--start-date`/`--end-date`. **With no
window flag they default to the last 30 days** and print a notice, because
time-windowed collectors (Okta System Log, GitHub Audit Log, Elastic Alerts)
would otherwise export their full retained history.

```bash
grabber --okta --okta-system-log --lookback 90d
grabber --github --github-audit-log --start-date 2026-07-01 --end-date 2026-07-31
```

### Tenable scan selection

`--tenable-scan-ids` (numeric) and `--tenable-was-scan-ids` (string config IDs)
replace the TUI's scan-selection screen. Both default to empty, meaning "all
scans" — which is correct for `tenable-vulns`, whose export API is keyed on scan
UUIDs and ignores numeric IDs entirely.

```bash
grabber --tenable --tenable-was --tenable-was-scan-ids 8d1f...,9a2c...
```

### Okta STIG

The read-only DISA STIG evaluation is a normal collector:
`--okta-stig-compliance` writes the full check-by-check CSV. STIG
**remediation** — which writes changes to the live tenant — stays in the TUI
behind its interactive confirmation screen and has no CLI flag.

### Output, packaging, and audit artifacts

Files land in `{output}/{account name}/{YYYY}/{MM-MMM}/`, matching the TUI.
`--output` wins; otherwise the account's `output_dir` from config is used as-is.
`--zip`, `--sign`, `--signing-key`, and `--write-run-manifest` all work.
`--write-chain-of-custody` does not — the custody record is keyed on an AWS
caller identity — and warns rather than failing.

```bash
# Full Okta evidence run, zipped and signed
grabber --okta --lookback 90d -o ./evidence-output --zip --sign --write-run-manifest
```
````

- [ ] **Step 3: Add the provider flag tables to `README.md`**

After the inventory flag table (around line 308), add:

````markdown
### Non-AWS provider CLI modes

Okta, Tenable, Elastic Security, and GitHub run headlessly via their own mode
flags. One provider per invocation. Full detail in the
[CLI Reference](docs/cli-reference.md#provider-modes).

| Flag | Default | Description |
|---|---|---|
| `--okta` / `--tenable` / `--elastic` / `--github` | off | Run that provider's collectors non-interactively. Mutually exclusive. |
| `--<provider>-account <NAME>` | all | Narrow a multi-account config to the `[[account]]` with this `name`. |
| `--<provider>-collectors <KEY>[,<KEY>…]` | all | Collector keys to run; additive with the individual flags below. |
| `--okta-users` / `--okta-groups` / `--tenable-assets` / `--elastic-alerts` / `--github-repos` … | off | One opt-in flag per collector, named after its key (50 total across the four providers). |
| `--tenable-scan-ids` / `--tenable-was-scan-ids` | all scans | Scope Tenable collection to specific scans (replaces the TUI scan picker). |

Credentials come from `--<provider>-*` flags, then environment variables, then
the sibling `*-config.toml` files. With no window flag, provider modes default
to the last 30 days.

```bash
grabber --okta --okta-users --okta-groups --lookback 90d
grabber --github --github-audit-log --start-date 2026-07-01 --end-date 2026-07-31
grabber --elastic --lookback 30d -o ./evidence-output --zip
```
````

- [ ] **Step 4: Verify the docs match the binary**

```bash
cargo run -- --help | grep -E '^\s+--(okta|tenable|elastic|github)' | wc -l
```

Expected: at least 66 lines (50 collector flags + 4 mode flags + 4 account flags + 4 key-list flags + 10 credential flags + 2 Tenable scan-ID flags). Spot-check that every flag named in the two doc sections appears in `--help` output, and that no flag name in the docs was renamed during implementation.

- [ ] **Step 5: Commit**

```bash
git add docs/cli-reference.md README.md
git commit -m "docs(cli): document Okta, Tenable, Elastic, and GitHub CLI modes"
```

---

## Self-Review Notes

- **Coverage:** all 50 collector keys from the four TUI menu files appear in a key table and a boolean flag in Task 1. Okta 25 (`src/tui/menus/okta.rs`), Tenable 5, Elastic 10, GitHub 10. Jira is out of scope by decision.
- **STIG:** covered by the `okta-stig-compliance` collector flag; remediation deliberately excluded and called out in the docs.
- **Type consistency:** `resolve_collectors()` returns `Result<Vec<String>>` in all four impls and is consumed as `?` in all four runners. `resolve_window` returns `CollectParams` (not a tuple) and every runner derives its `dates` tuple from `params.start_time` / `params.end_time`. `provider_output_dir(cli, name, Option<&str>)` and `finish_provider_run(cli, timestamp, account_id, params, outcomes, output_dir)` have one signature each, used identically in Tasks 3–6.
- **Compile-order safety:** `mod.rs` (Task 2) ships with zero child-module declarations; Tasks 3–6 each add one `mod` line in the same step that creates the file it names.
- **Known non-goal:** multi-account provider runs produce one run manifest per account rather than a merged one. That matches the TUI's per-account behavior and is not a regression. Note the original wording ("one output tree per account") was **false**: without `--output`, every account of a provider uses the config's `output_dir` as-is, and the shipped `*-config.example.toml` files hardcode one directory per provider — so two accounts of the same provider share a directory unless `--output` is passed. Evidence files are account-prefixed and survive; `RUN-MANIFEST-*.json` and `fedramp-coverage-actual.csv` have fixed names and the last account overwrites the rest. The run now prints a `WARN:` when it detects this. The layout itself was deliberately left alone (changing it would diverge from the AWS TUI).
