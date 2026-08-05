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
//!
//! Nothing in `src/runner/` calls `resolve_collectors()` or reads the
//! `*_COLLECTOR_KEYS` tables yet — that dispatch wiring lands in a later task
//! in this plan. Until then the module-level allow below keeps clippy clean.
#![allow(dead_code)]

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
            (
                self.okta_shared_account_broker,
                "okta-shared-account-broker",
            ),
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
