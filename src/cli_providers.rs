//! Headless-CLI flag groups for the non-AWS providers.
//!
//! Each provider gets a `clap::Args` struct that is `#[command(flatten)]`-ed
//! into [`crate::cli::Cli`]: a mode flag (`--okta`), credential overrides, a
//! comma-separated `--<provider>-collectors` key list, and one opt-in boolean
//! per collector. The individual flags and the key list are additive; an empty
//! selection means "every collector for this provider". Providers covered:
//! Okta, Tenable, Elastic, GitHub, Jira, Jamf, and JumpCloud.
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
#[derive(Args, Debug, Default)]
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
#[derive(Args, Debug, Default)]
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
#[derive(Args, Debug, Default)]
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
#[derive(Args, Debug, Default)]
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

/// Every Jira collector key, in TUI menu order (`src/tui/menus/jira.rs`).
pub const JIRA_COLLECTOR_KEYS: &[&str] = &[
    "jira-projects",
    "jira-issues",
    "jira-offboarding-sla",
    "jira-ir-external",
    "jira-sanctions-isso",
    "jira-transfer-notify",
    "jira-remote-access-approvals",
    "jira-external-system-approvals",
    "jira-remote-maint",
    "jira-special-protection",
    "jira-change-retention",
    "jira-cp-update",
    "jira-cp-test-poam",
    "jira-baseline-exceptions",
    "jira-allowlist-review",
    "jira-patch-test",
    "jira-sw-license",
    "jira-ir-cp",
    "jira-ir-lessons",
    "jira-ir-severity",
    "jira-dr-test",
    "jira-malware-fp",
    "jira-public-content",
    "jira-logging-coordination",
    "jira-audit-posture",
    "jira-isa-annual",
    "jira-fw-exception",
    "jira-data-reassignment",
];

/// Jira headless-CLI flags.
#[derive(Args, Debug, Default)]
#[command(next_help_heading = "Jira")]
pub struct JiraFlags {
    /// Run the Jira evidence workflow non-interactively.
    /// Reads accounts from jira-config.toml / config.toml, or falls back to
    /// --jira-domain / --jira-email / --jira-api-token (or the JIRA_* env vars).
    #[arg(long = "jira", default_value_t = false)]
    pub jira_enabled: bool,

    /// Limit the run to the [[account]] with this `name` (case-insensitive).
    #[arg(long)]
    pub jira_account: Option<String>,

    /// Jira tenant base URL, e.g. https://acme.atlassian.net.
    /// Overrides config.toml and JIRA_DOMAIN.
    #[arg(long)]
    pub jira_domain: Option<String>,

    /// Jira account email (Basic-auth username). Overrides config.toml and
    /// JIRA_EMAIL.
    #[arg(long)]
    pub jira_email: Option<String>,

    /// Jira API token. Overrides config.toml and JIRA_API_TOKEN.
    #[arg(long)]
    pub jira_api_token: Option<String>,

    /// Collector keys to run (comma-separated). Additive with the individual
    /// --jira-* collector flags. Omit both to run all 28 Jira collectors.
    #[arg(long, value_delimiter = ',')]
    pub jira_collectors: Option<Vec<String>>,

    /// Jira: collect Projects.
    #[arg(long, default_value_t = false)]
    pub jira_projects: bool,

    /// Jira: collect Issues.
    #[arg(long, default_value_t = false)]
    pub jira_issues: bool,

    /// Jira: collect Offboarding SLA.
    #[arg(long, default_value_t = false)]
    pub jira_offboarding_sla: bool,

    /// Jira: collect IR: External Reporting SLA.
    #[arg(long, default_value_t = false)]
    pub jira_ir_external: bool,

    /// Jira: collect Sanctions ISSO Notify.
    #[arg(long, default_value_t = false)]
    pub jira_sanctions_isso: bool,

    /// Jira: collect Transfer Notifications.
    #[arg(long, default_value_t = false)]
    pub jira_transfer_notify: bool,

    /// Jira: collect Remote Access Approvals.
    #[arg(long, default_value_t = false)]
    pub jira_remote_access_approvals: bool,

    /// Jira: collect External System Approvals.
    #[arg(long, default_value_t = false)]
    pub jira_external_system_approvals: bool,

    /// Jira: collect Remote Maintenance.
    #[arg(long, default_value_t = false)]
    pub jira_remote_maint: bool,

    /// Jira: collect Special Protection.
    #[arg(long, default_value_t = false)]
    pub jira_special_protection: bool,

    /// Jira: collect Change Retention.
    #[arg(long, default_value_t = false)]
    pub jira_change_retention: bool,

    /// Jira: collect CP Update Trigger.
    #[arg(long, default_value_t = false)]
    pub jira_cp_update: bool,

    /// Jira: collect CP Test POAM.
    #[arg(long, default_value_t = false)]
    pub jira_cp_test_poam: bool,

    /// Jira: collect Baseline Exceptions.
    #[arg(long, default_value_t = false)]
    pub jira_baseline_exceptions: bool,

    /// Jira: collect Allowlist Review.
    #[arg(long, default_value_t = false)]
    pub jira_allowlist_review: bool,

    /// Jira: collect Patch Test Records.
    #[arg(long, default_value_t = false)]
    pub jira_patch_test: bool,

    /// Jira: collect SW License Review.
    #[arg(long, default_value_t = false)]
    pub jira_sw_license: bool,

    /// Jira: collect IR: CP Coordination.
    #[arg(long, default_value_t = false)]
    pub jira_ir_cp: bool,

    /// Jira: collect IR: Lessons Learned.
    #[arg(long, default_value_t = false)]
    pub jira_ir_lessons: bool,

    /// Jira: collect IR: Severity vs Rigor.
    #[arg(long, default_value_t = false)]
    pub jira_ir_severity: bool,

    /// Jira: collect DR Test Results.
    #[arg(long, default_value_t = false)]
    pub jira_dr_test: bool,

    /// Jira: collect Malware False Positive.
    #[arg(long, default_value_t = false)]
    pub jira_malware_fp: bool,

    /// Jira: collect Public Content Review.
    #[arg(long, default_value_t = false)]
    pub jira_public_content: bool,

    /// Jira: collect Logging Coordination.
    #[arg(long, default_value_t = false)]
    pub jira_logging_coordination: bool,

    /// Jira: collect Audit Posture Change.
    #[arg(long, default_value_t = false)]
    pub jira_audit_posture: bool,

    /// Jira: collect ISA Annual Review.
    #[arg(long, default_value_t = false)]
    pub jira_isa_annual: bool,

    /// Jira: collect Firewall Exception.
    #[arg(long, default_value_t = false)]
    pub jira_fw_exception: bool,

    /// Jira: collect Data Reassignment.
    #[arg(long, default_value_t = false)]
    pub jira_data_reassignment: bool,

    /// Comma-separated Jira project keys to scope the issues collector to
    /// (e.g. "SEC,CMP"). Omit to cover every project.
    #[arg(long)]
    pub jira_project_keys: Option<String>,
}

impl JiraFlags {
    /// Collector keys for this run. Empty selection = every Jira collector.
    pub fn resolve_collectors(&self) -> Result<Vec<String>> {
        let toggles = [
            (self.jira_projects, "jira-projects"),
            (self.jira_issues, "jira-issues"),
            (self.jira_offboarding_sla, "jira-offboarding-sla"),
            (self.jira_ir_external, "jira-ir-external"),
            (self.jira_sanctions_isso, "jira-sanctions-isso"),
            (self.jira_transfer_notify, "jira-transfer-notify"),
            (
                self.jira_remote_access_approvals,
                "jira-remote-access-approvals",
            ),
            (
                self.jira_external_system_approvals,
                "jira-external-system-approvals",
            ),
            (self.jira_remote_maint, "jira-remote-maint"),
            (self.jira_special_protection, "jira-special-protection"),
            (self.jira_change_retention, "jira-change-retention"),
            (self.jira_cp_update, "jira-cp-update"),
            (self.jira_cp_test_poam, "jira-cp-test-poam"),
            (self.jira_baseline_exceptions, "jira-baseline-exceptions"),
            (self.jira_allowlist_review, "jira-allowlist-review"),
            (self.jira_patch_test, "jira-patch-test"),
            (self.jira_sw_license, "jira-sw-license"),
            (self.jira_ir_cp, "jira-ir-cp"),
            (self.jira_ir_lessons, "jira-ir-lessons"),
            (self.jira_ir_severity, "jira-ir-severity"),
            (self.jira_dr_test, "jira-dr-test"),
            (self.jira_malware_fp, "jira-malware-fp"),
            (self.jira_public_content, "jira-public-content"),
            (self.jira_logging_coordination, "jira-logging-coordination"),
            (self.jira_audit_posture, "jira-audit-posture"),
            (self.jira_isa_annual, "jira-isa-annual"),
            (self.jira_fw_exception, "jira-fw-exception"),
            (self.jira_data_reassignment, "jira-data-reassignment"),
        ];
        resolve_keys(
            "jira",
            self.jira_collectors.as_ref(),
            &toggles,
            JIRA_COLLECTOR_KEYS,
        )
    }

    /// Jira project keys for this run: the comma-separated `--jira-project-keys`
    /// list, trimmed, with empty entries dropped. Empty vec = all projects.
    pub fn resolve_project_keys(&self) -> Vec<String> {
        self.jira_project_keys
            .as_deref()
            .map(|s| {
                s.split(',')
                    .map(|k| k.trim().to_string())
                    .filter(|k| !k.is_empty())
                    .collect()
            })
            .unwrap_or_default()
    }
}

/// Every Jamf collector key, in TUI menu order (`src/tui/menus/jamf.rs`).
pub const JAMF_COLLECTOR_KEYS: &[&str] = &[
    "jamf-computers",
    "jamf-mobile-devices",
    "jamf-computer-groups",
    "jamf-mobile-device-groups",
    "jamf-computer-config-profiles",
    "jamf-mobile-config-profiles",
    "jamf-policies",
    "jamf-patch-titles",
    "jamf-patch-compliance",
];

/// Jamf headless-CLI flags.
#[derive(Args, Debug, Default)]
#[command(next_help_heading = "Jamf")]
pub struct JamfFlags {
    /// Run the Jamf evidence workflow non-interactively.
    /// Reads accounts from jamf-config.toml / config.toml, or falls back to
    /// --jamf-base-url / --jamf-client-id / --jamf-client-secret (or the
    /// JAMF_* env vars).
    #[arg(long = "jamf", default_value_t = false)]
    pub jamf_enabled: bool,

    /// Limit the run to the [[account]] with this `name` (case-insensitive).
    #[arg(long)]
    pub jamf_account: Option<String>,

    /// Jamf Pro server base URL, e.g. https://acme.jamfcloud.com.
    /// Overrides config.toml and JAMF_BASE_URL.
    #[arg(long)]
    pub jamf_base_url: Option<String>,

    /// Jamf Pro API OAuth2 client ID. Overrides config.toml and JAMF_CLIENT_ID.
    #[arg(long)]
    pub jamf_client_id: Option<String>,

    /// Jamf Pro API OAuth2 client secret.
    /// Overrides config.toml and JAMF_CLIENT_SECRET.
    #[arg(long)]
    pub jamf_client_secret: Option<String>,

    /// Collector keys to run (comma-separated). Additive with the individual
    /// --jamf-* collector flags. Omit both to run all 9 Jamf collectors.
    #[arg(long, value_delimiter = ',')]
    pub jamf_collectors: Option<Vec<String>>,

    /// Jamf: collect Computers.
    #[arg(long, default_value_t = false)]
    pub jamf_computers: bool,

    /// Jamf: collect Mobile Devices.
    #[arg(long, default_value_t = false)]
    pub jamf_mobile_devices: bool,

    /// Jamf: collect Computer Groups.
    #[arg(long, default_value_t = false)]
    pub jamf_computer_groups: bool,

    /// Jamf: collect Mobile Device Groups.
    #[arg(long, default_value_t = false)]
    pub jamf_mobile_device_groups: bool,

    /// Jamf: collect Computer Config Profiles.
    #[arg(long, default_value_t = false)]
    pub jamf_computer_config_profiles: bool,

    /// Jamf: collect Mobile Config Profiles.
    #[arg(long, default_value_t = false)]
    pub jamf_mobile_config_profiles: bool,

    /// Jamf: collect Policies.
    #[arg(long, default_value_t = false)]
    pub jamf_policies: bool,

    /// Jamf: collect Patch Titles.
    #[arg(long, default_value_t = false)]
    pub jamf_patch_titles: bool,

    /// Jamf: collect Patch Compliance.
    #[arg(long, default_value_t = false)]
    pub jamf_patch_compliance: bool,
}

impl JamfFlags {
    /// Collector keys for this run. Empty selection = every Jamf collector.
    pub fn resolve_collectors(&self) -> Result<Vec<String>> {
        let toggles = [
            (self.jamf_computers, "jamf-computers"),
            (self.jamf_mobile_devices, "jamf-mobile-devices"),
            (self.jamf_computer_groups, "jamf-computer-groups"),
            (self.jamf_mobile_device_groups, "jamf-mobile-device-groups"),
            (
                self.jamf_computer_config_profiles,
                "jamf-computer-config-profiles",
            ),
            (
                self.jamf_mobile_config_profiles,
                "jamf-mobile-config-profiles",
            ),
            (self.jamf_policies, "jamf-policies"),
            (self.jamf_patch_titles, "jamf-patch-titles"),
            (self.jamf_patch_compliance, "jamf-patch-compliance"),
        ];
        resolve_keys(
            "jamf",
            self.jamf_collectors.as_ref(),
            &toggles,
            JAMF_COLLECTOR_KEYS,
        )
    }
}

/// Every JumpCloud collector key, in TUI menu order
/// (`src/tui/menus/jumpcloud.rs`).
pub const JUMPCLOUD_COLLECTOR_KEYS: &[&str] = &[
    "jumpcloud-users",
    "jumpcloud-user-groups",
    "jumpcloud-user-group-members",
    "jumpcloud-mfa-factors",
    "jumpcloud-admin-roles",
    "jumpcloud-disabled-users",
    "jumpcloud-applications",
    "jumpcloud-policies",
    "jumpcloud-password-policy",
    "jumpcloud-session-policy",
    "jumpcloud-directory-insights",
    "jumpcloud-directory-alerts",
    "jumpcloud-systems",
    "jumpcloud-system-groups",
    "jumpcloud-system-group-members",
    "jumpcloud-system-user-associations",
];

/// JumpCloud headless-CLI flags.
#[derive(Args, Debug, Default)]
#[command(next_help_heading = "JumpCloud")]
pub struct JumpcloudFlags {
    /// Run the JumpCloud evidence workflow non-interactively.
    /// Reads accounts from jumpcloud-config.toml / config.toml, or falls back
    /// to --jumpcloud-api-key (or JUMPCLOUD_API_KEY).
    #[arg(long = "jumpcloud", default_value_t = false)]
    pub jumpcloud_enabled: bool,

    /// Limit the run to the [[account]] with this `name` (case-insensitive).
    #[arg(long)]
    pub jumpcloud_account: Option<String>,

    /// JumpCloud API base URL. Defaults to https://console.jumpcloud.com.
    /// Overrides config.toml and JUMPCLOUD_BASE_URL.
    #[arg(long)]
    pub jumpcloud_base_url: Option<String>,

    /// JumpCloud API key. Overrides config.toml and JUMPCLOUD_API_KEY.
    #[arg(long)]
    pub jumpcloud_api_key: Option<String>,

    /// JumpCloud org id (required for MTP/MSP orgs, sent as x-org-id).
    /// Overrides config.toml and JUMPCLOUD_ORG_ID.
    #[arg(long)]
    pub jumpcloud_org_id: Option<String>,

    /// Collector keys to run (comma-separated). Additive with the individual
    /// --jumpcloud-* collector flags. Omit both to run all 16 JumpCloud
    /// collectors.
    #[arg(long, value_delimiter = ',')]
    pub jumpcloud_collectors: Option<Vec<String>>,

    /// JumpCloud: collect Users.
    #[arg(long, default_value_t = false)]
    pub jumpcloud_users: bool,

    /// JumpCloud: collect User Groups.
    #[arg(long, default_value_t = false)]
    pub jumpcloud_user_groups: bool,

    /// JumpCloud: collect User Group Members.
    #[arg(long, default_value_t = false)]
    pub jumpcloud_user_group_members: bool,

    /// JumpCloud: collect MFA Factors.
    #[arg(long, default_value_t = false)]
    pub jumpcloud_mfa_factors: bool,

    /// JumpCloud: collect Admin Roles.
    #[arg(long, default_value_t = false)]
    pub jumpcloud_admin_roles: bool,

    /// JumpCloud: collect Disabled Users.
    #[arg(long, default_value_t = false)]
    pub jumpcloud_disabled_users: bool,

    /// JumpCloud: collect Applications.
    #[arg(long, default_value_t = false)]
    pub jumpcloud_applications: bool,

    /// JumpCloud: collect Policies.
    #[arg(long, default_value_t = false)]
    pub jumpcloud_policies: bool,

    /// JumpCloud: collect Password Policy.
    #[arg(long, default_value_t = false)]
    pub jumpcloud_password_policy: bool,

    /// JumpCloud: collect Session Policy.
    #[arg(long, default_value_t = false)]
    pub jumpcloud_session_policy: bool,

    /// JumpCloud: collect Directory Insights events.
    #[arg(long, default_value_t = false)]
    pub jumpcloud_directory_insights: bool,

    /// JumpCloud: collect Directory Alerts.
    #[arg(long, default_value_t = false)]
    pub jumpcloud_directory_alerts: bool,

    /// JumpCloud: collect Systems.
    #[arg(long, default_value_t = false)]
    pub jumpcloud_systems: bool,

    /// JumpCloud: collect System Groups.
    #[arg(long, default_value_t = false)]
    pub jumpcloud_system_groups: bool,

    /// JumpCloud: collect System Group Members.
    #[arg(long, default_value_t = false)]
    pub jumpcloud_system_group_members: bool,

    /// JumpCloud: collect System-User Associations.
    #[arg(long, default_value_t = false)]
    pub jumpcloud_system_user_associations: bool,
}

impl JumpcloudFlags {
    /// Collector keys for this run. Empty selection = every JumpCloud collector.
    pub fn resolve_collectors(&self) -> Result<Vec<String>> {
        let toggles = [
            (self.jumpcloud_users, "jumpcloud-users"),
            (self.jumpcloud_user_groups, "jumpcloud-user-groups"),
            (
                self.jumpcloud_user_group_members,
                "jumpcloud-user-group-members",
            ),
            (self.jumpcloud_mfa_factors, "jumpcloud-mfa-factors"),
            (self.jumpcloud_admin_roles, "jumpcloud-admin-roles"),
            (self.jumpcloud_disabled_users, "jumpcloud-disabled-users"),
            (self.jumpcloud_applications, "jumpcloud-applications"),
            (self.jumpcloud_policies, "jumpcloud-policies"),
            (self.jumpcloud_password_policy, "jumpcloud-password-policy"),
            (self.jumpcloud_session_policy, "jumpcloud-session-policy"),
            (
                self.jumpcloud_directory_insights,
                "jumpcloud-directory-insights",
            ),
            (
                self.jumpcloud_directory_alerts,
                "jumpcloud-directory-alerts",
            ),
            (self.jumpcloud_systems, "jumpcloud-systems"),
            (self.jumpcloud_system_groups, "jumpcloud-system-groups"),
            (
                self.jumpcloud_system_group_members,
                "jumpcloud-system-group-members",
            ),
            (
                self.jumpcloud_system_user_associations,
                "jumpcloud-system-user-associations",
            ),
        ];
        resolve_keys(
            "jumpcloud",
            self.jumpcloud_collectors.as_ref(),
            &toggles,
            JUMPCLOUD_COLLECTOR_KEYS,
        )
    }
}
