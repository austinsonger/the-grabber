use std::fs;
use std::path::PathBuf;

use serde::Deserialize;

use crate::providers::CloudProvider;

/// User-level configuration loaded from a TOML file.
///
/// Supports multi-account setups (e.g. AWS SSO with multiple accounts),
/// global defaults, and per-account collector overrides.
/// If the file is missing or invalid, the application falls back to
/// built-in defaults.
#[derive(Debug, Default, Deserialize)]
pub struct AppConfig {
    /// Global defaults applied when not overridden by an account.
    #[serde(default)]
    pub defaults: Defaults,

    /// Named AWS accounts. When present the TUI shows an account picker
    /// instead of the raw profile / region screens.
    #[serde(default)]
    pub account: Vec<Account>,
}

/// Global default values for the TUI wizard.
#[derive(Debug, Default, Deserialize)]
pub struct Defaults {
    /// Prefer profiles whose name contains this substring when
    /// pre-selecting a default profile (legacy flow).
    pub profile_contains: Option<String>,

    /// Default region to highlight (e.g. "us-east-1").
    pub region: Option<String>,

    /// Default output directory (e.g. "./evidence-output").
    pub output_dir: Option<String>,

    /// Compute start date as today minus N days (e.g. 90).
    pub start_date_offset_days: Option<u32>,

    /// Whether to include raw JSON in output by default.
    pub include_raw: Option<bool>,

    /// When true, bundle all output files into a dated .zip after collection.
    pub zip: Option<bool>,

    /// When true, HMAC-SHA256-sign all output files after collection.
    /// A per-run signing key is generated and written to SIGNING-<ts>.key.
    pub sign: Option<bool>,

    /// Global collector enable/disable rules.
    #[serde(default)]
    pub collectors: CollectorConfig,
}

/// Controls which collectors are enabled or disabled.
///
/// Resolution order:
/// 1. If `enable` is set → ONLY those collectors are enabled.
/// 2. Otherwise all collectors are enabled, then:
///    a. Remove any listed in `disable`.
///    b. Add any listed in `enable_extra` (useful for per-account
///       overrides that add org-level collectors).
#[derive(Debug, Default, Clone, Deserialize)]
pub struct CollectorConfig {
    /// Exclusive list: if set, ONLY these collector keys are enabled.
    pub enable: Option<Vec<String>>,

    /// Subtractive list: these collector keys are disabled.
    pub disable: Option<Vec<String>>,

    /// Additive list: these collector keys are added on top of defaults.
    pub enable_extra: Option<Vec<String>>,
}

/// A named account for any supported provider.
///
/// Existing TOML configs with no `provider` field default to `aws` — no migration needed.
#[derive(Debug, Clone, Deserialize)]
pub struct Account {
    /// Human-readable display name (e.g. "Corporate Production").
    pub name: String,

    /// Which provider this account belongs to.
    /// Defaults to `aws` when not specified, preserving backwards compatibility.
    #[serde(default)]
    pub provider: CloudProvider,

    // ------------------------------------------------------------------
    // AWS fields
    // ------------------------------------------------------------------
    /// AWS account ID, shown in the TUI for identification.
    pub account_id: Option<String>,

    /// Short description shown below the account name.
    pub description: Option<String>,

    /// AWS CLI profile name or SSO role name (must match ~/.aws/config).
    pub profile: Option<String>,

    /// AWS region override (e.g. "us-east-1").
    pub region: Option<String>,

    /// Override the default output directory for this account.
    pub output_dir: Option<String>,

    // ------------------------------------------------------------------
    // Azure fields
    // ------------------------------------------------------------------
    /// Azure Active Directory tenant ID (UUID).
    pub tenant_id: Option<String>,

    /// Azure subscription ID (UUID).
    pub subscription_id: Option<String>,

    // ------------------------------------------------------------------
    // GCP fields
    // ------------------------------------------------------------------
    /// GCP project ID string (e.g. "my-project-123").
    pub project_id: Option<String>,

    // ------------------------------------------------------------------
    // Tenable fields (Tenable.io and Tenable.sc share the same key format)
    // ------------------------------------------------------------------
    /// Tenable API access key.
    /// Can also be supplied via `TENABLE_ACCESS_KEY` env var (env wins over TOML).
    pub tenable_access_key: Option<String>,

    /// Tenable API secret key.
    /// Can also be supplied via `TENABLE_SECRET_KEY` env var (env wins over TOML).
    pub tenable_secret_key: Option<String>,

    /// Tenable base URL.
    /// Omit for Tenable.io (defaults to `https://cloud.tenable.com`).
    /// Set to your on-premises Tenable.sc URL for self-hosted deployments.
    pub tenable_url: Option<String>,

    // ------------------------------------------------------------------
    // Okta fields
    // ------------------------------------------------------------------
    /// Okta tenant base URL (e.g. `https://acme.okta.com` or `https://acme.oktapreview.com`).
    pub okta_domain: Option<String>,

    /// Okta API token (SSWS).
    /// Can also be supplied via `OKTA_API_TOKEN` env var (env wins over TOML).
    pub okta_api_token: Option<String>,

    // ------------------------------------------------------------------
    // Jira fields
    // ------------------------------------------------------------------
    /// Jira Cloud tenant base URL (e.g. `https://acme.atlassian.net`).
    pub jira_domain: Option<String>,

    /// Jira account email (used as the username half of Basic auth).
    /// Can also be supplied via `JIRA_EMAIL` env var (env wins over TOML).
    pub jira_email: Option<String>,

    /// Jira API token.
    /// Can also be supplied via `JIRA_API_TOKEN` env var (env wins over TOML).
    pub jira_api_token: Option<String>,

    // ------------------------------------------------------------------
    // Collector filtering (all providers)
    // ------------------------------------------------------------------
    /// Per-account collector overrides (enable_extra / disable).
    #[serde(default)]
    pub collectors: CollectorConfig,
}

impl Account {
    /// Resolve Tenable access key: env var takes precedence over TOML.
    pub fn tenable_access_key_resolved(&self) -> Option<String> {
        std::env::var("TENABLE_ACCESS_KEY")
            .ok()
            .or_else(|| self.tenable_access_key.clone())
    }

    /// Resolve Tenable secret key: env var takes precedence over TOML.
    pub fn tenable_secret_key_resolved(&self) -> Option<String> {
        std::env::var("TENABLE_SECRET_KEY")
            .ok()
            .or_else(|| self.tenable_secret_key.clone())
    }

    /// Resolve Tenable base URL, defaulting to Tenable.io cloud endpoint.
    pub fn tenable_url_resolved(&self) -> String {
        self.tenable_url
            .clone()
            .unwrap_or_else(|| "https://cloud.tenable.com".to_string())
    }

    /// Resolve Okta API token: env var takes precedence over TOML.
    pub fn okta_api_token_resolved(&self) -> Option<String> {
        std::env::var("OKTA_API_TOKEN")
            .ok()
            .or_else(|| self.okta_api_token.clone())
    }

    /// Resolve Okta domain, trimming any trailing slash. Returns None if unset.
    pub fn okta_domain_resolved(&self) -> Option<String> {
        std::env::var("OKTA_DOMAIN")
            .ok()
            .or_else(|| self.okta_domain.clone())
            .map(|s| s.trim().trim_end_matches('/').to_string())
            .filter(|s| !s.is_empty())
    }

    /// Resolve Jira API token: env var takes precedence over TOML.
    pub fn jira_api_token_resolved(&self) -> Option<String> {
        std::env::var("JIRA_API_TOKEN")
            .ok()
            .or_else(|| self.jira_api_token.clone())
    }

    /// Resolve Jira email: env var takes precedence over TOML.
    pub fn jira_email_resolved(&self) -> Option<String> {
        std::env::var("JIRA_EMAIL")
            .ok()
            .or_else(|| self.jira_email.clone())
    }

    /// Resolve Jira domain, trimming any trailing slash. Returns None if unset.
    pub fn jira_domain_resolved(&self) -> Option<String> {
        std::env::var("JIRA_DOMAIN")
            .ok()
            .or_else(|| self.jira_domain.clone())
            .map(|s| s.trim().trim_end_matches('/').to_string())
            .filter(|s| !s.is_empty())
    }
}

/// Best-effort load of config, checking in order:
///   1. `./config.toml`  (project-local)
///   2. `~/.config/evidence/config.toml`  (user-global)
///
/// After loading the primary config, `./tenable-config.toml`, `./okta-config.toml`,
/// and `./jira-config.toml` are merged in (accounts only) if those files exist.
pub fn load_config() -> Option<AppConfig> {
    let mut cfg: AppConfig = {
        let local = PathBuf::from("config.toml");
        if local.exists() {
            if let Ok(contents) = fs::read_to_string(&local) {
                if let Ok(c) = toml::from_str(&contents) {
                    c
                } else {
                    return None;
                }
            } else {
                return None;
            }
        } else {
            let path = global_config_path()?;
            let contents = fs::read_to_string(path).ok()?;
            toml::from_str(&contents).ok()?
        }
    };

    // Merge tenable-config.toml accounts if present
    let tenable_path = PathBuf::from("tenable-config.toml");
    if tenable_path.exists() {
        if let Ok(contents) = fs::read_to_string(&tenable_path) {
            if let Ok(tenable_cfg) = toml::from_str::<AppConfig>(&contents) {
                cfg.account.extend(tenable_cfg.account);
            }
        }
    }

    // Merge okta-config.toml accounts if present
    let okta_path = PathBuf::from("okta-config.toml");
    if okta_path.exists() {
        if let Ok(contents) = fs::read_to_string(&okta_path) {
            if let Ok(okta_cfg) = toml::from_str::<AppConfig>(&contents) {
                cfg.account.extend(okta_cfg.account);
            }
        }
    }

    // Merge jira-config.toml accounts if present
    let jira_path = PathBuf::from("jira-config.toml");
    if jira_path.exists() {
        if let Ok(contents) = fs::read_to_string(&jira_path) {
            if let Ok(jira_cfg) = toml::from_str::<AppConfig>(&contents) {
                cfg.account.extend(jira_cfg.account);
            }
        }
    }

    Some(cfg)
}

fn global_config_path() -> Option<PathBuf> {
    let base = dirs_next::home_dir()?;
    Some(base.join(".config").join("evidence").join("config.toml"))
}
