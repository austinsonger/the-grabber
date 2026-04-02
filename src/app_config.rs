use std::fs;
use std::path::PathBuf;

use serde::Deserialize;

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

/// A named AWS account that the tool can collect evidence from.
///
/// Each account maps to an AWS CLI profile (typically an SSO role)
/// and carries its own region, output directory, and collector
/// override settings.
#[derive(Debug, Clone, Deserialize)]
pub struct Account {
    /// Human-readable display name (e.g. "Corporate Production").
    pub name: String,

    /// AWS account ID, shown in the TUI for identification.
    pub account_id: Option<String>,

    /// Short description shown below the account name.
    pub description: Option<String>,

    /// AWS CLI profile name or SSO role name (must match ~/.aws/config).
    pub profile: String,

    /// Override the default region for this account.
    pub region: Option<String>,

    /// Override the default output directory for this account.
    pub output_dir: Option<String>,

    /// Per-account collector overrides (enable_extra / disable).
    #[serde(default)]
    pub collectors: CollectorConfig,
}

/// Best-effort load of `~/.config/evidence/config.toml`.
/// Returns `None` on any error (no file, parse error, etc.).
pub fn load_config() -> Option<AppConfig> {
    let path = config_path()?;
    let contents = fs::read_to_string(path).ok()?;
    toml::from_str(&contents).ok()
}

fn config_path() -> Option<PathBuf> {
    let base = dirs_next::home_dir()?;
    Some(base.join(".config").join("evidence").join("config.toml"))
}
