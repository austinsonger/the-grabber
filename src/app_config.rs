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

/// Cloud provider tag for an account entry.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum CloudProvider {
    Aws,
    Azure,
    Gcp,
}

impl Default for CloudProvider {
    fn default() -> Self {
        CloudProvider::Aws
    }
}

fn default_provider() -> CloudProvider {
    CloudProvider::Aws
}

fn default_profile() -> String {
    String::new()
}

/// A named cloud account that the tool can collect evidence from.
///
/// Each account maps to credentials and carries its own region, output
/// directory, and collector override settings.
#[derive(Debug, Clone, Deserialize)]
pub struct Account {
    /// Human-readable display name (e.g. "Corporate Production").
    pub name: String,

    /// Cloud provider for this account entry.  Defaults to `aws`.
    #[serde(default = "default_provider")]
    pub provider: CloudProvider,

    // ── AWS ──────────────────────────────────────────────────────────────────
    /// AWS account ID, shown in the TUI for identification.
    pub account_id: Option<String>,

    /// Short description shown below the account name.
    pub description: Option<String>,

    /// AWS CLI profile name or SSO role name (must match ~/.aws/config).
    /// Non-AWS account entries can omit this field.
    #[serde(default = "default_profile")]
    pub profile: String,

    /// Override the default region for this account.
    pub region: Option<String>,

    // ── Azure ─────────────────────────────────────────────────────────────────
    /// Azure Active Directory tenant ID (UUID).
    pub tenant_id: Option<String>,

    /// Azure subscription ID (UUID) to collect from.
    pub subscription_id: Option<String>,

    // ── Shared ────────────────────────────────────────────────────────────────
    /// Override the default output directory for this account.
    pub output_dir: Option<String>,

    /// Per-account collector overrides (enable_extra / disable).
    #[serde(default)]
    pub collectors: CollectorConfig,
}

/// Best-effort load of config, checking in order:
///   1. `./config.toml`  (project-local, committed to repo)
///   2. `~/.config/evidence/config.toml`  (user-global)
/// Returns `None` on any error (no file, parse error, etc.).
pub fn load_config() -> Option<AppConfig> {
    let local = PathBuf::from("config.toml");
    if local.exists() {
        if let Ok(contents) = fs::read_to_string(&local) {
            if let Ok(cfg) = toml::from_str(&contents) {
                return Some(cfg);
            }
        }
    }
    let path = global_config_path()?;
    let contents = fs::read_to_string(path).ok()?;
    toml::from_str(&contents).ok()
}

fn global_config_path() -> Option<PathBuf> {
    let base = dirs_next::home_dir()?;
    Some(base.join(".config").join("evidence").join("config.toml"))
}

#[cfg(test)]
mod tests {
    use super::{AppConfig, CloudProvider};

    #[test]
    fn deserializes_azure_account_without_aws_profile() {
        let config: AppConfig = toml::from_str(
            r#"
                [[account]]
                name = "Azure Prod"
                provider = "azure"
                tenant_id = "tenant-id"
                subscription_id = "subscription-id"
            "#,
        )
        .expect("config should deserialize");

        let account = &config.account[0];
        assert_eq!(account.provider, CloudProvider::Azure);
        assert!(account.profile.is_empty());
    }

    #[test]
    fn defaults_provider_to_aws() {
        let config: AppConfig = toml::from_str(
            r#"
                [[account]]
                name = "AWS Prod"
                profile = "prod"
            "#,
        )
        .expect("config should deserialize");

        assert_eq!(config.account[0].provider, CloudProvider::Aws);
        assert_eq!(config.account[0].profile, "prod");
    }
}
