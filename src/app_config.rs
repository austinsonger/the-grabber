use std::fs;
use std::path::PathBuf;

use serde::Deserialize;

/// User-level configuration loaded from a TOML file.
///
/// This is intentionally minimal – it only influences TUI defaults
/// and is entirely optional. If the file is missing or invalid,
/// the application falls back to built-in defaults.
#[derive(Debug, Default, Deserialize)]
pub struct AppConfig {
    /// Prefer profiles whose name contains this substring when pre-selecting
    /// a default profile in the TUI (e.g. "Prod").
    pub default_profile_contains: Option<String>,

    /// Default region to highlight in the TUI region list (e.g. "us-east-1").
    pub default_region: Option<String>,

    /// Default output directory shown in the TUI (e.g. "./evidence").
    pub default_output_dir: Option<String>,
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
