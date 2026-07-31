//! Detect AWS CLI profiles from `~/.aws/config` and `~/.aws/credentials`.
//!
//! Only profile names and non-secret settings (region, SSO metadata, role ARNs)
//! are read; secret values such as `aws_secret_access_key` are never returned.

use std::collections::BTreeMap;
use std::path::PathBuf;

use anyhow::Result;
use serde::Serialize;

/// A profile discovered in the shared AWS config/credentials files.
#[derive(Debug, Clone, Serialize)]
pub struct DetectedAwsProfile {
    pub name: String,
    pub region: Option<String>,
    /// "sso" | "access_key" | "assume_role" | "other"
    pub kind: String,
    /// Which files the profile appears in: "config" and/or "credentials".
    pub sources: Vec<String>,
}

/// Scan the shared AWS files for profiles.
///
/// Honors `AWS_CONFIG_FILE` and `AWS_SHARED_CREDENTIALS_FILE` overrides like the
/// AWS CLI does; missing files simply contribute no profiles.
pub fn detect_aws_profiles() -> Result<Vec<DetectedAwsProfile>> {
    let mut profiles: BTreeMap<String, ProfileAccumulator> = BTreeMap::new();

    if let Some(path) = config_file_path() {
        merge_file(&mut profiles, &path, FileKind::Config)?;
    }
    if let Some(path) = credentials_file_path() {
        merge_file(&mut profiles, &path, FileKind::Credentials)?;
    }

    Ok(profiles
        .into_iter()
        .map(|(name, acc)| {
            let kind = acc.kind();
            DetectedAwsProfile {
                name,
                region: acc.region,
                kind,
                sources: acc.sources,
            }
        })
        .collect())
}

enum FileKind {
    Config,
    Credentials,
}

#[derive(Default)]
struct ProfileAccumulator {
    region: Option<String>,
    has_sso: bool,
    has_access_key: bool,
    has_role_arn: bool,
    sources: Vec<String>,
}

impl ProfileAccumulator {
    fn kind(&self) -> String {
        if self.has_sso {
            "sso".to_string()
        } else if self.has_role_arn {
            "assume_role".to_string()
        } else if self.has_access_key {
            "access_key".to_string()
        } else {
            "other".to_string()
        }
    }
}

fn config_file_path() -> Option<PathBuf> {
    if let Ok(path) = std::env::var("AWS_CONFIG_FILE") {
        if !path.is_empty() {
            return Some(PathBuf::from(path));
        }
    }
    dirs_next::home_dir().map(|h| h.join(".aws/config"))
}

fn credentials_file_path() -> Option<PathBuf> {
    if let Ok(path) = std::env::var("AWS_SHARED_CREDENTIALS_FILE") {
        if !path.is_empty() {
            return Some(PathBuf::from(path));
        }
    }
    dirs_next::home_dir().map(|h| h.join(".aws/credentials"))
}

fn merge_file(
    profiles: &mut BTreeMap<String, ProfileAccumulator>,
    path: &std::path::Path,
    kind: FileKind,
) -> Result<()> {
    if !path.exists() {
        return Ok(());
    }
    let contents = std::fs::read_to_string(path)
        .map_err(|e| anyhow::anyhow!("Failed to read {}: {e}", path.display()))?;

    let source = match kind {
        FileKind::Config => "config",
        FileKind::Credentials => "credentials",
    };

    let mut current: Option<String> = None;
    for raw_line in contents.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            let section = line[1..line.len() - 1].trim();
            current = section_profile_name(section, &kind);
            if let Some(name) = &current {
                let acc = profiles.entry(name.clone()).or_default();
                if !acc.sources.iter().any(|s| s == source) {
                    acc.sources.push(source.to_string());
                }
            }
            continue;
        }
        let Some(name) = &current else { continue };
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim().to_ascii_lowercase();
        let value = value.trim();
        let acc = profiles.entry(name.clone()).or_default();
        match key.as_str() {
            "region" => {
                if acc.region.is_none() && !value.is_empty() {
                    acc.region = Some(value.to_string());
                }
            }
            "sso_start_url" | "sso_session" | "sso_account_id" => acc.has_sso = true,
            "aws_access_key_id" => acc.has_access_key = true,
            "role_arn" => acc.has_role_arn = true,
            _ => {}
        }
    }
    Ok(())
}

/// Map an INI section header to a profile name.
///
/// In `~/.aws/config`, profiles are `[default]` or `[profile <name>]`; other
/// sections (e.g. `[sso-session <name>]`) are not profiles. In
/// `~/.aws/credentials`, every section is a profile name as-is.
fn section_profile_name(section: &str, kind: &FileKind) -> Option<String> {
    match kind {
        FileKind::Config => {
            if section == "default" {
                Some("default".to_string())
            } else {
                section
                    .strip_prefix("profile ")
                    .map(|name| name.trim().to_string())
                    .filter(|name| !name.is_empty())
            }
        }
        FileKind::Credentials => {
            if section.is_empty() {
                None
            } else {
                Some(section.to_string())
            }
        }
    }
}
