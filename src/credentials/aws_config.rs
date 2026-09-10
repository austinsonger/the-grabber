//! Build an AWS SDK config from a stored credential.

use anyhow::{Context, Result};
use aws_config::BehaviorVersion;
use tokio::io::AsyncWriteExt;

use crate::credentials::{CredentialEntry, CredentialKind, CredentialSecret};

/// Build an AWS SDK config from a stored credential and its secret.
///
/// The caller is responsible for loading the secret from the vault; this keeps
/// the function synchronous with respect to secret access and makes it easy to
/// test without touching the OS keyring.
pub async fn load_aws_sdk_config(
    entry: &CredentialEntry,
    secret: &CredentialSecret,
    region: Option<String>,
) -> Result<aws_config::SdkConfig> {
    let region = region.unwrap_or_else(|| "us-east-1".to_string());
    match &entry.kind {
        CredentialKind::AwsProfileReference { profile_name } => {
            Ok(aws_config::defaults(BehaviorVersion::latest())
                .profile_name(profile_name)
                .region(aws_config::Region::new(region))
                .load()
                .await)
        }
        CredentialKind::AwsSso {
            account_id,
            role_name,
            session_name,
            start_url,
            region: sso_region,
        } => {
            update_aws_config_sso_profile(
                &entry.name,
                start_url,
                sso_region,
                account_id,
                role_name,
                session_name,
            )
            .await?;
            Ok(aws_config::defaults(BehaviorVersion::latest())
                .profile_name(&entry.name)
                .region(aws_config::Region::new(region))
                .load()
                .await)
        }
        CredentialKind::AwsAccessKey { access_key_id } => {
            let (secret_key, session_token) = match secret {
                CredentialSecret::AwsAccessKeySecret {
                    secret_access_key,
                    session_token,
                } => (secret_access_key.as_str(), session_token.as_deref()),
                _ => anyhow::bail!("Missing AWS secret access key in keyring"),
            };
            let creds = aws_credential_types::Credentials::new(
                access_key_id.clone(),
                secret_key.to_string(),
                session_token.map(|t| t.to_string()),
                None,
                "the-grabber-vault",
            );
            Ok(aws_config::defaults(BehaviorVersion::latest())
                .credentials_provider(creds)
                .region(aws_config::Region::new(region))
                .load()
                .await)
        }
        _ => anyhow::bail!("Credential kind is not compatible with AWS"),
    }
}

/// Append an SSO profile block to `~/.aws/config` so the SDK/CLI can refresh tokens.
///
/// This is intentionally simple: if the profile already exists the new block is
/// still appended. A production implementation should parse and update INI
/// sections properly.
async fn update_aws_config_sso_profile(
    profile_name: &str,
    start_url: &str,
    sso_region: &str,
    account_id: &str,
    role_name: &str,
    session_name: &str,
) -> Result<()> {
    let home = dirs_next::home_dir().context("Cannot determine home directory")?;
    let path = home.join(".aws/config");
    let mut contents = if path.exists() {
        tokio::fs::read_to_string(&path).await.unwrap_or_default()
    } else {
        String::new()
    };

    let block = format!(
        "\n[profile {profile_name}]\nsso_start_url = {start_url}\nsso_region = {sso_region}\nsso_account_id = {account_id}\nsso_role_name = {role_name}\nsso_session = {session_name}\n"
    );

    // The plan accepts appended duplicates for now; refine later with INI parsing.
    contents.push_str(&block);

    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .with_context(|| format!("Failed to create {}", parent.display()))?;
    }
    let mut file = tokio::fs::File::create(&path)
        .await
        .with_context(|| format!("Failed to open {} for writing", path.display()))?;
    file.write_all(contents.as_bytes())
        .await
        .with_context(|| format!("Failed to write {}", path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::providers::CloudProvider;
    use std::env;
    use tempfile::tempdir;
    use uuid::Uuid;

    fn aws_access_entry(name: &str, access_key_id: &str) -> CredentialEntry {
        CredentialEntry {
            id: Uuid::new_v4(),
            name: name.into(),
            provider: CloudProvider::Aws,
            kind: CredentialKind::AwsAccessKey {
                access_key_id: access_key_id.into(),
            },
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        }
    }

    #[tokio::test]
    async fn load_aws_config_from_access_key() {
        let entry = aws_access_entry("test", "AKIAIOSFODNN7EXAMPLE");
        let secret = CredentialSecret::AwsAccessKeySecret {
            secret_access_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".into(),
            session_token: Some("session-token".into()),
        };
        let config = load_aws_sdk_config(&entry, &secret, Some("us-west-2".into()))
            .await
            .expect("should build config");
        assert_eq!(config.region().unwrap().as_ref(), "us-west-2");
    }

    #[tokio::test]
    async fn sso_profile_written_to_aws_config() {
        let dir = tempdir().unwrap();
        env::set_var("HOME", dir.path());

        let entry = CredentialEntry {
            id: Uuid::new_v4(),
            name: "sso-test".into(),
            provider: CloudProvider::Aws,
            kind: CredentialKind::AwsSso {
                start_url: "https://example.awsapps.com/start".into(),
                account_id: "123456789012".into(),
                role_name: "ReadOnly".into(),
                region: "us-east-1".into(),
                session_name: "grabber".into(),
            },
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };

        load_aws_sdk_config(&entry, &CredentialSecret::None, Some("us-west-2".into()))
            .await
            .expect("should build config");

        let contents = tokio::fs::read_to_string(dir.path().join(".aws/config"))
            .await
            .expect("config file should exist");
        assert!(contents.contains("[profile sso-test]"));
        assert!(contents.contains("sso_start_url = https://example.awsapps.com/start"));
        assert!(contents.contains("sso_account_id = 123456789012"));
        assert!(contents.contains("sso_role_name = ReadOnly"));
        assert!(contents.contains("sso_session = grabber"));
    }
}
