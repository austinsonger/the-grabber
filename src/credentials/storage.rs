//! OS credential-store backends for secrets.

use std::collections::HashMap;

use anyhow::{Context, Result};
use keyring::Entry;

use crate::credentials::{CredentialKind, CredentialSecret};

const APP_NAME: &str = "the-grabber";

pub trait SecretStorage: Send + Sync {
    fn store(&self, credential_id: &str, kind: &CredentialKind, secret: &CredentialSecret) -> Result<()>;
    fn load(&self, credential_id: &str, kind: &CredentialKind) -> Result<CredentialSecret>;
    fn delete(&self, credential_id: &str, kind: &CredentialKind) -> Result<()>;
}

#[derive(Default)]
pub struct KeyringStorage;

impl KeyringStorage {
    fn entries_for(&self, credential_id: &str, kind: &CredentialKind) -> Vec<(String, String)> {
        // Returns (service, label) pairs for each secret field.
        let base = format!("{APP_NAME}/{credential_id}");
        match kind {
            CredentialKind::AwsAccessKey { .. } => vec![
                (format!("{base}/aws_secret_access_key"), "AWS Secret Access Key".into()),
                (format!("{base}/aws_session_token"), "AWS Session Token".into()),
            ],
            CredentialKind::ApiToken { .. } => vec![
                (format!("{base}/token"), "API Token".into()),
            ],
            CredentialKind::BasicAuth { .. } => vec![
                (format!("{base}/password"), "Password".into()),
            ],
            CredentialKind::OAuth { .. } => vec![
                (format!("{base}/client_secret"), "OAuth Client Secret".into()),
            ],
            _ => vec![],
        }
    }
}

impl SecretStorage for KeyringStorage {
    fn store(&self, credential_id: &str, kind: &CredentialKind, secret: &CredentialSecret) -> Result<()> {
        let pairs = match (kind, secret) {
            (CredentialKind::AwsAccessKey { .. }, CredentialSecret::AwsAccessKeySecret { secret_access_key, session_token }) => {
                let mut map = HashMap::new();
                map.insert("aws_secret_access_key", secret_access_key.as_str());
                if let Some(t) = session_token {
                    map.insert("aws_session_token", t.as_str());
                }
                map
            }
            (CredentialKind::ApiToken { .. }, CredentialSecret::ApiToken { token }) => {
                [("token", token.as_str())].into_iter().collect()
            }
            (CredentialKind::BasicAuth { .. }, CredentialSecret::BasicAuth { password }) => {
                [("password", password.as_str())].into_iter().collect()
            }
            (CredentialKind::OAuth { .. }, CredentialSecret::OAuth { client_secret }) => {
                [("client_secret", client_secret.as_str())].into_iter().collect()
            }
            (_, CredentialSecret::None) => HashMap::new(),
            _ => anyhow::bail!("Credential kind and secret type mismatch"),
        };

        let mut stored_any = false;
        for (field, value) in pairs {
            if value.is_empty() {
                continue;
            }
            let service = format!("{APP_NAME}/{credential_id}/{field}");
            let entry = Entry::new(&service, credential_id)
                .with_context(|| format!("Failed to open keyring entry for {service}"))?;
            entry.set_password(value)
                .with_context(|| format!("Failed to store secret for {service}"))?;
            stored_any = true;
        }

        if !stored_any && !matches!(secret, CredentialSecret::None) {
            anyhow::bail!("No secret fields were stored");
        }
        Ok(())
    }

    fn load(&self, credential_id: &str, kind: &CredentialKind) -> Result<CredentialSecret> {
        let defs = self.entries_for(credential_id, kind);
        if defs.is_empty() {
            return Ok(CredentialSecret::None);
        }

        let mut values: HashMap<String, String> = HashMap::new();
        for (service, _label) in defs {
            let field = service.rsplit('/').next().unwrap_or(&service).to_string();
            let entry = Entry::new(&service, credential_id)
                .with_context(|| format!("Failed to open keyring entry for {service}"))?;
            match entry.get_password() {
                Ok(v) => { values.insert(field, v); }
                Err(keyring::Error::NoEntry) => {}
                Err(e) => anyhow::bail!("Keyring read error: {e}"),
            }
        }

        Ok(match kind {
            CredentialKind::AwsAccessKey { .. } => CredentialSecret::AwsAccessKeySecret {
                secret_access_key: values.remove("aws_secret_access_key").unwrap_or_default(),
                session_token: values.remove("aws_session_token"),
            },
            CredentialKind::ApiToken { .. } => CredentialSecret::ApiToken {
                token: values.remove("token").unwrap_or_default(),
            },
            CredentialKind::BasicAuth { .. } => CredentialSecret::BasicAuth {
                password: values.remove("password").unwrap_or_default(),
            },
            CredentialKind::OAuth { .. } => CredentialSecret::OAuth {
                client_secret: values.remove("client_secret").unwrap_or_default(),
            },
            _ => CredentialSecret::None,
        })
    }

    fn delete(&self, credential_id: &str, kind: &CredentialKind) -> Result<()> {
        for (service, _label) in self.entries_for(credential_id, kind) {
            if let Ok(entry) = Entry::new(&service, credential_id) {
                let _ = entry.delete_credential();
            }
        }
        Ok(())
    }
}
