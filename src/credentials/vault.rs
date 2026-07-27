//! High-level credential vault API.

use std::path::PathBuf;

use anyhow::{Context, Result};
use chrono::Utc;
use uuid::Uuid;

use crate::credentials::{
    CredentialEntry, CredentialMeta, CredentialSecret, EncryptedMetadataStore, KeyringStorage,
    NewCredential, SecretStorage,
};

pub struct CredentialVault {
    metadata: EncryptedMetadataStore,
    secrets: Box<dyn SecretStorage>,
}

impl CredentialVault {
    pub fn new(metadata: EncryptedMetadataStore, secrets: Box<dyn SecretStorage>) -> Self {
        Self { metadata, secrets }
    }

    pub fn open(data_dir: PathBuf) -> Result<Self> {
        let metadata = EncryptedMetadataStore::open(data_dir.join("credentials.enc.json"))?;
        Ok(Self::new(metadata, Box::new(KeyringStorage)))
    }

    pub fn list(&self) -> Result<Vec<CredentialMeta>> {
        Ok(self
            .metadata
            .list()?
            .into_iter()
            .map(|e| e.meta())
            .collect())
    }

    pub fn get(&self, id: Uuid) -> Result<Option<(CredentialEntry, CredentialSecret)>> {
        let entries = self.metadata.list()?;
        let entry = entries.into_iter().find(|e| e.id == id);
        match entry {
            Some(e) => {
                let secret = self.secrets.load(&id.to_string(), &e.kind)?;
                Ok(Some((e, secret)))
            }
            None => Ok(None),
        }
    }

    pub fn create(&self, new: NewCredential) -> Result<CredentialMeta> {
        let id = Uuid::new_v4();
        let now = Utc::now();
        let entry = CredentialEntry {
            id,
            name: new.name,
            provider: new.provider,
            kind: new.kind,
            created_at: now,
            updated_at: now,
        };
        self.secrets
            .store(&id.to_string(), &entry.kind, &new.secret)?;
        let mut entries = self.metadata.list()?;
        entries.push(entry.clone());
        self.metadata.save(&entries)?;
        Ok(entry.meta())
    }

    pub fn update(&self, id: Uuid, new: NewCredential) -> Result<CredentialMeta> {
        let mut entries = self.metadata.list()?;
        let idx = entries
            .iter()
            .position(|e| e.id == id)
            .context("Credential not found")?;
        let now = Utc::now();
        let entry = CredentialEntry {
            id,
            name: new.name,
            provider: new.provider,
            kind: new.kind.clone(),
            created_at: entries[idx].created_at,
            updated_at: now,
        };
        self.secrets.delete(&id.to_string(), &entries[idx].kind)?;
        self.secrets
            .store(&id.to_string(), &entry.kind, &new.secret)?;
        entries[idx] = entry.clone();
        self.metadata.save(&entries)?;
        Ok(entry.meta())
    }

    pub fn delete(&self, id: Uuid) -> Result<()> {
        let mut entries = self.metadata.list()?;
        let idx = entries
            .iter()
            .position(|e| e.id == id)
            .context("Credential not found")?;
        self.secrets.delete(&id.to_string(), &entries[idx].kind)?;
        entries.remove(idx);
        self.metadata.save(&entries)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    use super::*;
    use crate::credentials::CredentialKind;
    use crate::providers::CloudProvider;
    use tempfile::tempdir;

    /// In-memory secret backend so vault unit tests don't depend on the OS keyring.
    #[derive(Default, Clone)]
    struct MemoryStorage {
        data: Arc<Mutex<HashMap<String, String>>>,
    }

    impl SecretStorage for MemoryStorage {
        fn store(
            &self,
            credential_id: &str,
            _kind: &CredentialKind,
            secret: &CredentialSecret,
        ) -> Result<()> {
            let mut data = self.data.lock().unwrap();
            match secret {
                CredentialSecret::AwsAccessKeySecret {
                    secret_access_key,
                    session_token,
                } => {
                    data.insert(
                        format!("{credential_id}/aws_secret_access_key"),
                        secret_access_key.clone(),
                    );
                    if let Some(t) = session_token {
                        data.insert(format!("{credential_id}/aws_session_token"), t.clone());
                    }
                }
                CredentialSecret::ApiToken { token } => {
                    data.insert(format!("{credential_id}/token"), token.clone());
                }
                CredentialSecret::BasicAuth { password } => {
                    data.insert(format!("{credential_id}/password"), password.clone());
                }
                CredentialSecret::OAuth { client_secret } => {
                    data.insert(
                        format!("{credential_id}/client_secret"),
                        client_secret.clone(),
                    );
                }
                CredentialSecret::None => {}
            }
            Ok(())
        }

        fn load(&self, credential_id: &str, kind: &CredentialKind) -> Result<CredentialSecret> {
            let data = self.data.lock().unwrap();
            Ok(match kind {
                CredentialKind::AwsAccessKey { .. } => CredentialSecret::AwsAccessKeySecret {
                    secret_access_key: data
                        .get(&format!("{credential_id}/aws_secret_access_key"))
                        .cloned()
                        .unwrap_or_default(),
                    session_token: data
                        .get(&format!("{credential_id}/aws_session_token"))
                        .cloned(),
                },
                CredentialKind::ApiToken { .. } => CredentialSecret::ApiToken {
                    token: data
                        .get(&format!("{credential_id}/token"))
                        .cloned()
                        .unwrap_or_default(),
                },
                CredentialKind::BasicAuth { .. } => CredentialSecret::BasicAuth {
                    password: data
                        .get(&format!("{credential_id}/password"))
                        .cloned()
                        .unwrap_or_default(),
                },
                CredentialKind::OAuth { .. } => CredentialSecret::OAuth {
                    client_secret: data
                        .get(&format!("{credential_id}/client_secret"))
                        .cloned()
                        .unwrap_or_default(),
                },
                _ => CredentialSecret::None,
            })
        }

        fn delete(&self, credential_id: &str, _kind: &CredentialKind) -> Result<()> {
            let mut data = self.data.lock().unwrap();
            let prefix = format!("{credential_id}/");
            data.retain(|k, _| !k.starts_with(&prefix));
            Ok(())
        }
    }

    #[test]
    fn vault_round_trip() {
        let dir = tempdir().unwrap();
        let metadata =
            EncryptedMetadataStore::open(dir.path().join("credentials.enc.json")).unwrap();
        let vault = CredentialVault::new(metadata, Box::new(MemoryStorage::default()));
        let meta = vault
            .create(NewCredential {
                name: "Test".into(),
                provider: CloudProvider::Aws,
                kind: CredentialKind::ApiToken {
                    domain: "example.okta.com".into(),
                },
                secret: CredentialSecret::ApiToken {
                    token: "secret-token".into(),
                },
            })
            .unwrap();

        let list = vault.list().unwrap();
        assert_eq!(list.len(), 1);

        let (entry, secret) = vault.get(meta.id).unwrap().unwrap();
        assert_eq!(entry.name, "Test");
        match &secret {
            CredentialSecret::ApiToken { token } => assert_eq!(token, "secret-token"),
            _ => panic!("wrong secret type"),
        }
    }
}
