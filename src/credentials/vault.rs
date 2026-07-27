//! High-level credential vault API.

use std::path::PathBuf;

use anyhow::{Context, Result};
use chrono::Utc;
use uuid::Uuid;

use crate::credentials::{
    CredentialEntry, CredentialKind, CredentialMeta, CredentialSecret, EncryptedMetadataStore,
    KeyringStorage, NewCredential, SecretStorage,
};

pub struct CredentialVault {
    metadata: EncryptedMetadataStore,
    secrets: Box<dyn SecretStorage>,
}

impl CredentialVault {
    pub fn open(data_dir: PathBuf) -> Result<Self> {
        let metadata = EncryptedMetadataStore::open(data_dir.join("credentials.enc.json"))?;
        Ok(Self {
            metadata,
            secrets: Box::new(KeyringStorage::default()),
        })
    }

    pub fn list(&self) -> Result<Vec<CredentialMeta>> {
        Ok(self.metadata.list()?.into_iter().map(|e| e.meta()).collect())
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
        self.secrets.store(&id.to_string(), &entry.kind, &new.secret)?;
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
        self.secrets.store(&id.to_string(), &entry.kind, &new.secret)?;
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
    use super::*;
    use crate::providers::CloudProvider;
    use tempfile::tempdir;

    #[test]
    fn vault_round_trip() {
        let dir = tempdir().unwrap();
        let vault = CredentialVault::open(dir.path().to_path_buf()).unwrap();
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
        match secret {
            CredentialSecret::ApiToken { token } => assert_eq!(token, "secret-token"),
            _ => panic!("wrong secret type"),
        }
    }
}
