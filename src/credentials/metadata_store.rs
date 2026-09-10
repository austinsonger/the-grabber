//! Encrypted JSON store for credential metadata.

use std::fs;
use std::path::PathBuf;

use aes_gcm::{
    aead::{Aead, KeyInit},
    AeadCore, Aes256Gcm, Nonce,
};
use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use keyring::Entry;
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};

use crate::credentials::CredentialEntry;

const METADATA_KEY_SERVICE: &str = "the-grabber/metadata-key";
const METADATA_KEY_LABEL: &str = "metadata-key";

#[derive(Debug, Clone, Serialize, Deserialize)]
struct MetadataFile {
    version: u32,
    entries: Vec<CredentialEntry>,
}

pub struct EncryptedMetadataStore {
    path: PathBuf,
    cipher: Aes256Gcm,
}

impl EncryptedMetadataStore {
    pub fn open(path: PathBuf) -> Result<Self> {
        let key = Self::load_or_create_key()?;
        let cipher =
            Aes256Gcm::new_from_slice(&key).context("Failed to initialize AES-GCM cipher")?;
        Ok(Self { path, cipher })
    }

    fn load_or_create_key() -> Result<Vec<u8>> {
        let entry = Entry::new(METADATA_KEY_SERVICE, METADATA_KEY_LABEL)
            .context("Failed to open metadata key keyring entry")?;
        match entry.get_password() {
            Ok(b64) => STANDARD
                .decode(b64)
                .context("Metadata key is not valid base64"),
            Err(keyring::Error::NoEntry) => {
                let mut key = vec![0u8; 32];
                OsRng.fill_bytes(&mut key);
                let b64 = STANDARD.encode(&key);
                entry
                    .set_password(&b64)
                    .context("Failed to store metadata encryption key")?;
                Ok(key)
            }
            Err(e) => anyhow::bail!("Keyring error: {e}"),
        }
    }

    pub fn list(&self) -> Result<Vec<CredentialEntry>> {
        if !self.path.exists() {
            return Ok(Vec::new());
        }
        let bytes = fs::read(&self.path)
            .with_context(|| format!("Failed to read metadata store {}", self.path.display()))?;
        if bytes.is_empty() {
            return Ok(Vec::new());
        }
        // Format: nonce(12) || ciphertext
        if bytes.len() < 12 {
            anyhow::bail!("Metadata store is corrupt (too short)");
        }
        let (nonce_bytes, ciphertext) = bytes.split_at(12);
        let nonce = Nonce::from_slice(nonce_bytes);
        let plaintext = self
            .cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| anyhow::anyhow!("Failed to decrypt metadata store: {e:?}"))?;
        let file: MetadataFile =
            serde_json::from_slice(&plaintext).context("Metadata store JSON is invalid")?;
        Ok(file.entries)
    }

    pub fn save(&self, entries: &[CredentialEntry]) -> Result<()> {
        let file = MetadataFile {
            version: 1,
            entries: entries.to_vec(),
        };
        let plaintext = serde_json::to_vec(&file).context("Failed to serialize metadata")?;
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let ciphertext = self
            .cipher
            .encrypt(&nonce, plaintext.as_ref())
            .map_err(|e| anyhow::anyhow!("Failed to encrypt metadata: {e:?}"))?;
        let mut bytes = Vec::with_capacity(nonce.len() + ciphertext.len());
        bytes.extend_from_slice(&nonce);
        bytes.extend_from_slice(&ciphertext);
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("Failed to create {}", parent.display()))?;
        }
        fs::write(&self.path, bytes)
            .with_context(|| format!("Failed to write metadata store {}", self.path.display()))?;
        Ok(())
    }
}
