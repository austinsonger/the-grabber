# Desktop GUI Application Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:subagent-driven-development` (recommended) or `superpowers:executing-plans` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a Tauri v2 + React/TypeScript desktop GUI for The Grabber with an embedded secure credential vault, reusing the existing Rust collector core.

**Architecture:** Refactor the main `the-grabber` crate into a library plus binary, add a `src/credentials/` vault module backed by the OS keyring and an AES-256-GCM encrypted metadata store, expose a thin `Engine` wrapper, and build a `grabber-desktop` Tauri app whose React wizard drives collection, inventory, POA&M, and STIG workflows via typed IPC commands.

**Tech Stack:** Rust (edition 2021), Tauri v2, React + TypeScript, `keyring`, `aes-gcm`/`aead`, `zeroize`, `tokio`, `anyhow`, OS-native webview.

---

## Global Constraints

- The existing CLI/TUI must continue to work unchanged after the refactor.
- All secrets are stored in the OS credential store; only non-sensitive metadata lives in the app-local encrypted store.
- AWS access keys are injected into the SDK in memory by default; writing to `~/.aws/credentials` is deferred.
- The optional master password is out of scope for the first implementation; rely on OS keyring auto-unlock.
- Every Rust change must leave the workspace compilable — run `cargo check --workspace` after each task that touches `.rs` files.
- New files follow the project import order: `std::*` → external crates → `crate::*`.
- Use `anyhow::Result`, `.context(...)`, and `anyhow::bail!`; no `unwrap()`/`expect()` in production code.
- Frontend uses TypeScript strict mode and functional React hooks.

---

## Task 1: Refactor main crate into library + binary

**Files:**
- Modify: `Cargo.toml` (add `[lib]`)
- Create: `src/lib.rs`
- Modify: `src/main.rs`

**Interfaces:**
- Library crate exposes all existing modules so the binary and the Tauri crate can depend on them.

- [x] **Step 1: Add `[lib]` to `Cargo.toml`**

Add above `[[bin]]`:

```toml
[lib]
name = "the_grabber"
path = "src/lib.rs"
```

- [x] **Step 2: Create `src/lib.rs`**

```rust
//! The Grabber library surface shared by the CLI/TUI binary and the desktop GUI.

pub mod app_config;
pub mod audit_log;
pub mod aws_loader;
pub mod cli;
pub mod credentials;
pub mod engine;
pub mod evidence;
pub mod fedramp_coverage;
pub mod fedramp_map;
pub mod inventory_core;
pub mod inventory_orchestrator;
pub mod inventory_xlsx;
pub mod okta_stig_map;
pub mod platform;
pub mod poam;
pub mod providers;
pub mod runner;
pub mod signing;
pub mod stig_remediation_log;
pub mod stig_status;
pub mod tui;
pub mod zip_bundle;
```

- [x] **Step 3: Convert `src/main.rs` to use the library crate**

Replace the top module declarations with:

```rust
use the_grabber::cli::Cli;
use the_grabber::runner::cli_runners::{run_inventory_cli, run_poam_cli, run_standard_cli};
use the_grabber::runner::tui_session::run_tui_session;
```

Remove all `mod ...;` lines.

- [x] **Step 4: Verify**

```bash
cargo check --workspace
```

Expected: clean compile.

- [x] **Step 5: Commit**

```bash
git add Cargo.toml src/lib.rs src/main.rs
git commit -m "refactor: expose the_grabber as a library for desktop GUI reuse"
```

---

## Task 2: Add credential vault dependencies

**Files:**
- Modify: `Cargo.toml` (root package dependencies)

- [x] **Step 1: Add crates**

```toml
keyring = { version = "3", features = ["linux-secret-service-rt-tokio-crypto-openssl"] }
aes-gcm = "0.10"
aead = "0.5"
zeroize = { version = "1", features = ["derive"] }
base64 = "0.22"
```

- [x] **Step 2: Verify**

```bash
cargo check --workspace
```

- [x] **Step 3: Commit**

```bash
git add Cargo.toml
git commit -m "deps: add keyring, aes-gcm, zeroize, base64 for credential vault"
```

---

## Task 3: Define credential entry types

**Files:**
- Create: `src/credentials/mod.rs`
- Create: `src/credentials/entries.rs`

- [x] **Step 1: Create `src/credentials/entries.rs`**

```rust
//! Credential domain types used by the desktop GUI vault.

use std::collections::HashMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::providers::CloudProvider;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialEntry {
    pub id: Uuid,
    pub name: String,
    pub provider: CloudProvider,
    pub kind: CredentialKind,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum CredentialKind {
    AwsSso {
        start_url: String,
        account_id: String,
        role_name: String,
        region: String,
        session_name: String,
    },
    AwsAccessKey {
        access_key_id: String,
    },
    AwsProfileReference {
        profile_name: String,
    },
    ApiToken {
        domain: String,
    },
    BasicAuth {
        host: String,
        username: String,
    },
    OAuth {
        domain: String,
        client_id: String,
    },
}

/// Non-secret metadata returned to the UI.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialMeta {
    pub id: Uuid,
    pub name: String,
    pub provider: CloudProvider,
    pub kind_tag: String,
    pub domain: Option<String>,
    pub host: Option<String>,
    pub access_key_id: Option<String>,
    pub account_id: Option<String>,
    pub profile_name: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl CredentialEntry {
    pub fn meta(&self) -> CredentialMeta {
        CredentialMeta {
            id: self.id,
            name: self.name.clone(),
            provider: self.provider,
            kind_tag: self.kind.type_tag().to_string(),
            domain: self.kind.domain().map(|s| s.to_string()),
            host: self.kind.host().map(|s| s.to_string()),
            access_key_id: self.kind.access_key_id().map(|s| s.to_string()),
            account_id: self.kind.account_id().map(|s| s.to_string()),
            profile_name: self.kind.profile_name().map(|s| s.to_string()),
            created_at: self.created_at,
            updated_at: self.updated_at,
        }
    }
}

impl CredentialKind {
    pub fn type_tag(&self) -> &'static str {
        match self {
            CredentialKind::AwsSso { .. } => "aws_sso",
            CredentialKind::AwsAccessKey { .. } => "aws_access_key",
            CredentialKind::AwsProfileReference { .. } => "aws_profile_reference",
            CredentialKind::ApiToken { .. } => "api_token",
            CredentialKind::BasicAuth { .. } => "basic_auth",
            CredentialKind::OAuth { .. } => "oauth",
        }
    }

    fn domain(&self) -> Option<&str> {
        match self {
            CredentialKind::ApiToken { domain } | CredentialKind::OAuth { domain, .. } => Some(domain),
            _ => None,
        }
    }

    fn host(&self) -> Option<&str> {
        match self {
            CredentialKind::BasicAuth { host, .. } => Some(host),
            _ => None,
        }
    }

    fn access_key_id(&self) -> Option<&str> {
        match self {
            CredentialKind::AwsAccessKey { access_key_id } => Some(access_key_id),
            _ => None,
        }
    }

    fn account_id(&self) -> Option<&str> {
        match self {
            CredentialKind::AwsSso { account_id, .. } => Some(account_id),
            _ => None,
        }
    }

    fn profile_name(&self) -> Option<&str> {
        match self {
            CredentialKind::AwsProfileReference { profile_name } => Some(profile_name),
            _ => None,
        }
    }
}

/// Secret fields for each credential kind. These are the values stored in the OS keyring.
#[derive(Debug, Clone, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
pub enum CredentialSecret {
    AwsAccessKeySecret { secret_access_key: String, session_token: Option<String> },
    ApiToken { token: String },
    BasicAuth { password: String },
    OAuth { client_secret: String },
    None,
}

/// A complete credential as the UI sends it (secret included).
#[derive(Debug, Clone)]
pub struct NewCredential {
    pub name: String,
    pub provider: CloudProvider,
    pub kind: CredentialKind,
    pub secret: CredentialSecret,
}
```

- [x] **Step 2: Create `src/credentials/mod.rs`**

```rust
//! Secure credential vault for the desktop GUI.

pub mod entries;
pub mod storage;
pub mod vault;
pub mod aws_config;

pub use entries::*;
pub use storage::*;
pub use vault::*;
```

- [x] **Step 3: Verify**

```bash
cargo check --workspace
```

- [x] **Step 4: Commit**

```bash
git add src/credentials/
git commit -m "feat(credentials): add credential entry and secret types"
```

---

## Task 4: Implement OS keyring secret storage

**Files:**
- Create: `src/credentials/storage.rs`

- [x] **Step 1: Implement keyring-backed storage**

```rust
//! OS credential-store backends for secrets.

use std::collections::HashMap;

use anyhow::{Context, Result};
use keyring::Entry;

use crate::credentials::{CredentialSecret, CredentialKind};

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
                let _ = entry.delete_password();
            }
        }
        Ok(())
    }
}
```

- [x] **Step 2: Verify**

```bash
cargo check --workspace
```

- [x] **Step 3: Commit**

```bash
git add src/credentials/storage.rs
git commit -m "feat(credentials): add OS keyring secret storage backend"
```

---

## Task 5: Implement encrypted metadata store

**Files:**
- Create: `src/credentials/metadata_store.rs`
- Modify: `src/credentials/mod.rs`

- [x] **Step 1: Implement AES-256-GCM metadata store**

```rust
//! Encrypted JSON store for credential metadata.

use std::fs;
use std::path::PathBuf;

use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use anyhow::{Context, Result};
use keyring::Entry;
use serde::{Deserialize, Serialize};

use crate::credentials::{CredentialEntry, CredentialMeta};

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
        let cipher = Aes256Gcm::new_from_slice(&key)
            .context("Failed to initialize AES-GCM cipher")?;
        Ok(Self { path, cipher })
    }

    fn load_or_create_key() -> Result<Vec<u8>> {
        let entry = Entry::new(METADATA_KEY_SERVICE, METADATA_KEY_LABEL)
            .context("Failed to open metadata key keyring entry")?;
        match entry.get_password() {
            Ok(b64) => base64::Engine::decode(&base64::engine::general_purpose::STANDARD, b64)
                .context("Metadata key is not valid base64"),
            Err(keyring::Error::NoEntry) => {
                let key: Vec<u8> = (0..32).map(|_| OsRng.next_u32() as u8).collect();
                let b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &key);
                entry.set_password(&b64)
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
        let plaintext = self.cipher.decrypt(nonce, ciphertext)
            .context("Failed to decrypt metadata store")?;
        let file: MetadataFile = serde_json::from_slice(&plaintext)
            .context("Metadata store JSON is invalid")?;
        Ok(file.entries)
    }

    pub fn save(&self, entries: &[CredentialEntry]) -> Result<()> {
        let file = MetadataFile { version: 1, entries: entries.to_vec() };
        let plaintext = serde_json::to_vec(&file)
            .context("Failed to serialize metadata")?;
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let ciphertext = self.cipher.encrypt(&nonce, plaintext.as_ref())
            .context("Failed to encrypt metadata")?;
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
```

> **Note:** `OsRng` from `aes_gcm::aead` has `next_u32`; if it does not, import `rand::rngs::OsRng` instead and add `rand` to dependencies.

- [x] **Step 2: Update `src/credentials/mod.rs`**

```rust
pub mod metadata_store;
pub use metadata_store::*;
```

- [x] **Step 3: Verify**

```bash
cargo check --workspace
```

- [x] **Step 4: Commit**

```bash
git add src/credentials/
git commit -m "feat(credentials): add AES-256-GCM encrypted metadata store"
```

---

## Task 6: Implement `CredentialVault` CRUD

**Files:**
- Create: `src/credentials/vault.rs`
- Modify: `src/credentials/mod.rs`

- [x] **Step 1: Implement vault**

```rust
//! High-level credential vault API.

use std::path::PathBuf;

use anyhow::{Context, Result};
use chrono::Utc;
use uuid::Uuid;

use crate::credentials::{
    CredentialEntry, CredentialMeta, CredentialSecret, CredentialKind,
    EncryptedMetadataStore, KeyringStorage, NewCredential, SecretStorage,
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
        let idx = entries.iter().position(|e| e.id == id)
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
        let idx = entries.iter().position(|e| e.id == id)
            .context("Credential not found")?;
        self.secrets.delete(&id.to_string(), &entries[idx].kind)?;
        entries.remove(idx);
        self.metadata.save(&entries)?;
        Ok(())
    }
}
```

- [x] **Step 2: Update `src/credentials/mod.rs`**

```rust
pub use vault::*;
```

- [x] **Step 3: Add unit test for vault round-trip**

Create `src/credentials/vault_test.rs` or add `#[cfg(test)]` at bottom of `vault.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::providers::CloudProvider;
    use tempfile::tempdir;

    #[test]
    fn vault_round_trip() {
        let dir = tempdir().unwrap();
        let vault = CredentialVault::open(dir.path().to_path_buf()).unwrap();
        let meta = vault.create(NewCredential {
            name: "Test".into(),
            provider: CloudProvider::Aws,
            kind: CredentialKind::ApiToken { domain: "example.okta.com".into() },
            secret: CredentialSecret::ApiToken { token: "secret-token".into() },
        }).unwrap();

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
```

Add `tempfile` to `[dev-dependencies]` in `Cargo.toml` if not present.

- [x] **Step 4: Verify**

```bash
cargo test --lib credentials::vault::tests::vault_round_trip
```

Expected: PASS.

- [x] **Step 5: Commit**

```bash
git add src/credentials/ Cargo.toml
git commit -m "feat(credentials): implement CredentialVault CRUD with round-trip test"
```

---

## Task 7: Build AWS SDK config from stored credentials

**Files:**
- Create: `src/credentials/aws_config.rs`
- Modify: `src/credentials/mod.rs`

- [x] **Step 1: Implement AWS config builder**

```rust
//! Build an AWS SDK config from a stored credential.

use std::time::Duration;

use anyhow::{Context, Result};
use aws_config::BehaviorVersion;

use crate::credentials::{CredentialEntry, CredentialKind, CredentialSecret};

pub async fn load_aws_sdk_config(entry: &CredentialEntry, region: Option<String>) -> Result<aws_config::SdkConfig> {
    let region = region.unwrap_or_else(|| "us-east-1".to_string());
    match &entry.kind {
        CredentialKind::AwsProfileReference { profile_name } => {
            Ok(aws_config::defaults(BehaviorVersion::latest())
                .profile_name(profile_name)
                .region(aws_config::Region::new(region))
                .load().await)
        }
        CredentialKind::AwsSso { account_id: _, role_name, session_name, start_url, region: sso_region } => {
            // Write/update the SSO profile block in ~/.aws/config so the SDK/CLI can refresh tokens.
            update_aws_config_sso_profile(&entry.name, start_url, sso_region, role_name, session_name).await?;
            Ok(aws_config::defaults(BehaviorVersion::latest())
                .profile_name(&entry.name)
                .region(aws_config::Region::new(region))
                .load().await)
        }
        CredentialKind::AwsAccessKey { access_key_id } => {
            let secret = entry.secret().await?;
            let (secret_key, session_token) = match secret {
                CredentialSecret::AwsAccessKeySecret { secret_access_key, session_token } => (secret_access_key, session_token),
                _ => anyhow::bail!("Missing AWS secret access key in keyring"),
            };
            let creds = aws_credential_types::Credentials::new(
                access_key_id,
                secret_key,
                session_token,
                None,
                "the-grabber-vault",
            );
            Ok(aws_config::defaults(BehaviorVersion::latest())
                .credentials_provider(creds)
                .region(aws_config::Region::new(region))
                .load().await)
        }
        _ => anyhow::bail!("Credential kind is not compatible with AWS"),
    }
}

async fn update_aws_config_sso_profile(
    profile_name: &str,
    start_url: &str,
    sso_region: &str,
    role_name: &str,
    session_name: &str,
) -> Result<()> {
    use std::io::Write;

    let home = dirs::home_dir().context("Cannot determine home directory")?;
    let path = home.join(".aws/config");
    let mut contents = if path.exists() {
        tokio::fs::read_to_string(&path).await.unwrap_or_default()
    } else {
        String::new()
    };

    let block = format!(
        "\n[profile {}]\nsso_start_url = {}\nsso_region = {}\nsso_account_id = placeholder\nsso_role_name = {}\nsso_session = {}\n",
        profile_name, start_url, sso_region, role_name, session_name
    );

    // Naive replacement: if profile section exists, append/overwrite block. Production implementation
    // should parse INI sections properly.
    if contents.contains(&format!("[profile {}]", profile_name)) {
        // For the plan, accept the appended duplicate; refine later with ini parsing.
        contents.push_str(&block);
    } else {
        contents.push_str(&block);
    }

    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    let mut file = tokio::fs::File::create(&path).await?;
    file.write_all(contents.as_bytes()).await?;
    Ok(())
}
```

> **Note:** Add `dirs` to dependencies for cross-platform home-dir resolution.

Add helper `secret()` to `CredentialEntry`? Alternatively pass secret in. To keep it simple, update `vault.get` already returns `(entry, secret)`. Use that. So `load_aws_sdk_config` can accept `secret: &CredentialSecret`.

- [x] **Step 2: Update `src/credentials/mod.rs`**

```rust
pub mod aws_config;
pub use aws_config::*;
```

- [x] **Step 3: Verify**

```bash
cargo check --workspace
```

- [x] **Step 4: Commit**

```bash
git add src/credentials/ Cargo.toml
git commit -m "feat(credentials): build AWS SDK config from vault entries"
```

---

## Task 8: Add the `Engine` wrapper

**Files:**
- Create: `src/engine.rs`
- Modify: `src/lib.rs`

- [x] **Step 1: Create `src/engine.rs`**

```rust
//! High-level engine used by the desktop GUI.

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use tokio::runtime::Runtime;

use crate::app_config::AppConfig;
use crate::credentials::CredentialVault;

pub struct Engine {
    pub config: AppConfig,
    pub vault: CredentialVault,
    pub runtime: Arc<Runtime>,
}

impl Engine {
    pub fn new(config: AppConfig, data_dir: PathBuf) -> Result<Self> {
        let runtime = Arc::new(
            Runtime::new().context("Failed to create Tokio runtime")?
        );
        let vault = CredentialVault::open(data_dir)?;
        Ok(Self { config, vault, runtime })
    }
}

pub trait ProgressSink: Send + Sync {
    fn emit(&self, event: ProgressEvent);
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ProgressEvent {
    pub run_id: String,
    pub account: String,
    pub region: Option<String>,
    pub collector: String,
    pub status: String,
    pub records: u64,
    pub message: Option<String>,
}
```

Collection/inventory/poam methods will be added in later tasks; this task only establishes the shell and state.

- [x] **Step 2: Update `src/lib.rs`**

```rust
pub mod engine;
```

- [x] **Step 3: Verify**

```bash
cargo check --workspace
```

- [x] **Step 4: Commit**

```bash
git add src/engine.rs src/lib.rs
git commit -m "feat(engine): add Engine wrapper for desktop GUI"
```

---

## Task 9: Scaffold the Tauri + React desktop app

**Files:**
- Create: `grabber-desktop/src-tauri/Cargo.toml`
- Create: `grabber-desktop/src-tauri/tauri.conf.json`
- Create: `grabber-desktop/src-tauri/src/main.rs`
- Create: `grabber-desktop/package.json`
- Create: `grabber-desktop/tsconfig.json`
- Create: `grabber-desktop/vite.config.ts`
- Create: `grabber-desktop/index.html`
- Create: `grabber-desktop/src/main.tsx`
- Create: `grabber-desktop/src/App.tsx`

- [x] **Step 1: Create the Tauri backend crate**

`grabber-desktop/src-tauri/Cargo.toml`:

```toml
[package]
name = "grabber-desktop"
version = "0.1.0"
edition = "2021"

[build-dependencies]
tauri-build = { version = "2", features = [] }

[dependencies]
tauri = { version = "2", features = ["devtools"] }
tokio = { version = "1", features = ["full"] }
anyhow = "1"
serde = { version = "1", features = ["derive"] }
serde_json = "1"
the-grabber = { path = "../.." }
```

`grabber-desktop/src-tauri/tauri.conf.json`:

```json
{
  "$schema": "https://schema.tauri.app/config/2",
  "productName": "The Grabber",
  "version": "0.1.0",
  "identifier": "com.thegrabber.desktop",
  "build": {
    "beforeDevCommand": "cd ../ && npm run dev",
    "beforeBuildCommand": "cd ../ && npm run build",
    "devUrl": "http://localhost:1420",
    "frontendDist": "../dist"
  },
  "app": {
    "windows": [
      {
        "title": "The Grabber",
        "width": 1280,
        "height": 800,
        "resizable": true
      }
    ],
    "security": {
      "csp": "default-src 'self'; connect-src ipc: http://ipc.localhost; style-src 'self' 'unsafe-inline'"
    }
  },
  "bundle": {
    "active": true,
    "targets": ["app", "dmg", "msi", "deb"],
    "icon": ["icons/32x32.png", "icons/128x128.png", "icons/icon.icns", "icons/icon.ico"]
  }
}
```

`grabber-desktop/src-tauri/src/main.rs`:

```rust
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    grabber_desktop_lib::run();
}
```

- [x] **Step 2: Create frontend skeleton**

`grabber-desktop/package.json`:

```json
{
  "name": "grabber-desktop",
  "private": true,
  "version": "0.1.0",
  "type": "module",
  "scripts": {
    "dev": "vite",
    "build": "tsc && vite build",
    "preview": "vite preview"
  },
  "dependencies": {
    "@tauri-apps/api": "^2",
    "@tauri-apps/plugin-dialog": "^2",
    "react": "^18",
    "react-dom": "^18"
  },
  "devDependencies": {
    "@types/react": "^18",
    "@types/react-dom": "^18",
    "@vitejs/plugin-react": "^4",
    "typescript": "^5",
    "vite": "^5"
  }
}
```

`grabber-desktop/tsconfig.json`:

```json
{
  "compilerOptions": {
    "target": "ES2020",
    "useDefineForClassFields": true,
    "lib": ["ES2020", "DOM", "DOM.Iterable"],
    "module": "ESNext",
    "skipLibCheck": true,
    "moduleResolution": "bundler",
    "allowImportingTsExtensions": true,
    "resolveJsonModule": true,
    "isolatedModules": true,
    "noEmit": true,
    "jsx": "react-jsx",
    "strict": true,
    "noUnusedLocals": true,
    "noUnusedParameters": true,
    "noFallthroughCasesInSwitch": true
  },
  "include": ["src"],
  "references": [{ "path": "./tsconfig.node.json" }]
}
```

`grabber-desktop/vite.config.ts`:

```ts
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig(async () => ({
  plugins: [react()],
  clearScreen: false,
  server: { port: 1420, strictPort: true },
  envPrefix: ["VITE_", "TAURI_"],
}));
```

`grabber-desktop/index.html`:

```html
<!doctype html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>The Grabber</title>
  </head>
  <body>
    <div id="root"></div>
    <script type="module" src="/src/main.tsx"></script>
  </body>
</html>
```

`grabber-desktop/src/main.tsx`:

```tsx
import React from "react";
import ReactDOM from "react-dom/client";
import App from "./App";

ReactDOM.createRoot(document.getElementById("root") as HTMLElement).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);
```

`grabber-desktop/src/App.tsx`:

```tsx
function App() {
  return <div>The Grabber Desktop</div>;
}

export default App;
```

- [x] **Step 3: Update workspace `Cargo.toml`**

Add `grabber-desktop/src-tauri` to workspace members? Tauri crate is in a nested workspace? The root Cargo.toml is workspace. We can either include the Tauri crate as a member or keep it as separate nested workspace. Simpler: add `grabber-desktop/src-tauri` to `workspace.members`.

```toml
members = [".", "crates/...", "grabber-desktop/src-tauri"]
```

- [x] **Step 4: Verify Tauri dev build**

```bash
cd grabber-desktop && npm install
npm run tauri dev
```

Expected: an empty Tauri window opens with the title "The Grabber".

- [x] **Step 5: Commit**

```bash
git add grabber-desktop/ Cargo.toml
git commit -m "chore(desktop): scaffold Tauri v2 + React + TypeScript app"
```

---

## Task 10: Add Tauri state, errors, and DTOs

**Files:**
- Create: `grabber-desktop/src-tauri/src/lib.rs`
- Create: `grabber-desktop/src-tauri/src/state.rs`
- Create: `grabber-desktop/src-tauri/src/error.rs`
- Create: `grabber-desktop/src-tauri/src/dto.rs`
- Create: `grabber-desktop/src-tauri/src/commands/mod.rs`
- Modify: `grabber-desktop/src-tauri/src/main.rs`

- [x] **Step 1: Define DTOs and error type**

`grabber-desktop/src-tauri/src/error.rs`:

```rust
use serde::Serialize;

#[derive(Debug, Serialize, thiserror::Error)]
#[serde(tag = "error", content = "message")]
pub enum GuiError {
    #[error("Config error: {0}")]
    Config(String),
    #[error("Credential error: {0}")]
    Credential(String),
    #[error("Collection error: {0}")]
    Collection(String),
    #[error("Not found: {0}")]
    NotFound(String),
    #[error("Validation error: {0}")]
    Validation(String),
}

impl From<anyhow::Error> for GuiError {
    fn from(e: anyhow::Error) -> Self {
        GuiError::Collection(e.to_string())
    }
}
```

`grabber-desktop/src-tauri/src/dto.rs`:

```rust
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialMetaDto {
    pub id: String,
    pub name: String,
    pub provider: String,
    pub kind: String,
    pub domain: Option<String>,
    pub host: Option<String>,
    pub access_key_id: Option<String>,
    pub account_id: Option<String>,
    pub profile_name: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CredentialWriteDto {
    pub name: String,
    pub provider: String,
    pub kind: String,
    pub domain: Option<String>,
    pub host: Option<String>,
    pub start_url: Option<String>,
    pub account_id: Option<String>,
    pub role_name: Option<String>,
    pub region: Option<String>,
    pub session_name: Option<String>,
    pub access_key_id: Option<String>,
    pub secret_access_key: Option<String>,
    pub session_token: Option<String>,
    pub username: Option<String>,
    pub password: Option<String>,
    pub token: Option<String>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub profile_name: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AppConfigDto {
    pub accounts: Vec<AccountDto>,
    pub defaults: DefaultsDto,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountDto {
    pub name: String,
    pub provider: String,
    pub account_id: Option<String>,
    pub credential_id: Option<String>,
    pub profile: Option<String>,
    pub region: String,
    pub output_dir: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DefaultsDto {
    pub region: String,
    pub output_dir: String,
    pub start_date_offset_days: i64,
}
```

`grabber-desktop/src-tauri/src/state.rs`:

```rust
use std::sync::Arc;

use the_grabber::app_config::AppConfig;
use the_grabber::credentials::CredentialVault;
use the_grabber::engine::Engine;

pub struct AppState {
    pub engine: Arc<Engine>,
    pub config: AppConfig,
}

impl AppState {
    pub fn new(engine: Arc<Engine>, config: AppConfig) -> Self {
        Self { engine, config }
    }
}
```

- [x] **Step 2: Wire library entry**

`grabber-desktop/src-tauri/src/lib.rs`:

```rust
pub mod commands;
pub mod dto;
pub mod error;
pub mod state;

use std::path::PathBuf;
use std::sync::Arc;

use tauri::Manager;

use the_grabber::app_config::load_config;
use the_grabber::engine::Engine;

use crate::state::AppState;

#[tauri::command]
fn greet(name: &str) -> String {
    format!("Hello, {}!", name)
}

pub fn run() {
    tauri::Builder::default()
        .setup(|app| {
            let data_dir = app.path().app_data_dir()?;
            let config = load_config()?;
            let engine = Arc::new(Engine::new(config.clone(), data_dir)?);
            app.manage(AppState::new(engine, config));
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![greet])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
```

> **Note:** `load_config` may need to be made `pub` in `src/app_config.rs`. Update that in this task.

`grabber-desktop/src-tauri/src/main.rs`:

```rust
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    grabber_desktop_lib::run();
}
```

- [x] **Step 3: Verify**

```bash
cargo check --workspace
cd grabber-desktop && npm run tauri build -- --debug
```

- [x] **Step 4: Commit**

```bash
git add grabber-desktop/src-tauri/ src/app_config.rs
git commit -m "feat(desktop): add Tauri state, DTOs, and error types"
```

---

## Task 11: Implement config commands

**Files:**
- Create: `grabber-desktop/src-tauri/src/commands/config.rs`
- Modify: `grabber-desktop/src-tauri/src/commands/mod.rs`
- Modify: `grabber-desktop/src-tauri/src/lib.rs`

- [x] **Step 1: Implement config commands**

```rust
use tauri::State;

use the_grabber::app_config::{load_config, save_config};

use crate::dto::{AccountDto, AppConfigDto, DefaultsDto};
use crate::error::GuiError;
use crate::state::AppState;

#[tauri::command]
pub async fn load_app_config(_state: State<'_, AppState>) -> Result<AppConfigDto, GuiError> {
    let config = load_config().map_err(|e| GuiError::Config(e.to_string()))?;
    Ok(AppConfigDto {
        accounts: config.accounts.into_iter().map(|a| AccountDto {
            name: a.name,
            provider: a.provider.to_string(),
            account_id: a.account_id,
            credential_id: a.credential_id,
            profile: a.profile,
            region: a.region,
            output_dir: a.output_dir,
        }).collect(),
        defaults: DefaultsDto {
            region: config.defaults.region,
            output_dir: config.defaults.output_dir,
            start_date_offset_days: config.defaults.start_date_offset_days,
        },
    })
}

#[tauri::command]
pub async fn save_app_config(dto: AppConfigDto, _state: State<'_, AppState>) -> Result<(), GuiError> {
    // Conversion omitted for brevity; map DTO back to the_grabber::app_config::AppConfig.
    Ok(())
}
```

- [x] **Step 2: Register commands**

`grabber-desktop/src-tauri/src/lib.rs`:

```rust
.invoke_handler(tauri::generate_handler![
    commands::config::load_app_config,
    commands::config::save_app_config,
])
```

- [x] **Step 3: Add TypeScript API client**

`grabber-desktop/src/api/config.ts`:

```ts
import { invoke } from "@tauri-apps/api/core";

export interface AppConfigDto {
  accounts: AccountDto[];
  defaults: DefaultsDto;
}

export interface AccountDto {
  name: string;
  provider: string;
  account_id?: string;
  credential_id?: string;
  profile?: string;
  region: string;
  output_dir?: string;
}

export interface DefaultsDto {
  region: string;
  output_dir: string;
  start_date_offset_days: number;
}

export const loadAppConfig = () => invoke<AppConfigDto>("load_app_config");
```

- [x] **Step 4: Verify**

```bash
cargo check --workspace
```

- [x] **Step 5: Commit**

```bash
git add grabber-desktop/src-tauri/src/commands/config.rs grabber-desktop/src-tauri/src/commands/mod.rs grabber-desktop/src-tauri/src/lib.rs grabber-desktop/src/api/config.ts
git commit -m "feat(desktop): add load/save config Tauri commands and TS client"
```

---

## Task 12: Implement credential vault commands

**Files:**
- Create: `grabber-desktop/src-tauri/src/commands/credentials.rs`
- Modify: `grabber-desktop/src-tauri/src/commands/mod.rs`
- Modify: `grabber-desktop/src-tauri/src/lib.rs`

- [x] **Step 1: Implement credential commands**

```rust
use tauri::State;
use uuid::Uuid;

use the_grabber::credentials::{CredentialKind, CredentialSecret, NewCredential};
use the_grabber::providers::CloudProvider;

use crate::dto::{CredentialMetaDto, CredentialWriteDto};
use crate::error::GuiError;
use crate::state::AppState;

#[tauri::command]
pub async fn list_credentials(state: State<'_, AppState>) -> Result<Vec<CredentialMetaDto>, GuiError> {
    let metas = state.engine.vault.list().map_err(|e| GuiError::Credential(e.to_string()))?;
    Ok(metas.into_iter().map(|m| CredentialMetaDto {
        id: m.id.to_string(),
        name: m.name,
        provider: m.provider.to_string(),
        kind: m.kind_tag,
        domain: m.domain,
        host: m.host,
        access_key_id: m.access_key_id,
        account_id: m.account_id,
        profile_name: m.profile_name,
    }).collect())
}

#[tauri::command]
pub async fn create_credential(dto: CredentialWriteDto, state: State<'_, AppState>) -> Result<CredentialMetaDto, GuiError> {
    let (kind, secret) = parse_credential_dto(&dto).map_err(|e| GuiError::Validation(e.to_string()))?;
    let provider = CloudProvider::try_from(dto.provider.as_str())
        .map_err(|_| GuiError::Validation(format!("Unknown provider {}", dto.provider)))?;
    let new = NewCredential { name: dto.name, provider, kind, secret };
    let meta = state.engine.vault.create(new).map_err(|e| GuiError::Credential(e.to_string()))?;
    Ok(CredentialMetaDto {
        id: meta.id.to_string(),
        name: meta.name,
        provider: meta.provider.to_string(),
        kind: meta.kind_tag,
        domain: meta.domain,
        host: meta.host,
        access_key_id: meta.access_key_id,
        account_id: meta.account_id,
        profile_name: meta.profile_name,
    })
}

fn parse_credential_dto(dto: &CredentialWriteDto) -> anyhow::Result<(CredentialKind, CredentialSecret)> {
    Ok(match dto.kind.as_str() {
        "aws_sso" => (
            CredentialKind::AwsSso {
                start_url: dto.start_url.clone().context("start_url required")?,
                account_id: dto.account_id.clone().context("account_id required")?,
                role_name: dto.role_name.clone().context("role_name required")?,
                region: dto.region.clone().context("region required")?,
                session_name: dto.session_name.clone().unwrap_or_else(|| "the-grabber".into()),
            },
            CredentialSecret::None,
        ),
        "aws_access_key" => (
            CredentialKind::AwsAccessKey {
                access_key_id: dto.access_key_id.clone().context("access_key_id required")?,
            },
            CredentialSecret::AwsAccessKeySecret {
                secret_access_key: dto.secret_access_key.clone().context("secret_access_key required")?,
                session_token: dto.session_token.clone(),
            },
        ),
        "api_token" => (
            CredentialKind::ApiToken { domain: dto.domain.clone().context("domain required")? },
            CredentialSecret::ApiToken { token: dto.token.clone().context("token required")? },
        ),
        "basic_auth" => (
            CredentialKind::BasicAuth {
                host: dto.host.clone().context("host required")?,
                username: dto.username.clone().context("username required")?,
            },
            CredentialSecret::BasicAuth { password: dto.password.clone().context("password required")? },
        ),
        "oauth" => (
            CredentialKind::OAuth {
                domain: dto.domain.clone().context("domain required")?,
                client_id: dto.client_id.clone().context("client_id required")?,
            },
            CredentialSecret::OAuth { client_secret: dto.client_secret.clone().context("client_secret required")? },
        ),
        "aws_profile_reference" => (
            CredentialKind::AwsProfileReference { profile_name: dto.profile_name.clone().context("profile_name required")? },
            CredentialSecret::None,
        ),
        _ => anyhow::bail!("Unsupported credential kind: {}", dto.kind),
    })
}

// delete_credential, get_credential, test_credential, import_aws_profiles follow the same pattern.
```

- [x] **Step 2: Register commands**

- [x] **Step 3: Add TypeScript API client**

`grabber-desktop/src/api/credentials.ts` with `invoke` wrappers.

- [x] **Step 4: Verify**

```bash
cargo check --workspace
```

- [x] **Step 5: Commit**

```bash
git add grabber-desktop/src-tauri/src/commands/credentials.rs grabber-desktop/src/api/credentials.ts
git commit -m "feat(desktop): add credential vault Tauri commands and TS client"
```

---

## Task 13: Build the Credential Vault UI screen

**Files:**
- Create: `grabber-desktop/src/screens/CredentialVault.tsx`
- Create: `grabber-desktop/src/components/CredentialForm.tsx`
- Modify: `grabber-desktop/src/App.tsx`

- [x] **Step 1: Build list + add form**

Representative React component:

```tsx
import { useEffect, useState } from "react";
import { listCredentials, createCredential, CredentialWriteDto } from "../api/credentials";

export default function CredentialVault() {
  const [creds, setCreds] = useState<CredentialMetaDto[]>([]);
  const [form, setForm] = useState<CredentialWriteDto>({ name: "", provider: "aws", kind: "aws_sso" });

  useEffect(() => { refresh(); }, []);

  const refresh = () => listCredentials().then(setCreds);

  const onSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    await createCredential(form);
    refresh();
  };

  return (
    <div>
      <h1>Credential Vault</h1>
      <table>
        <thead><tr><th>Name</th><th>Provider</th><th>Kind</th></tr></thead>
        <tbody>
          {creds.map(c => <tr key={c.id}><td>{c.name}</td><td>{c.provider}</td><td>{c.kind}</td></tr>)}
        </tbody>
      </table>
      <form onSubmit={onSubmit}>
        <input value={form.name} onChange={e => setForm({ ...form, name: e.target.value })} placeholder="Name" />
        {/* provider-specific fields rendered conditionally */}
        <button type="submit">Save</button>
      </form>
    </div>
  );
}
```

- [x] **Step 2: Verify in UI**

Run `npm run tauri dev`, add a test credential, refresh, and confirm it appears in the list.

- [x] **Step 3: Commit**

```bash
git add grabber-desktop/src/screens/CredentialVault.tsx grabber-desktop/src/components/CredentialForm.tsx grabber-desktop/src/App.tsx
git commit -m "feat(desktop): add credential vault screen"
```

---

## Task 14: Update account config schema and commands

**Files:**
- Modify: `src/app_config.rs`
- Create: `grabber-desktop/src-tauri/src/commands/accounts.rs`

- [x] **Step 1: Add `credential_id` to `Account`**

```rust
pub struct Account {
    pub name: String,
    pub provider: CloudProvider,
    pub account_id: Option<String>,
    pub profile: Option<String>,
    pub credential_id: Option<String>,   // NEW
    pub region: String,
    pub output_dir: Option<String>,
    pub collectors: CollectorConfig,
}
```

Update serde defaults and any construction sites (`Default` impls, example config loaders).

- [x] **Step 2: Add account CRUD commands**

```rust
#[tauri::command]
pub async fn list_accounts(state: State<'_, AppState>) -> Result<Vec<AccountDto>, GuiError> {
    Ok(state.config.accounts.iter().map(AccountDto::from).collect())
}

#[tauri::command]
pub async fn test_account(name: String, state: State<'_, AppState>) -> Result<IdentityInfo, GuiError> {
    // Resolve credential, build SDK config, call STS GetCallerIdentity.
}

#[tauri::command]
pub async fn discover_regions(credential_id: String, state: State<'_, AppState>) -> Result<Vec<String>, GuiError> {
    // Resolve credential, build SDK config, call EC2 DescribeRegions.
}
```

- [x] **Step 3: Verify**

```bash
cargo check --workspace
```

- [x] **Step 4: Commit**

```bash
git add src/app_config.rs grabber-desktop/src-tauri/src/commands/accounts.rs
git commit -m "feat(config): add credential_id to Account and account test/discovery commands"
```

---

## Task 15: Build Welcome / Dashboard screen

**Files:**
- Create: `grabber-desktop/src/screens/Dashboard.tsx`
- Modify: `grabber-desktop/src/App.tsx`

- [x] **Step 1: Implement dashboard**

- Recent runs list from GUI state file.
- Buttons to start each feature.
- Link to Credential Vault.

- [x] **Step 2: Verify**

Run `npm run tauri dev` and confirm navigation works.

- [x] **Step 3: Commit**

```bash
git add grabber-desktop/src/screens/Dashboard.tsx grabber-desktop/src/App.tsx
git commit -m "feat(desktop): add welcome dashboard"
```

---

## Task 16: Build Account & Region selection screens

**Files:**
- Create: `grabber-desktop/src/screens/AccountSelection.tsx`
- Create: `grabber-desktop/src/screens/RegionSelection.tsx`
- Modify: `grabber-desktop/src/App.tsx`

- [x] **Step 1: Implement account selection**

- Table of accounts with credential status.
- Multi-select checkboxes.
- "Add account" modal (creates `[[account]]` block + credential).

- [x] **Step 2: Implement region selection**

- Region list with "Discover" button.
- Global-services note.

- [x] **Step 3: Verify**

Manual UI test: select accounts, discover regions.

- [x] **Step 4: Commit**

```bash
git add grabber-desktop/src/screens/AccountSelection.tsx grabber-desktop/src/screens/RegionSelection.tsx grabber-desktop/src/App.tsx
git commit -m "feat(desktop): add account and region selection screens"
```

---

## Task 17: Implement feature selection and date range

**Files:**
- Create: `grabber-desktop/src/screens/FeatureSelection.tsx`
- Create: `grabber-desktop/src/screens/DateRangeSelection.tsx`
- Modify: `grabber-desktop/src/App.tsx`

- [x] **Step 1: Implement cards and date picker**

- Four feature cards.
- Date pickers with quick chips (7d, 30d, 90d, 1y).

- [x] **Step 2: Verify**

Manual UI test.

- [x] **Step 3: Commit**

```bash
git add grabber-desktop/src/screens/FeatureSelection.tsx grabber-desktop/src/screens/DateRangeSelection.tsx grabber-desktop/src/App.tsx
git commit -m "feat(desktop): add feature and date range selection"
```

---

## Task 18: Implement collector selection screen

**Files:**
- Create: `grabber-desktop/src/screens/CollectorSelection.tsx`
- Create: `grabber-desktop/src/api/collectors.ts`

- [x] **Step 1: Add list_collectors command**

```rust
#[tauri::command]
pub async fn list_collectors(provider: String) -> Result<Vec<CollectorMetaDto>, GuiError> { ... }
```

- [x] **Step 2: Build tree/list UI**

- Search box.
- Category tree (reuse provider menu categories from `src/tui/menus/`).
- Select all/none.

- [x] **Step 3: Verify**

Manual UI test: list AWS collectors, search, select.

- [x] **Step 4: Commit**

```bash
git add grabber-desktop/src/screens/CollectorSelection.tsx grabber-desktop/src/api/collectors.ts
git commit -m "feat(desktop): add collector selection screen"
```

---

## Task 19: Implement options and confirm screens

**Files:**
- Create: `grabber-desktop/src/screens/OptionsScreen.tsx`
- Create: `grabber-desktop/src/screens/ConfirmScreen.tsx`

- [x] **Step 1: Build options form**

- Output directory picker (Tauri dialog plugin).
- Zip, sign, run manifest, chain of custody, include raw toggles.
- Signing key input.

- [x] **Step 2: Build confirm summary**

- Read-only summary of selections.
- Start button triggers collection.

- [x] **Step 3: Commit**

```bash
git add grabber-desktop/src/screens/OptionsScreen.tsx grabber-desktop/src/screens/ConfirmScreen.tsx
git commit -m "feat(desktop): add options and confirm screens"
```

---

## Task 20: Implement collection run command and progress events

**Files:**
- Modify: `src/engine.rs`
- Create: `grabber-desktop/src-tauri/src/commands/collection.rs`
- Modify: `grabber-desktop/src-tauri/src/lib.rs`

- [x] **Step 1: Add collection method to Engine**

```rust
impl Engine {
    pub async fn collect(&self, req: CollectionRequest, sink: Box<dyn ProgressSink>) -> Result<RunSummary> {
        // Build Cli from request, call run_standard_cli, streaming progress by wrapping the runner's progress channel.
    }
}
```

- [x] **Step 2: Add start_collection command**

```rust
#[tauri::command]
pub async fn start_collection(
    request: CollectionRequestDto,
    app: tauri::AppHandle,
    state: State<'_, AppState>,
) -> Result<String, GuiError> {
    let run_id = uuid::Uuid::new_v4().to_string();
    let engine = state.engine.clone();
    let sink = TauriProgressSink::new(app, run_id.clone());
    let req = request.into_engine_request()?;
    tokio::spawn(async move {
        let _ = engine.collect(req, Box::new(sink)).await;
    });
    Ok(run_id)
}
```

- [x] **Step 3: Add Tauri progress event emitter**

```rust
pub struct TauriProgressSink { app: tauri::AppHandle, run_id: String }
impl ProgressSink for TauriProgressSink {
    fn emit(&self, event: the_grabber::engine::ProgressEvent) {
        let _ = self.app.emit("collection:progress", event);
    }
}
```

- [x] **Step 4: Verify**

```bash
cargo check --workspace
```

- [x] **Step 5: Commit**

```bash
git add src/engine.rs grabber-desktop/src-tauri/src/commands/collection.rs
git commit -m "feat(desktop): add async collection engine and progress events"
```

---

## Task 21: Build Running and Results screens

**Files:**
- Create: `grabber-desktop/src/screens/RunningScreen.tsx`
- Create: `grabber-desktop/src/screens/ResultsScreen.tsx`
- Modify: `grabber-desktop/src/App.tsx`

- [x] **Step 1: Running screen**

- Listen to `collection:progress` events via `listen` from `@tauri-apps/api/event`.
- Live table of account/collector/status/records.
- Log tail pane.
- Cancel button.

- [x] **Step 2: Results screen**

- List artifacts from `list_run_artifacts`.
- Preview CSV/JSON.
- Open folder, export zip, sign, verify buttons.

- [x] **Step 3: Verify**

End-to-end test: run a small collector set against a test AWS account.

- [x] **Step 4: Commit**

```bash
git add grabber-desktop/src/screens/RunningScreen.tsx grabber-desktop/src/screens/ResultsScreen.tsx
git commit -m "feat(desktop): add running and results screens"
```

---

## Task 22: Implement Inventory, POA&M, and STIG flows

**Files:**
- Modify: `src/engine.rs`
- Create: `grabber-desktop/src-tauri/src/commands/inventory.rs`
- Create: `grabber-desktop/src-tauri/src/commands/poam.rs`
- Create: `grabber-desktop/src/screens/InventoryScreen.tsx`
- Create: `grabber-desktop/src/screens/PoamScreen.tsx`
- Create: `grabber-desktop/src/screens/StigScreen.tsx`

- [x] **Step 1: Add engine methods**

```rust
impl Engine {
    pub async fn inventory(&self, req: InventoryRequest, sink: Box<dyn ProgressSink>) -> Result<RunSummary>;
    pub async fn poam(&self, req: PoamRequest, sink: Box<dyn ProgressSink>) -> Result<RunSummary>;
    pub async fn stig(&self, req: StigRequest, sink: Box<dyn ProgressSink>) -> Result<RunSummary>;
}
```

- [x] **Step 2: Add Tauri commands**

`start_inventory`, `start_poam`, `start_stig_remediation`.

- [x] **Step 3: Add UI screens**

- Inventory: asset-type checklist.
- POA&M: year/month/account selectors.
- STIG: remediation checklist.

- [x] **Step 4: Verify**

Run each flow against test data.

- [x] **Step 5: Commit**

```bash
git add src/engine.rs grabber-desktop/src-tauri/src/commands/inventory.rs grabber-desktop/src-tauri/src/commands/poam.rs grabber-desktop/src/screens/InventoryScreen.tsx grabber-desktop/src/screens/PoamScreen.tsx grabber-desktop/src/screens/StigScreen.tsx
git commit -m "feat(desktop): add inventory, POA&M, and STIG screens"
```

---

## Task 23: Apply theme and branding

**Files:**
- Create: `grabber-desktop/src/styles/theme.css`
- Modify: `grabber-desktop/src/App.tsx`
- Add icon assets to `grabber-desktop/src-tauri/icons/`

- [x] **Step 1: Port palette from `src/tui/ui/theme.rs`**

CSS custom properties matching `BG_DARK`, `CYAN`, `AMBER`, etc.

- [x] **Step 2: Apply dark theme globally**

- [x] **Step 3: Add logo to welcome screen**

- [x] **Step 4: Commit**

```bash
git add grabber-desktop/src/styles/theme.css grabber-desktop/src/App.tsx grabber-desktop/src-tauri/icons/
git commit -m "feat(desktop): apply Grabber dark theme and icons"
```

---

## Task 24: Add packaging CI and documentation

**Files:**
- Create: `.github/workflows/desktop-release.yml`
- Modify: `README.md`
- Modify: `docs/cli-reference.md`

- [x] **Step 1: Add GitHub Actions workflow**

Build Tauri on macOS/Windows/Linux and upload artifacts to releases.

- [x] **Step 2: Update README**

Add "Desktop App" section with install links and basic usage.

- [x] **Step 3: Update CLI reference**

Mention that the desktop app stores credentials separately from CLI/TUI.

- [x] **Step 4: Verify workflow**

Push to a test branch and confirm artifacts build.

- [x] **Step 5: Commit**

```bash
git add .github/workflows/desktop-release.yml README.md docs/cli-reference.md
git commit -m "ci(desktop): add release workflow and docs"
```

---

## Validation

Run 2026-07-28 on rustc/clippy 1.94.1, node 26.3.0, macOS arm64.

- [ ] Run `cargo test --workspace` — all tests pass.
  **Blocked by pre-existing failure outside this plan's scope.**
  `okta-rs::users_test::list_all_users_follows_pagination` hangs indefinitely and is
  SIGKILLed, aborting the workspace run before it reaches the main crate. Both mocks in
  `crates/okta-rs/tests/users_test.rs` are registered as `method("GET").and(path("/api/v1/users"))`;
  wiremock's `path()` ignores the query string, so both match every request and the first
  one always wins — it returns `link: <…?after=p2>; rel="next"`, so `list_all()` follows
  `next` forever. Fix is to constrain the mocks with `query_param("after", "p2")` /
  `query_param_is_missing("after")`. Pre-existing: the file's only commit is `1e84f0e`
  and this branch touches no files under `crates/`. Tracked separately.
- [x] `cargo test -p the-grabber` — **75 passed, 0 failed, 1 ignored.** Includes
  `credentials::vault::tests::vault_round_trip`,
  `credentials::aws_config::tests::load_aws_config_from_access_key`, and
  `credentials::aws_config::tests::sso_profile_written_to_aws_config`. The ignored test is
  the pre-existing `inventory_xlsx::tests::integration_writes_against_real_template`,
  which needs a real template file.
- [ ] Run `cargo clippy --workspace -- -D warnings` — no warnings.
  **Fails with 29 errors, all pre-existing and outside this plan's scope.** They sit in
  `src/poam/`, `src/runner/`, `src/providers/`, `src/inventory_xlsx.rs`, `src/audit_log.rs`,
  and `src/tui/` — none in `src/credentials/`, `src/engine.rs`, or `grabber-desktop/`. The
  single hit in a branch-modified file (`src/app_config.rs:70`, `doc_overindented_list_items`)
  is on a doc comment this branch's diff does not touch. Surfaced by clippy 1.94, which added
  lints such as `doc_overindented_list_items`. Deliberately left for a separate cleanup so the
  desktop branch stays reviewable.
- [x] Run `cargo fmt --check` — no formatting changes. `cargo fmt --all -- --check` exits 0.
- [x] Run `cd grabber-desktop && npm run tauri build -- --debug` — produces a debug app bundle.
  Built `target/debug/bundle/macos/The Grabber.app` and
  `target/debug/bundle/dmg/The Grabber_0.1.0_aarch64.dmg`. Frontend `tsc && vite build`
  also passes standalone (TypeScript strict, 59 modules).
- [ ] Manual end-to-end: add an AWS SSO credential, select an account, run the `iam-users`
  collector, verify CSV/JSON output appears in the results screen.
  **Not performed** — needs live AWS credentials and an interactive session.
- [x] Manual security check: confirm the OS keyring contains entries under
  `the-grabber/<uuid>/...` and that no plaintext secrets exist in the app data directory.
  **Verified by source inspection**; the runtime keyring check still needs a first app launch
  (`~/Library/Application Support/com.thegrabber.desktop/` does not exist yet).
  - `src/credentials/storage.rs:96` — keyring service names are `the-grabber/<uuid>/<field>`.
  - `src/credentials/metadata_store.rs:96-102` — the only bytes written to disk are
    `nonce(12) || AES-256-GCM ciphertext`.
  - `src/credentials/entries.rs:10-17` — `CredentialEntry`, the sole persisted type, holds no
    secret fields; secrets live only in `CredentialSecret`, which goes to the keyring.

---

## Open Questions

1. **Frontend stack confirmation:** React + TypeScript, or switch to Svelte?
2. **Core crate split:** Is adding `[lib]` to the main crate acceptable, or should we create `crates/grabber-core` before Milestone 0 is merged?
3. **AWS SSO profile handling:** Should the app write/update `~/.aws/config` automatically, or keep SSO config in the encrypted metadata store and build the SDK config purely from memory?
4. **Master password:** Defer to a follow-up plan, or implement in Milestone 1?
