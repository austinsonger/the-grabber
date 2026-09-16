# Desktop Credentials & Collection for Non-AWS Providers — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let a desktop user save credentials for Tenable, Okta, Jira, GitHub, Elastic, Jamf and JumpCloud in the credential vault and run a full evidence collection against them, with no `*-config.toml` file on disk.

**Architecture:** The vault already stores arbitrary provider credentials; nothing downstream consumes the non-AWS ones. We add four provider-shaped credential kinds, then a pure mapping function that stamps a vault credential onto the existing `Cli` provider flag structs (`cli.okta.okta_domain`, `cli.tenable.tenable_access_key`, …). `run_provider_cli` already reads those flags and is the single entry point for all seven providers, so the engine gains one `collect_provider` method and the desktop gains one Tauri command. A new `--vault-account` flag makes a provider run ignore `*-config.toml` accounts entirely and collect one tenant under the credential's own name. No environment variables are mutated and no provider collector changes.

**Tech Stack:** Rust (anyhow, tokio, clap, keyring, uuid, serde), Tauri v2, React + TypeScript.

**Spec:** None written; the requirements are the Background section below, agreed with the user on 2026-09-14 (scope: full non-AWS collection workflow; providers: all seven non-AWS providers with credential fields today; Azure/GCP excluded).

## Background — what exists and what is missing

Exists:
- `src/credentials/` — `CredentialVault` (encrypted metadata file + OS keyring secrets), kinds `AwsSso`, `AwsAccessKey`, `AwsProfileReference`, `ApiToken{domain}`, `BasicAuth{host,username}`, `OAuth{domain,client_id}`.
- `src/runner/provider_cli/` — `run_provider_cli(&Cli)` dispatches to per-provider `run()` for Okta, Tenable, Elastic, GitHub, Jira, Jamf, JumpCloud. Each resolves accounts from the merged config, and falls back to CLI-flag/env credentials when **no account of that provider exists in config**.
- `src/cli_providers.rs` — every provider has mode flag, `--<p>-account`, full credential override flags, `--<p>-collectors`, and a public `<P>_COLLECTOR_KEYS` table.
- `grabber-desktop` — Credential Vault screen, `Engine::collect/inventory/poam`, Tauri commands.

Missing (the work):
1. No credential kind matches Tenable (two keys), GitHub (org + base URL), Elastic (two URLs), JumpCloud (org id + base URL). Jira fits `BasicAuth`, Jamf fits `OAuth`, Okta fits `ApiToken`.
2. `Engine::apply_aws_credential` handles AWS only; `Engine::collect` always calls `run_standard_cli` (AWS-only).
3. `list_accounts` (`grabber-desktop/src-tauri/src/commands/accounts.rs:38`) `continue`s on every non-AWS vault credential.
4. `list_collectors` (`.../commands/collectors.rs:5`) ignores its `provider` argument and returns a hard-coded AWS list.
5. A vault credential cannot suppress config accounts: when `*-config.toml` has accounts of that provider, credential flags get layered onto **them** and `guard_credential_overrides` rejects the run.

## Global Constraints

- Errors: `anyhow::Result` / `anyhow::Context`. No `unwrap()`/`expect()` in production code; `anyhow::bail!` for early exits. `unwrap()` in `#[cfg(test)]` code is fine.
- `cargo clippy -- -D warnings` and `cargo fmt` must be clean before every commit.
- Imports grouped std → external crates → `crate::*`, blank line between groups.
- Non-AWS provider code is feature-gated: `tenable`, `okta`, `jira` are default features; `elastic`, `github`, `jamf`, `jumpcloud` are compiled in the default build too (verify with `cargo check` — they are not in `default` in `Cargo.toml` only if `cargo check` fails; in that case gate the new code with `#[cfg(feature = "...")]` exactly as `src/providers/mod.rs` does).
- `CHANGELOG.md` is updated **in the same commit** as the code, under `## [Unreleased]`, in `Added`/`Changed`/`Fixed`. Never invent a version number. No real account IDs, domains, org names or tokens in entries — use `example.okta.com`, `123456789012`, `acme-org`.
- Secrets never appear in log output, error messages, `Debug` output shown to the user, or the encrypted metadata file. Only non-secret identifiers (domain, org, base URL, access key id, client id, username) go in `CredentialKind`; every secret goes in `CredentialSecret`, which is `Zeroize`.
- Git: commit on `main`, author "Austin Songer" `<asonger.pixel@gmail.com>`, no co-author trailers.
- The desktop app must keep building: `cd grabber-desktop && npm run build` (TypeScript) and `cargo check --manifest-path grabber-desktop/src-tauri/Cargo.toml`.

## File Structure

| File | Responsibility |
|---|---|
| `src/credentials/entries.rs` (modify) | Add 4 `CredentialKind` variants + 1 `CredentialSecret` variant; extend `CredentialMeta` accessors. |
| `src/credentials/storage.rs` (modify) | Keyring field names for the new kinds. |
| `src/credentials/vault.rs` (modify, tests) | Extend the in-memory test backend to the new secret. |
| `src/credentials/provider_flags.rs` (create) | `apply_credential_to_cli(&CredentialEntry, &CredentialSecret, &mut Cli) -> Result<()>` — the single credential→flags mapping, plus its unit tests. |
| `src/credentials/mod.rs` (modify) | Declare and re-export `provider_flags`. |
| `src/cli.rs` (modify) | Add `vault_account: Option<String>`. |
| `src/runner/provider_cli/mod.rs` (modify) | `accounts_for_run(cli, provider, name)` — returns empty when `--vault-account` is set; `vault_account_name(cli)`. |
| `src/runner/provider_cli/{okta,tenable,elastic,github,jira,jamf,jumpcloud}.rs` (modify) | Two-line change each: use `accounts_for_run`, and name the fallback target from `--vault-account`. |
| `src/engine.rs` (modify) | `ProviderCollectionRequest` + `Engine::collect_provider`. |
| `grabber-desktop/src-tauri/src/dto.rs` (modify) | New `CredentialWriteDto` fields, `ProviderCollectionRequestDto`. |
| `grabber-desktop/src-tauri/src/commands/credentials.rs` (modify) | Parse the new kinds. |
| `grabber-desktop/src-tauri/src/commands/accounts.rs` (modify) | Surface non-AWS vault credentials as accounts. |
| `grabber-desktop/src-tauri/src/commands/collectors.rs` (modify) | Per-provider collector catalog from the `<P>_COLLECTOR_KEYS` tables. |
| `grabber-desktop/src-tauri/src/commands/collection.rs` (modify) | `start_provider_collection` command. |
| `grabber-desktop/src-tauri/src/lib.rs` (modify) | Register the new command. |
| `grabber-desktop/src/api/credentials.ts`, `api/collection.ts` (modify) | DTO fields + `startProviderCollection`. |
| `grabber-desktop/src/components/CredentialForm.tsx` (modify) | Provider-driven kind list and fields. |
| `grabber-desktop/src/App.tsx` (modify) | Route non-AWS accounts past region selection into the provider run. |

---

### Task 1: Provider-shaped credential kinds

Four new kinds. Jira reuses `BasicAuth` (host = Jira domain, username = email, password = API token), Jamf reuses `OAuth` (domain = Jamf base URL), Okta reuses `ApiToken`.

**Files:**
- Modify: `src/credentials/entries.rs`
- Modify: `src/credentials/storage.rs`
- Modify: `src/credentials/vault.rs` (test backend + a new test)
- Modify: `CHANGELOG.md`

**Interfaces:**
- Consumes: nothing.
- Produces: `CredentialKind::{TenableKeys{base_url}, GithubToken{org, base_url}, ElasticApiKey{kibana_url, es_url}, JumpCloudKey{org_id, base_url}}`; `CredentialSecret::TenableKeys{access_key, secret_key}`; `CredentialMeta.base_url: Option<String>` and `CredentialMeta.org: Option<String>`; kind tags `"tenable_keys"`, `"github_token"`, `"elastic_api_key"`, `"jumpcloud_key"`.

- [ ] **Step 1: Write the failing test**

Append inside the existing `mod tests` in `src/credentials/vault.rs`:

```rust
    #[test]
    fn tenable_keys_round_trip() {
        let dir = tempdir().unwrap();
        let metadata =
            EncryptedMetadataStore::open(dir.path().join("credentials.enc.json")).unwrap();
        let vault = CredentialVault::new(metadata, Box::new(MemoryStorage::default()));
        let meta = vault
            .create(NewCredential {
                name: "Tenable Prod".into(),
                provider: CloudProvider::Tenable,
                kind: CredentialKind::TenableKeys {
                    base_url: "https://cloud.tenable.com".into(),
                },
                secret: CredentialSecret::TenableKeys {
                    access_key: "ak".into(),
                    secret_key: "sk".into(),
                },
            })
            .unwrap();

        assert_eq!(meta.kind_tag, "tenable_keys");
        assert_eq!(meta.base_url.as_deref(), Some("https://cloud.tenable.com"));

        let (_entry, secret) = vault.get(meta.id).unwrap().unwrap();
        match &secret {
            CredentialSecret::TenableKeys {
                access_key,
                secret_key,
            } => {
                assert_eq!(access_key, "ak");
                assert_eq!(secret_key, "sk");
            }
            _ => panic!("wrong secret type"),
        }
    }

    #[test]
    fn github_token_meta_exposes_org_and_base_url() {
        let dir = tempdir().unwrap();
        let metadata =
            EncryptedMetadataStore::open(dir.path().join("credentials.enc.json")).unwrap();
        let vault = CredentialVault::new(metadata, Box::new(MemoryStorage::default()));
        let meta = vault
            .create(NewCredential {
                name: "GitHub".into(),
                provider: CloudProvider::Github,
                kind: CredentialKind::GithubToken {
                    org: "acme-org".into(),
                    base_url: "https://api.github.com".into(),
                },
                secret: CredentialSecret::ApiToken {
                    token: "ghp_xxx".into(),
                },
            })
            .unwrap();

        assert_eq!(meta.kind_tag, "github_token");
        assert_eq!(meta.org.as_deref(), Some("acme-org"));
        assert_eq!(meta.base_url.as_deref(), Some("https://api.github.com"));
    }
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test --lib credentials::vault -- --nocapture`
Expected: FAIL — `no variant named TenableKeys found for enum CredentialKind`.

- [ ] **Step 3: Add the kinds and the secret variant**

In `src/credentials/entries.rs`, add to `enum CredentialKind` (after `OAuth`):

```rust
    TenableKeys {
        base_url: String,
    },
    GithubToken {
        org: String,
        base_url: String,
    },
    ElasticApiKey {
        kibana_url: String,
        es_url: String,
    },
    JumpCloudKey {
        org_id: String,
        base_url: String,
    },
```

Add to `enum CredentialSecret` (before `None`):

```rust
    TenableKeys {
        access_key: String,
        secret_key: String,
    },
```

Extend `CredentialKind::type_tag`:

```rust
            CredentialKind::TenableKeys { .. } => "tenable_keys",
            CredentialKind::GithubToken { .. } => "github_token",
            CredentialKind::ElasticApiKey { .. } => "elastic_api_key",
            CredentialKind::JumpCloudKey { .. } => "jumpcloud_key",
```

Add two accessors next to the existing private ones:

```rust
    /// Primary base URL for the provider kinds that carry one.
    fn base_url(&self) -> Option<&str> {
        match self {
            CredentialKind::TenableKeys { base_url }
            | CredentialKind::GithubToken { base_url, .. }
            | CredentialKind::JumpCloudKey { base_url, .. } => Some(base_url),
            CredentialKind::ElasticApiKey { kibana_url, .. } => Some(kibana_url),
            _ => None,
        }
    }

    /// Organisation identifier: GitHub org or JumpCloud org id.
    fn org(&self) -> Option<&str> {
        match self {
            CredentialKind::GithubToken { org, .. } => Some(org),
            CredentialKind::JumpCloudKey { org_id, .. } => Some(org_id),
            _ => None,
        }
    }
```

Add to `struct CredentialMeta` (after `profile_name`):

```rust
    pub base_url: Option<String>,
    pub org: Option<String>,
```

and populate them in `CredentialEntry::meta`:

```rust
            base_url: self.kind.base_url().map(|s| s.to_string()),
            org: self.kind.org().map(|s| s.to_string()),
```

- [ ] **Step 4: Teach the keyring backend the new secret fields**

In `src/credentials/storage.rs`, add to `KeyringStorage::entries_for`:

```rust
            CredentialKind::TenableKeys { .. } => vec![
                (
                    format!("{base}/tenable_access_key"),
                    "Tenable Access Key".into(),
                ),
                (
                    format!("{base}/tenable_secret_key"),
                    "Tenable Secret Key".into(),
                ),
            ],
            CredentialKind::GithubToken { .. }
            | CredentialKind::ElasticApiKey { .. }
            | CredentialKind::JumpCloudKey { .. } => {
                vec![(format!("{base}/token"), "API Token".into())]
            }
```

In `SecretStorage::store` for `KeyringStorage`, add match arms before `(_, CredentialSecret::None)`:

```rust
            (
                CredentialKind::TenableKeys { .. },
                CredentialSecret::TenableKeys {
                    access_key,
                    secret_key,
                },
            ) => [
                ("tenable_access_key", access_key.as_str()),
                ("tenable_secret_key", secret_key.as_str()),
            ]
            .into_iter()
            .collect(),
            (
                CredentialKind::GithubToken { .. }
                | CredentialKind::ElasticApiKey { .. }
                | CredentialKind::JumpCloudKey { .. },
                CredentialSecret::ApiToken { token },
            ) => [("token", token.as_str())].into_iter().collect(),
```

In `SecretStorage::load`, add before the `_ =>` arm:

```rust
            CredentialKind::TenableKeys { .. } => CredentialSecret::TenableKeys {
                access_key: values.remove("tenable_access_key").unwrap_or_default(),
                secret_key: values.remove("tenable_secret_key").unwrap_or_default(),
            },
            CredentialKind::GithubToken { .. }
            | CredentialKind::ElasticApiKey { .. }
            | CredentialKind::JumpCloudKey { .. } => CredentialSecret::ApiToken {
                token: values.remove("token").unwrap_or_default(),
            },
```

- [ ] **Step 5: Teach the in-memory test backend the same fields**

In `src/credentials/vault.rs`, inside `mod tests`, add to `MemoryStorage::store`'s match on `secret`:

```rust
                CredentialSecret::TenableKeys {
                    access_key,
                    secret_key,
                } => {
                    data.insert(
                        format!("{credential_id}/tenable_access_key"),
                        access_key.clone(),
                    );
                    data.insert(
                        format!("{credential_id}/tenable_secret_key"),
                        secret_key.clone(),
                    );
                }
```

and to `MemoryStorage::load`'s match on `kind`, before `_ =>`:

```rust
                CredentialKind::TenableKeys { .. } => CredentialSecret::TenableKeys {
                    access_key: data
                        .get(&format!("{credential_id}/tenable_access_key"))
                        .cloned()
                        .unwrap_or_default(),
                    secret_key: data
                        .get(&format!("{credential_id}/tenable_secret_key"))
                        .cloned()
                        .unwrap_or_default(),
                },
                CredentialKind::GithubToken { .. }
                | CredentialKind::ElasticApiKey { .. }
                | CredentialKind::JumpCloudKey { .. } => CredentialSecret::ApiToken {
                    token: data
                        .get(&format!("{credential_id}/token"))
                        .cloned()
                        .unwrap_or_default(),
                },
```

- [ ] **Step 6: Run the tests and the compile check**

Run: `cargo test --lib credentials:: && cargo clippy -- -D warnings && cargo fmt`
Expected: PASS, clippy clean. If `grabber-desktop/src-tauri` fails to build because `CredentialMetaDto` construction is now missing fields, leave it — Task 5 fixes it; but `cargo check` on the root crate must pass.

- [ ] **Step 7: Changelog**

Add under `## [Unreleased]` → `### Added` in `CHANGELOG.md`:

```markdown
- Credential vault: new credential types for Tenable (access key + secret key), GitHub (org + token + API base URL), Elastic (Kibana URL + Elasticsearch URL + API key), and JumpCloud (API key + org ID). Secrets are stored in the OS keyring like the existing types; only the URLs and identifiers are written to the vault metadata file.
```

- [ ] **Step 8: Commit**

```bash
git add src/credentials/entries.rs src/credentials/storage.rs src/credentials/vault.rs CHANGELOG.md
git commit -m "feat(credentials): add Tenable, GitHub, Elastic and JumpCloud credential kinds"
```

---

### Task 2: Map a vault credential onto the provider CLI flags

The one place that knows how each credential kind becomes provider flags.

**Files:**
- Create: `src/credentials/provider_flags.rs`
- Modify: `src/credentials/mod.rs`
- Modify: `CHANGELOG.md`

**Interfaces:**
- Consumes: `CredentialKind`/`CredentialSecret` from Task 1; `crate::cli::Cli` and its flattened flag structs (`cli.okta.okta_domain`, `cli.tenable.tenable_access_key`, `cli.elastic.elastic_kibana_url`, `cli.github.github_org`, `cli.jira.jira_email`, `cli.jamf.jamf_client_id`, `cli.jumpcloud.jumpcloud_org_id`, and each `<p>_enabled` bool).
- Produces: `pub fn apply_credential_to_cli(entry: &CredentialEntry, secret: &CredentialSecret, cli: &mut Cli) -> anyhow::Result<()>`.

- [ ] **Step 1: Write the failing test**

Create `src/credentials/provider_flags.rs` containing only its test module for now:

```rust
#[cfg(test)]
mod tests {
    use chrono::Utc;
    use uuid::Uuid;

    use super::apply_credential_to_cli;
    use crate::cli::Cli;
    use crate::credentials::{CredentialEntry, CredentialKind, CredentialSecret};
    use crate::providers::CloudProvider;

    fn entry(provider: CloudProvider, kind: CredentialKind) -> CredentialEntry {
        let now = Utc::now();
        CredentialEntry {
            id: Uuid::new_v4(),
            name: "Cred".into(),
            provider,
            kind,
            created_at: now,
            updated_at: now,
        }
    }

    #[test]
    fn okta_api_token_sets_domain_and_token() {
        let mut cli = Cli::default();
        let e = entry(
            CloudProvider::Okta,
            CredentialKind::ApiToken {
                domain: "https://example.okta.com".into(),
            },
        );
        let s = CredentialSecret::ApiToken {
            token: "ssws-token".into(),
        };

        apply_credential_to_cli(&e, &s, &mut cli).unwrap();

        assert!(cli.okta.okta_enabled);
        assert_eq!(cli.okta.okta_domain.as_deref(), Some("https://example.okta.com"));
        assert_eq!(cli.okta.okta_api_token.as_deref(), Some("ssws-token"));
    }

    #[test]
    fn tenable_keys_set_both_keys_and_url() {
        let mut cli = Cli::default();
        let e = entry(
            CloudProvider::Tenable,
            CredentialKind::TenableKeys {
                base_url: "https://cloud.tenable.com".into(),
            },
        );
        let s = CredentialSecret::TenableKeys {
            access_key: "ak".into(),
            secret_key: "sk".into(),
        };

        apply_credential_to_cli(&e, &s, &mut cli).unwrap();

        assert!(cli.tenable.tenable_enabled);
        assert_eq!(cli.tenable.tenable_url.as_deref(), Some("https://cloud.tenable.com"));
        assert_eq!(cli.tenable.tenable_access_key.as_deref(), Some("ak"));
        assert_eq!(cli.tenable.tenable_secret_key.as_deref(), Some("sk"));
    }

    #[test]
    fn jira_basic_auth_maps_to_domain_email_token() {
        let mut cli = Cli::default();
        let e = entry(
            CloudProvider::Jira,
            CredentialKind::BasicAuth {
                host: "https://acme.atlassian.net".into(),
                username: "svc@example.com".into(),
            },
        );
        let s = CredentialSecret::BasicAuth {
            password: "jira-token".into(),
        };

        apply_credential_to_cli(&e, &s, &mut cli).unwrap();

        assert!(cli.jira.jira_enabled);
        assert_eq!(cli.jira.jira_domain.as_deref(), Some("https://acme.atlassian.net"));
        assert_eq!(cli.jira.jira_email.as_deref(), Some("svc@example.com"));
        assert_eq!(cli.jira.jira_api_token.as_deref(), Some("jira-token"));
    }

    #[test]
    fn aws_credential_is_rejected() {
        let mut cli = Cli::default();
        let e = entry(
            CloudProvider::Aws,
            CredentialKind::AwsProfileReference {
                profile_name: "prod".into(),
            },
        );
        let err = apply_credential_to_cli(&e, &CredentialSecret::None, &mut cli).unwrap_err();
        assert!(err.to_string().contains("AWS"));
    }

    #[test]
    fn provider_and_kind_mismatch_is_rejected() {
        let mut cli = Cli::default();
        let e = entry(
            CloudProvider::Tenable,
            CredentialKind::ApiToken {
                domain: "https://example.okta.com".into(),
            },
        );
        let s = CredentialSecret::ApiToken {
            token: "t".into(),
        };
        let err = apply_credential_to_cli(&e, &s, &mut cli).unwrap_err();
        assert!(err.to_string().contains("Tenable"));
    }
}
```

Declare the module in `src/credentials/mod.rs`:

```rust
pub mod provider_flags;
```

and add the re-export next to the others:

```rust
pub use provider_flags::*;
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test --lib credentials::provider_flags`
Expected: FAIL — `cannot find function apply_credential_to_cli`.

- [ ] **Step 3: Write the mapping**

Prepend to `src/credentials/provider_flags.rs`, above the test module:

```rust
//! Map a stored vault credential onto the headless-CLI provider flags.
//!
//! `run_provider_cli` already resolves credentials from these flags, so this is
//! the whole of the desktop's non-AWS credential plumbing: no environment
//! variables are set and no provider collector is aware of the vault.

use anyhow::{bail, Result};

use crate::cli::Cli;
use crate::credentials::{CredentialEntry, CredentialKind, CredentialSecret};
use crate::providers::CloudProvider;

/// Stamp `entry`'s credential onto the provider flag group `cli` that matches
/// its provider, and turn that provider's mode flag on.
///
/// Errors when the credential is an AWS one (those go through
/// `Engine::apply_aws_credential`) or when the stored kind does not match the
/// provider it is filed under.
pub fn apply_credential_to_cli(
    entry: &CredentialEntry,
    secret: &CredentialSecret,
    cli: &mut Cli,
) -> Result<()> {
    match (entry.provider, &entry.kind, secret) {
        (
            CloudProvider::Okta,
            CredentialKind::ApiToken { domain },
            CredentialSecret::ApiToken { token },
        ) => {
            cli.okta.okta_enabled = true;
            cli.okta.okta_domain = Some(domain.clone());
            cli.okta.okta_api_token = Some(token.clone());
        }
        (
            CloudProvider::Tenable,
            CredentialKind::TenableKeys { base_url },
            CredentialSecret::TenableKeys {
                access_key,
                secret_key,
            },
        ) => {
            cli.tenable.tenable_enabled = true;
            cli.tenable.tenable_url = Some(base_url.clone());
            cli.tenable.tenable_access_key = Some(access_key.clone());
            cli.tenable.tenable_secret_key = Some(secret_key.clone());
        }
        (
            CloudProvider::Jira,
            CredentialKind::BasicAuth { host, username },
            CredentialSecret::BasicAuth { password },
        ) => {
            cli.jira.jira_enabled = true;
            cli.jira.jira_domain = Some(host.clone());
            cli.jira.jira_email = Some(username.clone());
            cli.jira.jira_api_token = Some(password.clone());
        }
        (
            CloudProvider::Github,
            CredentialKind::GithubToken { org, base_url },
            CredentialSecret::ApiToken { token },
        ) => {
            cli.github.github_enabled = true;
            cli.github.github_org = Some(org.clone());
            cli.github.github_base_url = Some(base_url.clone());
            cli.github.github_token = Some(token.clone());
        }
        (
            CloudProvider::Elastic,
            CredentialKind::ElasticApiKey {
                kibana_url,
                es_url,
            },
            CredentialSecret::ApiToken { token },
        ) => {
            cli.elastic.elastic_enabled = true;
            cli.elastic.elastic_kibana_url = Some(kibana_url.clone());
            cli.elastic.elastic_es_url = Some(es_url.clone());
            cli.elastic.elastic_api_key = Some(token.clone());
        }
        (
            CloudProvider::Jamf,
            CredentialKind::OAuth { domain, client_id },
            CredentialSecret::OAuth { client_secret },
        ) => {
            cli.jamf.jamf_enabled = true;
            cli.jamf.jamf_base_url = Some(domain.clone());
            cli.jamf.jamf_client_id = Some(client_id.clone());
            cli.jamf.jamf_client_secret = Some(client_secret.clone());
        }
        (
            CloudProvider::Jumpcloud,
            CredentialKind::JumpCloudKey { org_id, base_url },
            CredentialSecret::ApiToken { token },
        ) => {
            cli.jumpcloud.jumpcloud_enabled = true;
            cli.jumpcloud.jumpcloud_base_url = Some(base_url.clone());
            cli.jumpcloud.jumpcloud_org_id = Some(org_id.clone());
            cli.jumpcloud.jumpcloud_api_key = Some(token.clone());
        }
        (CloudProvider::Aws, _, _) => bail!(
            "Credential '{}' is an AWS credential; AWS runs use the standard collection path",
            entry.name
        ),
        (provider, kind, _) => bail!(
            "Credential '{}' is filed under {:?} but stores a '{}' credential, which {:?} \
             cannot use. Re-create it with the credential type for that provider.",
            entry.name,
            provider,
            kind.type_tag(),
            provider
        ),
    }
    Ok(())
}
```

Note on names: `CloudProvider` variant spellings must match `src/providers/mod.rs` exactly (`Github` vs `GitHub`, `Jumpcloud` vs `JumpCloud`). Check that file and fix the arms if the spellings differ — the compiler will say so.

- [ ] **Step 4: Run the tests**

Run: `cargo test --lib credentials::provider_flags && cargo clippy -- -D warnings && cargo fmt`
Expected: PASS, clippy clean.

- [ ] **Step 5: Commit**

```bash
git add src/credentials/provider_flags.rs src/credentials/mod.rs
git commit -m "feat(credentials): map vault credentials onto provider CLI flags"
```

No changelog entry: nothing is observable outside the codebase yet.

---

### Task 3: `--vault-account` — run one tenant, ignoring config accounts

Today a provider run with credential overrides gets those overrides layered onto the `*-config.toml` accounts, and `guard_credential_overrides` rejects the run outright when more than one exists. A vault credential is a self-contained tenant and must bypass config accounts entirely.

**Files:**
- Modify: `src/cli.rs`
- Modify: `src/runner/provider_cli/mod.rs`
- Modify: `src/runner/provider_cli/{okta,tenable,elastic,github,jira,jamf,jumpcloud}.rs`
- Modify: `CHANGELOG.md`

**Interfaces:**
- Consumes: `Cli`, `accounts_for`.
- Produces: `Cli.vault_account: Option<String>`; `pub(crate) fn accounts_for_run(cli: &Cli, provider: CloudProvider, name: Option<&str>) -> Result<Vec<Account>>`.

- [ ] **Step 1: Write the failing test**

Append to `src/runner/provider_cli/mod.rs` (create the `mod tests` block if absent):

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::Cli;

    #[test]
    fn vault_account_suppresses_config_accounts() {
        let cli = Cli {
            vault_account: Some("Okta Prod".into()),
            ..Cli::default()
        };
        let accounts = accounts_for_run(&cli, CloudProvider::Okta, None).unwrap();
        assert!(
            accounts.is_empty(),
            "--vault-account must bypass config.toml accounts so the vault credential \
             is not layered onto them"
        );
    }
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `cargo test --lib runner::provider_cli::tests::vault_account_suppresses_config_accounts`
Expected: FAIL — `Cli` has no field `vault_account` / `accounts_for_run` not found.

- [ ] **Step 3: Add the flag**

In `src/cli.rs`, add to `struct Cli` next to the other top-level options (keep the field out of the provider flag groups so every provider shares it):

```rust
    /// Run one provider tenant supplied entirely by credential flags, under
    /// this display name, ignoring any [[account]] entries in the config files.
    /// Set by the desktop app when a run is driven by a vault credential.
    #[arg(long)]
    pub vault_account: Option<String>,
```

`Cli` derives `Default`, so no other change is needed there.

- [ ] **Step 4: Add the helper**

In `src/runner/provider_cli/mod.rs`, next to `accounts_for`:

```rust
/// `accounts_for`, except that a `--vault-account` run reports no config
/// accounts at all. Each provider's `run` then takes its single-target
/// fallback branch and builds that target from the credential flags.
pub(crate) fn accounts_for_run(
    cli: &Cli,
    provider: CloudProvider,
    name: Option<&str>,
) -> Result<Vec<Account>> {
    if cli.vault_account.is_some() {
        return Ok(Vec::new());
    }
    accounts_for(provider, name)
}
```

- [ ] **Step 5: Switch the seven provider runs over**

In each of `okta.rs`, `tenable.rs`, `elastic.rs`, `github.rs`, `jira.rs`, `jamf.rs`, `jumpcloud.rs`, make exactly two changes.

(a) Replace the accounts lookup. In `okta.rs` the line is:

```rust
    let accounts = super::accounts_for(CloudProvider::Okta, cli.okta.okta_account.as_deref())?;
```

becomes

```rust
    let accounts =
        super::accounts_for_run(cli, CloudProvider::Okta, cli.okta.okta_account.as_deref())?;
```

Do the same in the other six, keeping each file's own `CloudProvider` variant and `<p>_account` field.

(b) Name the fallback target from the flag. In `okta.rs` the fallback branch is:

```rust
        let name = cli
            .okta
            .okta_account
            .clone()
            .unwrap_or_else(|| "Okta".to_string());
```

becomes

```rust
        let name = cli
            .vault_account
            .clone()
            .or_else(|| cli.okta.okta_account.clone())
            .unwrap_or_else(|| "Okta".to_string());
```

Do the same in the other six, keeping each file's default literal (`"Tenable"`, `"Elastic"`, `"GitHub"`, `"Jira"`, `"Jamf"`, `"JumpCloud"` — use whatever string that file already has).

- [ ] **Step 6: Run the tests**

Run: `cargo test --lib runner::provider_cli && cargo clippy -- -D warnings && cargo fmt`
Expected: PASS, clippy clean.

- [ ] **Step 7: Changelog**

Under `## [Unreleased]` → `### Added`:

```markdown
- `--vault-account <name>`: run a single provider tenant from credential flags (`--okta-domain`, `--tenable-access-key`, …) under that display name, ignoring every `[[account]]` in `config.toml` and the per-provider config files. Evidence is written to `{output}/{name}/{YYYY}/{MM-MMM}/` as usual. The desktop app sets this when a run is driven by a saved credential.
```

- [ ] **Step 8: Commit**

```bash
git add src/cli.rs src/runner/provider_cli CHANGELOG.md
git commit -m "feat(cli): add --vault-account to run one provider tenant from credential flags"
```

---

### Task 4: `Engine::collect_provider`

**Files:**
- Modify: `src/engine.rs`
- Modify: `CHANGELOG.md`

**Interfaces:**
- Consumes: `apply_credential_to_cli` (Task 2), `Cli.vault_account` (Task 3), `crate::runner::provider_cli::run_provider_cli`.
- Produces: `pub struct ProviderCollectionRequest { run_id, account_name, credential_id, start_date, end_date, collectors, output_dir, zip, sign, include_raw, write_run_manifest, write_chain_of_custody, signing_key }` and `pub async fn Engine::collect_provider(&self, req: ProviderCollectionRequest, sink: Box<dyn ProgressSink>) -> Result<RunSummary>`.

- [ ] **Step 1: Add the request type**

Append to `src/engine.rs`, next to `CollectionRequest`:

```rust
/// Request to run a non-AWS provider's evidence collection from a vault
/// credential. There are no regions: every non-AWS provider is a single tenant.
#[derive(Debug, Clone)]
pub struct ProviderCollectionRequest {
    pub run_id: String,
    /// Display name for the run; becomes the evidence output directory.
    pub account_name: String,
    pub credential_id: String,
    pub start_date: String,
    pub end_date: String,
    /// Provider collector keys (e.g. `okta-users`). Empty means every
    /// collector for that provider.
    pub collectors: Vec<String>,
    pub output_dir: PathBuf,
    pub zip: bool,
    pub sign: bool,
    pub include_raw: bool,
    pub write_run_manifest: bool,
    pub write_chain_of_custody: bool,
    pub signing_key: Option<String>,
}
```

- [ ] **Step 2: Add the method**

Inside `impl Engine`, after `collect`:

```rust
    /// Run a non-AWS provider's evidence collection against a stored credential.
    ///
    /// The credential is stamped onto the provider flag group that matches it,
    /// and `--vault-account` makes the run ignore config-file accounts, so the
    /// desktop can collect from a tenant that has no `*-config.toml` entry.
    pub async fn collect_provider(
        &self,
        req: ProviderCollectionRequest,
        sink: Box<dyn ProgressSink>,
    ) -> Result<RunSummary> {
        let credential_id = Uuid::parse_str(&req.credential_id).context("Invalid credential id")?;
        let (entry, secret) = self
            .vault
            .get(credential_id)
            .context("Failed to load credential")?
            .context("Credential not found")?;

        let mut cli = Cli {
            start_date: Some(req.start_date.clone()),
            end_date: Some(req.end_date.clone()),
            output: Some(req.output_dir.clone()),
            vault_account: Some(req.account_name.clone()),
            include_raw: req.include_raw,
            zip: req.zip,
            sign: req.sign,
            signing_key: req.signing_key.clone(),
            write_run_manifest: req.write_run_manifest,
            write_chain_of_custody: req.write_chain_of_custody,
            ..Cli::default()
        };
        crate::credentials::apply_credential_to_cli(&entry, &secret, &mut cli)?;
        set_provider_collectors(&mut cli, &req.collectors);

        sink.emit(ProgressEvent {
            run_id: req.run_id.clone(),
            account: req.account_name.clone(),
            region: None,
            collector: "all".into(),
            status: "started".into(),
            records: 0,
            message: Some(format!("{} collection started", entry.provider)),
        });

        crate::runner::provider_cli::run_provider_cli(&cli)
            .await
            .context("Provider collection run failed")?;

        sink.emit(ProgressEvent {
            run_id: req.run_id.clone(),
            account: req.account_name.clone(),
            region: None,
            collector: "all".into(),
            status: "finished".into(),
            records: 0,
            message: Some("Collection run finished".into()),
        });

        Ok(RunSummary {
            run_id: req.run_id,
            account: req.account_name,
            regions: Vec::new(),
            collectors: req.collectors.len(),
            output_dir: req.output_dir,
        })
    }
```

And, as a free function at the bottom of `src/engine.rs`:

```rust
/// Put the selected collector keys into whichever provider's `--<p>-collectors`
/// list is active. An empty selection is left as `None`, which the provider CLI
/// reads as "every collector".
fn set_provider_collectors(cli: &mut Cli, keys: &[String]) {
    if keys.is_empty() {
        return;
    }
    let keys = Some(keys.to_vec());
    if cli.okta.okta_enabled {
        cli.okta.okta_collectors = keys;
    } else if cli.tenable.tenable_enabled {
        cli.tenable.tenable_collectors = keys;
    } else if cli.elastic.elastic_enabled {
        cli.elastic.elastic_collectors = keys;
    } else if cli.github.github_enabled {
        cli.github.github_collectors = keys;
    } else if cli.jira.jira_enabled {
        cli.jira.jira_collectors = keys;
    } else if cli.jamf.jamf_enabled {
        cli.jamf.jamf_collectors = keys;
    } else if cli.jumpcloud.jumpcloud_enabled {
        cli.jumpcloud.jumpcloud_collectors = keys;
    }
}
```

Add `use crate::runner::provider_cli::run_provider_cli;` only if you prefer it over the inline path; either is fine, keep imports grouped.

- [ ] **Step 3: Write the regression test**

Append to `src/engine.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::set_provider_collectors;
    use crate::cli::Cli;

    #[test]
    fn collector_keys_land_on_the_active_provider() {
        let mut cli = Cli {
            ..Cli::default()
        };
        cli.tenable.tenable_enabled = true;
        set_provider_collectors(&mut cli, &["tenable-assets".to_string()]);

        assert_eq!(
            cli.tenable.tenable_collectors.as_deref(),
            Some(&["tenable-assets".to_string()][..])
        );
        assert!(cli.okta.okta_collectors.is_none());
    }

    #[test]
    fn empty_selection_means_every_collector() {
        let mut cli = Cli::default();
        cli.okta.okta_enabled = true;
        set_provider_collectors(&mut cli, &[]);
        assert!(cli.okta.okta_collectors.is_none());
    }
}
```

- [ ] **Step 4: Run the tests**

Run: `cargo test --lib engine:: && cargo clippy -- -D warnings && cargo fmt`
Expected: PASS, clippy clean.

- [ ] **Step 5: Commit**

```bash
git add src/engine.rs
git commit -m "feat(engine): add collect_provider for non-AWS vault-credential runs"
```

No changelog entry — no operator-visible surface until Task 7.

---

### Task 5: Desktop — save the new credential kinds

**Files:**
- Modify: `grabber-desktop/src-tauri/src/dto.rs`
- Modify: `grabber-desktop/src-tauri/src/commands/credentials.rs`
- Modify: `grabber-desktop/src/api/credentials.ts`
- Modify: `CHANGELOG.md`

**Interfaces:**
- Consumes: the Task 1 kinds; `CredentialMeta.base_url`/`.org`.
- Produces: `CredentialWriteDto` fields `secret_key`, `org`, `base_url`, `kibana_url`, `es_url`, `org_id`; `CredentialMetaDto` fields `base_url`, `org`; kind strings `"tenable_keys"`, `"github_token"`, `"elastic_api_key"`, `"jumpcloud_key"`.

- [ ] **Step 1: Extend the DTOs**

In `grabber-desktop/src-tauri/src/dto.rs`, add to `CredentialWriteDto`:

```rust
    pub secret_key: Option<String>,
    pub org: Option<String>,
    pub base_url: Option<String>,
    pub kibana_url: Option<String>,
    pub es_url: Option<String>,
    pub org_id: Option<String>,
```

and to `CredentialMetaDto`:

```rust
    pub base_url: Option<String>,
    pub org: Option<String>,
```

(`access_key_id` already exists and is reused as the Tenable access key.)

- [ ] **Step 2: Parse the new kinds**

In `grabber-desktop/src-tauri/src/commands/credentials.rs`, add to `parse_credential_dto`'s match, before the `_ =>` arm:

```rust
        "tenable_keys" => (
            CredentialKind::TenableKeys {
                base_url: dto
                    .base_url
                    .clone()
                    .unwrap_or_else(|| "https://cloud.tenable.com".to_string()),
            },
            CredentialSecret::TenableKeys {
                access_key: dto
                    .access_key_id
                    .clone()
                    .context("access_key_id required")?,
                secret_key: dto.secret_key.clone().context("secret_key required")?,
            },
        ),
        "github_token" => (
            CredentialKind::GithubToken {
                org: dto.org.clone().context("org required")?,
                base_url: dto
                    .base_url
                    .clone()
                    .unwrap_or_else(|| "https://api.github.com".to_string()),
            },
            CredentialSecret::ApiToken {
                token: dto.token.clone().context("token required")?,
            },
        ),
        "elastic_api_key" => (
            CredentialKind::ElasticApiKey {
                kibana_url: dto.kibana_url.clone().context("kibana_url required")?,
                es_url: dto.es_url.clone().context("es_url required")?,
            },
            CredentialSecret::ApiToken {
                token: dto.token.clone().context("token required")?,
            },
        ),
        "jumpcloud_key" => (
            CredentialKind::JumpCloudKey {
                org_id: dto.org_id.clone().unwrap_or_default(),
                base_url: dto
                    .base_url
                    .clone()
                    .unwrap_or_else(|| "https://console.jumpcloud.com".to_string()),
            },
            CredentialSecret::ApiToken {
                token: dto.token.clone().context("token required")?,
            },
        ),
```

- [ ] **Step 3: Carry the new meta fields**

`CredentialMetaDto` is built in three places in that file (`list_credentials`, `create_credential`, `import_aws_profiles`). Add to each construction:

```rust
            base_url: meta.base_url,
            org: meta.org,
```

For `import_aws_profiles` the values are `None` in practice, but take them from `meta` anyway so the three stay identical. Shorter alternative, if you prefer: extract a `fn meta_dto(meta: CredentialMeta) -> CredentialMetaDto` in that file and call it from all three.

- [ ] **Step 4: Mirror it in the TypeScript API**

In `grabber-desktop/src/api/credentials.ts`, add to `CredentialMetaDto`:

```ts
  base_url?: string;
  org?: string;
```

and to `CredentialWriteDto`:

```ts
  secret_key?: string;
  org?: string;
  base_url?: string;
  kibana_url?: string;
  es_url?: string;
  org_id?: string;
```

- [ ] **Step 5: Build both sides**

Run: `cargo check --manifest-path grabber-desktop/src-tauri/Cargo.toml && cd grabber-desktop && npx tsc --noEmit && cd ..`
Expected: both clean.

- [ ] **Step 6: Commit**

```bash
git add grabber-desktop/src-tauri/src/dto.rs grabber-desktop/src-tauri/src/commands/credentials.rs grabber-desktop/src/api/credentials.ts
git commit -m "feat(desktop): accept Tenable, GitHub, Elastic and JumpCloud credentials"
```

---

### Task 6: Credential form that matches the provider

Today the form offers all six kinds for every provider and puts a Jira email in a field labelled "Username". Drive the kind list and the labels from the chosen provider.

**Files:**
- Modify: `grabber-desktop/src/components/CredentialForm.tsx`
- Modify: `CHANGELOG.md`

**Interfaces:**
- Consumes: `CredentialWriteDto` from Task 5.
- Produces: a form whose `kind` is always valid for the selected `provider`.

- [ ] **Step 1: Replace the kind/provider tables**

In `grabber-desktop/src/components/CredentialForm.tsx`, replace the `KINDS` and `PROVIDERS` constants with:

```tsx
/** Credential kinds each provider can actually use, first entry is the default. */
const PROVIDER_KINDS: Record<string, string[]> = {
  aws: ["aws_sso", "aws_access_key", "aws_profile_reference"],
  tenable: ["tenable_keys"],
  okta: ["api_token"],
  jira: ["basic_auth"],
  github: ["github_token"],
  elastic: ["elastic_api_key"],
  jamf: ["oauth"],
  jumpcloud: ["jumpcloud_key"],
};

const PROVIDERS = Object.keys(PROVIDER_KINDS);

/** Per-provider field labels for the kinds that are shared between providers. */
const LABELS: Record<string, { host?: string; username?: string; password?: string; domain?: string; clientId?: string; secret?: string }> = {
  jira: {
    host: "Jira site URL (https://acme.atlassian.net)",
    username: "Jira account email",
    password: "Jira API token",
  },
  jamf: {
    domain: "Jamf Pro base URL (https://acme.jamfcloud.com)",
    clientId: "API client ID",
    secret: "API client secret",
  },
  okta: {
    domain: "Okta domain (https://example.okta.com)",
    secret: "API token (SSWS)",
  },
};
```

- [ ] **Step 2: Keep kind valid when the provider changes**

Replace the provider `<select>`'s `onChange` so switching provider also resets the kind:

```tsx
      <select
        value={value.provider}
        onChange={(e) => {
          const provider = e.target.value;
          update({ provider, kind: PROVIDER_KINDS[provider][0] });
        }}
      >
```

and the kind `<select>`'s option list:

```tsx
        {(PROVIDER_KINDS[value.provider] ?? []).map((k) => (
          <option key={k} value={k}>
            {k}
          </option>
        ))}
```

- [ ] **Step 3: Use the provider labels on the shared kinds**

Replace the `basic_auth` block with:

```tsx
      {value.kind === "basic_auth" && (
        <>
          <input
            value={value.host || ""}
            onChange={(e) => update({ host: e.target.value })}
            placeholder={LABELS[value.provider]?.host ?? "Host"}
          />
          <input
            value={value.username || ""}
            onChange={(e) => update({ username: e.target.value })}
            placeholder={LABELS[value.provider]?.username ?? "Username"}
          />
          <input
            type="password"
            value={value.password || ""}
            onChange={(e) => update({ password: e.target.value })}
            placeholder={LABELS[value.provider]?.password ?? "Password"}
          />
        </>
      )}
```

and in the existing `api_token || oauth` block, change the two placeholders to:

```tsx
            placeholder={LABELS[value.provider]?.domain ?? "Domain"}
```

```tsx
              placeholder={LABELS[value.provider]?.clientId ?? "Client ID"}
```

```tsx
            placeholder={
              value.kind === "oauth"
                ? (LABELS[value.provider]?.secret ?? "Client Secret")
                : (LABELS[value.provider]?.secret ?? "Token")
            }
```

- [ ] **Step 4: Add the four new field blocks**

Append before the closing `</div>`:

```tsx
      {value.kind === "tenable_keys" && (
        <>
          <input
            value={value.base_url || ""}
            onChange={(e) => update({ base_url: e.target.value })}
            placeholder="Tenable URL (blank = https://cloud.tenable.com)"
          />
          <input
            value={value.access_key_id || ""}
            onChange={(e) => update({ access_key_id: e.target.value })}
            placeholder="Access Key"
          />
          <input
            type="password"
            value={value.secret_key || ""}
            onChange={(e) => update({ secret_key: e.target.value })}
            placeholder="Secret Key"
          />
        </>
      )}

      {value.kind === "github_token" && (
        <>
          <input
            value={value.org || ""}
            onChange={(e) => update({ org: e.target.value })}
            placeholder="GitHub organisation"
          />
          <input
            value={value.base_url || ""}
            onChange={(e) => update({ base_url: e.target.value })}
            placeholder="API base URL (blank = https://api.github.com)"
          />
          <input
            type="password"
            value={value.token || ""}
            onChange={(e) => update({ token: e.target.value })}
            placeholder="Personal access token"
          />
        </>
      )}

      {value.kind === "elastic_api_key" && (
        <>
          <input
            value={value.kibana_url || ""}
            onChange={(e) => update({ kibana_url: e.target.value })}
            placeholder="Kibana URL"
          />
          <input
            value={value.es_url || ""}
            onChange={(e) => update({ es_url: e.target.value })}
            placeholder="Elasticsearch URL"
          />
          <input
            type="password"
            value={value.token || ""}
            onChange={(e) => update({ token: e.target.value })}
            placeholder="API key"
          />
        </>
      )}

      {value.kind === "jumpcloud_key" && (
        <>
          <input
            value={value.org_id || ""}
            onChange={(e) => update({ org_id: e.target.value })}
            placeholder="Org ID (multi-tenant only)"
          />
          <input
            value={value.base_url || ""}
            onChange={(e) => update({ base_url: e.target.value })}
            placeholder="Base URL (blank = https://console.jumpcloud.com)"
          />
          <input
            type="password"
            value={value.token || ""}
            onChange={(e) => update({ token: e.target.value })}
            placeholder="API key"
          />
        </>
      )}
```

- [ ] **Step 5: Show the new identifiers in the vault table**

In `grabber-desktop/src/screens/CredentialVault.tsx`, extend the identifier cell so the new kinds are not all shown as `—`:

```tsx
              <td>
                {c.access_key_id ||
                  c.account_id ||
                  c.profile_name ||
                  c.domain ||
                  c.host ||
                  c.org ||
                  c.base_url ||
                  "—"}
              </td>
```

- [ ] **Step 6: Build and eyeball it**

Run: `cd grabber-desktop && npx tsc --noEmit && npm run tauri dev`
Expected: compiles; in the app open Credential Vault, pick each provider in turn and confirm the kind list and fields change, then save one Okta credential and see it listed with its domain. Close the app.

- [ ] **Step 7: Changelog**

Under `## [Unreleased]` → `### Changed`:

```markdown
- Desktop Credential Vault: the credential form now offers only the credential type each provider actually uses, with provider-specific field labels (a Jira credential asks for site URL, account email and API token rather than host/username/password).
```

- [ ] **Step 8: Commit**

```bash
git add grabber-desktop/src/components/CredentialForm.tsx grabber-desktop/src/screens/CredentialVault.tsx CHANGELOG.md
git commit -m "feat(desktop): provider-driven credential form"
```

---

### Task 7: Desktop — list non-AWS credentials as accounts, and their collectors

**Files:**
- Modify: `grabber-desktop/src-tauri/src/commands/accounts.rs`
- Modify: `grabber-desktop/src-tauri/src/commands/collectors.rs`
- Modify: `CHANGELOG.md`

**Interfaces:**
- Consumes: `CredentialMeta`, the `<P>_COLLECTOR_KEYS` tables in `src/cli_providers.rs`.
- Produces: `list_accounts` returning non-AWS vault accounts (`provider` = e.g. `"okta"`, `region` = `""`); `list_collectors(provider)` returning that provider's keys.

- [ ] **Step 1: Stop skipping non-AWS credentials**

In `grabber-desktop/src-tauri/src/commands/accounts.rs`, delete these three lines from the vault loop:

```rust
        if meta.provider != the_grabber::providers::CloudProvider::Aws {
            continue;
        }
```

The `already_referenced` check below compares `credential_id` and `profile` and is correct as-is for non-AWS credentials (`profile_name` is `None` for them, so only the `credential_id` comparison can match).

- [ ] **Step 2: Return the real collector catalog per provider**

Replace the body of `list_collectors` in `grabber-desktop/src-tauri/src/commands/collectors.rs`. Keep the existing hard-coded AWS list for `"aws"`; for the others, build from the key tables:

```rust
use the_grabber::cli_providers::{
    ELASTIC_COLLECTOR_KEYS, GITHUB_COLLECTOR_KEYS, JAMF_COLLECTOR_KEYS, JIRA_COLLECTOR_KEYS,
    JUMPCLOUD_COLLECTOR_KEYS, OKTA_COLLECTOR_KEYS, TENABLE_COLLECTOR_KEYS,
};

use crate::dto::CollectorMetaDto;
use crate::error::GuiError;

/// Turn a selector key into a display name: `okta-group-members` → `Group Members`.
fn display_name(key: &str, provider: &str) -> String {
    key.strip_prefix(&format!("{provider}-"))
        .unwrap_or(key)
        .split('-')
        .map(|word| {
            let mut chars = word.chars();
            match chars.next() {
                Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
                None => String::new(),
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn from_keys(provider: &str, keys: &[&str]) -> Vec<CollectorMetaDto> {
    keys.iter()
        .map(|key| CollectorMetaDto {
            key: (*key).to_string(),
            name: display_name(key, provider),
            category: provider.to_uppercase(),
        })
        .collect()
}

#[tauri::command]
pub async fn list_collectors(provider: String) -> Result<Vec<CollectorMetaDto>, GuiError> {
    let keys: &[&str] = match provider.as_str() {
        "okta" => OKTA_COLLECTOR_KEYS,
        "tenable" => TENABLE_COLLECTOR_KEYS,
        "elastic" => ELASTIC_COLLECTOR_KEYS,
        "github" => GITHUB_COLLECTOR_KEYS,
        "jira" => JIRA_COLLECTOR_KEYS,
        "jamf" => JAMF_COLLECTOR_KEYS,
        "jumpcloud" => JUMPCLOUD_COLLECTOR_KEYS,
        _ => return Ok(aws_collectors()),
    };
    Ok(from_keys(&provider, keys))
}
```

and move the existing hard-coded AWS `vec![...]` into a private `fn aws_collectors() -> Vec<CollectorMetaDto>` in the same file, unchanged.

If `the_grabber::cli_providers` is not public, add `pub mod cli_providers;` to `src/lib.rs` (check first — it may already be public because `main.rs` uses it).

- [ ] **Step 3: Verify**

Run: `cargo check --manifest-path grabber-desktop/src-tauri/Cargo.toml && cargo clippy --manifest-path grabber-desktop/src-tauri/Cargo.toml -- -D warnings`
Expected: clean.

- [ ] **Step 4: Changelog**

Under `## [Unreleased]` → `### Added`:

```markdown
- Desktop: saved credentials for Okta, Tenable, Jira, GitHub, Elastic, Jamf and JumpCloud now appear in the account list and can be selected for a run, and the collector picker shows that provider's real collector list instead of the AWS one.
```

- [ ] **Step 5: Commit**

```bash
git add grabber-desktop/src-tauri/src/commands/accounts.rs grabber-desktop/src-tauri/src/commands/collectors.rs CHANGELOG.md
git commit -m "feat(desktop): surface non-AWS vault accounts and their collectors"
```

---

### Task 8: Desktop — run a non-AWS collection

**Files:**
- Modify: `grabber-desktop/src-tauri/src/dto.rs`
- Modify: `grabber-desktop/src-tauri/src/commands/collection.rs`
- Modify: `grabber-desktop/src-tauri/src/lib.rs`
- Modify: `grabber-desktop/src/api/collection.ts`
- Modify: `grabber-desktop/src/App.tsx`
- Modify: `CHANGELOG.md`

**Interfaces:**
- Consumes: `Engine::collect_provider` and `ProviderCollectionRequest` (Task 4).
- Produces: Tauri command `start_provider_collection(request: ProviderCollectionRequestDto) -> String`; TS `startProviderCollection(req: ProviderCollectionRequestDto): Promise<string>`.

- [ ] **Step 1: Add the request DTO**

In `grabber-desktop/src-tauri/src/dto.rs`, next to `CollectionRequestDto`:

```rust
#[derive(Debug, Clone, Deserialize)]
pub struct ProviderCollectionRequestDto {
    pub account_name: String,
    pub credential_id: String,
    pub start_date: String,
    pub end_date: String,
    pub collectors: Vec<String>,
    pub output_dir: String,
    pub zip: bool,
    pub sign: bool,
    pub include_raw: bool,
    pub write_run_manifest: bool,
    pub write_chain_of_custody: bool,
    pub signing_key: Option<String>,
}
```

(Match the derive list on `CollectionRequestDto` exactly, whatever it is.)

- [ ] **Step 2: Add the command**

In `grabber-desktop/src-tauri/src/commands/collection.rs`, after `start_collection` — it is `start_collection` with the regions dropped and `collect_provider` in place of `collect`:

```rust
#[tauri::command]
pub async fn start_provider_collection(
    request: ProviderCollectionRequestDto,
    app: tauri::AppHandle,
    state: State<'_, AppState>,
) -> Result<String, GuiError> {
    let run_id = Uuid::new_v4().to_string();
    let engine = state.engine.clone();
    let sink = TauriProgressSink::new(app.clone(), run_id.clone());
    let account_name = request.account_name.clone();
    let req = ProviderCollectionRequest {
        run_id: run_id.clone(),
        account_name: request.account_name,
        credential_id: request.credential_id,
        start_date: request.start_date,
        end_date: request.end_date,
        collectors: request.collectors,
        output_dir: PathBuf::from(request.output_dir),
        zip: request.zip,
        sign: request.sign,
        include_raw: request.include_raw,
        write_run_manifest: request.write_run_manifest,
        write_chain_of_custody: request.write_chain_of_custody,
        signing_key: request.signing_key,
    };

    let task_run_id = run_id.clone();
    let handle = tokio::spawn(async move {
        if let Err(e) = engine.collect_provider(req, Box::new(sink)).await {
            emit_failure(&app, &task_run_id, &account_name, "all", &e);
        }
        if let Some(state) = app.try_state::<AppState>() {
            state.take_run(&task_run_id);
        }
    });

    state.register_run(run_id.clone(), handle.abort_handle());

    Ok(run_id)
}
```

Extend the two `use` lines at the top of the file:

```rust
use the_grabber::engine::{
    CollectionRequest, ProgressEvent, ProgressSink, ProviderCollectionRequest,
};

use crate::dto::{CollectionRequestDto, ProviderCollectionRequestDto};
```

- [ ] **Step 3: Register the command**

In `grabber-desktop/src-tauri/src/lib.rs`, add `commands::collection::start_provider_collection` to the `tauri::generate_handler![...]` list, next to `start_collection` (use whatever path form the neighbouring entries use).

- [ ] **Step 4: Add the TS binding**

In `grabber-desktop/src/api/collection.ts`:

```ts
export interface ProviderCollectionRequestDto {
  account_name: string;
  credential_id: string;
  start_date: string;
  end_date: string;
  collectors: string[];
  output_dir: string;
  zip: boolean;
  sign: boolean;
  include_raw: boolean;
  write_run_manifest: boolean;
  write_chain_of_custody: boolean;
  signing_key?: string;
}

export const startProviderCollection = (request: ProviderCollectionRequestDto) =>
  invoke<string>("start_provider_collection", { request });
```

- [ ] **Step 5: Route non-AWS accounts through it**

In `grabber-desktop/src/App.tsx`:

(a) Import it:

```tsx
import {
  CollectionRequestDto,
  ProviderCollectionRequestDto,
  startCollection,
  startProviderCollection,
} from "./api/collection";
```

(b) Add a derived flag under `const account = selectedAccounts[0];`:

```tsx
  const isAwsAccount = (account?.provider ?? "aws") === "aws";
```

(c) Skip the region screen for non-AWS accounts — in the `accountSelection` case's `onNext`:

```tsx
          onNext={(accounts) => {
            setSelectedAccounts(accounts);
            setScreen(
              (accounts[0]?.provider ?? "aws") === "aws"
                ? "regionSelection"
                : "featureSelection",
            );
          }}
```

and make `featureSelection`'s back button return to the right place:

```tsx
          onBack={() => setScreen(isAwsAccount ? "regionSelection" : "accountSelection")}
```

(d) Add the provider request alongside `request`:

```tsx
  const providerRequest = useMemo<ProviderCollectionRequestDto | null>(() => {
    if (!account?.credential_id || !runOptions) return null;
    return {
      account_name: account.name,
      credential_id: account.credential_id,
      start_date: dateRange.start,
      end_date: dateRange.end,
      collectors,
      output_dir: runOptions.outputDir,
      zip: runOptions.zip,
      sign: runOptions.sign,
      include_raw: runOptions.includeRaw,
      write_run_manifest: runOptions.runManifest,
      write_chain_of_custody: runOptions.chainOfCustody,
      signing_key: runOptions.signingKey,
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [account, runOptions, dateRange, collectors]);
```

(e) In the `running` case, replace the final evidence branch:

```tsx
      if (!isAwsAccount) {
        if (!providerRequest) return missingCredential;
        const req = providerRequest;
        return (
          <RunningScreen
            title="Collecting Evidence"
            subtitle={`Running ${req.collectors.length || "all"} collectors for ${req.account_name}…`}
            start={() => startProviderCollection(req)}
            onFinished={() => setScreen("results")}
            onBack={() => setScreen("confirm")}
          />
        );
      }
      if (!request) return missingCredential;
```

(f) `inventory` and `poam` stay AWS-only. In `FeatureSelection`'s `onNext`, guard the two that cannot run:

```tsx
            if (!isAwsAccount && (selected === "inventory" || selected === "poam")) {
              return;
            }
```

and pass the flag into the screen so it can grey them out if it renders a list — if `FeatureSelection` takes no props today, add `awsOnly={!isAwsAccount}` and have it disable those two buttons. Read `grabber-desktop/src/screens/FeatureSelection.tsx` and follow whatever pattern it uses for its buttons.

- [ ] **Step 6: Build**

Run: `cargo check --manifest-path grabber-desktop/src-tauri/Cargo.toml && cd grabber-desktop && npx tsc --noEmit && npm run build && cd ..`
Expected: all clean.

- [ ] **Step 7: End-to-end check against a real tenant**

Run: `cd grabber-desktop && npm run tauri dev`

With a real Okta (or Tenable) tenant:
1. Credential Vault → provider `okta`, kind `api_token`, domain and SSWS token → Save.
2. Back → Accounts: the credential appears as an account with provider `okta`.
3. Select it → the region screen is skipped → Evidence → a date range → pick two collectors → Options → Confirm → Start.
4. The Running screen shows `started` then `finished`; evidence lands under `{output}/{credential name}/{YYYY}/{MM-MMM}/`.

Record what you saw in the commit message. If `run_provider_cli` errors with a message about credential overrides being applied to multiple accounts, `--vault-account` is not reaching `accounts_for_run` — go back to Task 3 Step 5 and check every provider file was converted.

- [ ] **Step 8: Changelog**

Under `## [Unreleased]` → `### Added`:

```markdown
- Desktop: evidence collection now runs against Okta, Tenable, Jira, GitHub, Elastic, Jamf and JumpCloud using a credential saved in the Credential Vault — no `okta-config.toml` / `tenable-config.toml` / etc. entry is needed. Evidence is written under the credential's name, e.g. `{output}/Okta Prod/2026/09-Sep/`. Region selection is skipped for these providers, and Inventory and POA&M remain AWS-only.
```

- [ ] **Step 9: Commit**

```bash
git add grabber-desktop/src-tauri/src/dto.rs grabber-desktop/src-tauri/src/commands/collection.rs grabber-desktop/src-tauri/src/lib.rs grabber-desktop/src/api/collection.ts grabber-desktop/src/App.tsx grabber-desktop/src/screens/FeatureSelection.tsx CHANGELOG.md
git commit -m "feat(desktop): run evidence collection for non-AWS providers from the vault"
```

---

### Task 9: Document it

**Files:**
- Modify: `README.md`
- Modify: `cli-examples.md`

- [ ] **Step 1: Document `--vault-account`**

In `cli-examples.md`, in the non-AWS provider section, add:

```markdown
### Collect from one tenant with no config file

`--vault-account` names the run and makes it ignore every `[[account]]` in the
config files, so the credential flags describe the whole tenant:

```bash
grabber --okta \
  --vault-account "Okta Prod" \
  --okta-domain https://example.okta.com \
  --okta-api-token "$OKTA_API_TOKEN" \
  --okta-collectors okta-users,okta-groups \
  --lookback 30
```

Evidence lands in `{output}/Okta Prod/2026/09-Sep/`. This is the flag the
desktop app sets when a run is driven by a saved credential.
```

- [ ] **Step 2: Document the desktop vault**

In `README.md`, in the desktop section, add a short paragraph after the existing credential-vault text:

```markdown
Credentials for Okta, Tenable, Jira, GitHub, Elastic, Jamf and JumpCloud can be
saved in the vault and selected directly as accounts — the per-provider
`*-config.toml` files are only needed for CLI and TUI runs, or for collecting
from several tenants of one provider in a single run. Secrets go to the OS
keyring; the vault's own metadata file holds only URLs and identifiers.
```

- [ ] **Step 3: Commit**

```bash
git add README.md cli-examples.md
git commit -m "docs: desktop credentials and --vault-account for non-AWS providers"
```

---

## Deliberately out of scope

- **Test-connection button.** Each provider needs its own client and a cheap probe call; a failed run already reports the authentication error. Add it when users report they cannot tell a bad token from a bad collector.
- **Editing a saved credential.** `CredentialVault::update` exists but no command exposes it. Delete-and-recreate covers it for now.
- **Multi-tenant desktop runs.** One credential per run; several tenants of one provider still go through the config files and the CLI/TUI.
- **Azure and GCP.** No credential fields and no collectors exist for them yet.
- **Inventory and POA&M for non-AWS providers.** `--inventory` and `--poam` reject provider mode flags by design.
