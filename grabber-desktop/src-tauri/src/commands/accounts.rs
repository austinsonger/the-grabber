use tauri::State;
use uuid::Uuid;

use the_grabber::credentials::load_aws_sdk_config;

use crate::dto::{AccountDto, IdentityInfoDto};
use crate::error::GuiError;
use crate::state::AppState;

#[tauri::command]
pub async fn list_accounts(state: State<'_, AppState>) -> Result<Vec<AccountDto>, GuiError> {
    let mut accounts: Vec<AccountDto> = state
        .config
        .account
        .iter()
        .map(|a| AccountDto {
            name: a.name.clone(),
            provider: a.provider.to_string(),
            account_id: a.account_id.clone(),
            credential_id: a.credential_id.clone(),
            profile: a.profile.clone(),
            region: a.region.clone().unwrap_or_default(),
            output_dir: a.output_dir.clone(),
        })
        .collect();

    // Vault credentials (e.g. imported ~/.aws profiles) that no config.toml
    // account references yet are offered as standalone accounts — collection
    // resolves them by credential_id, so no config entry is required.
    // An unreadable vault (e.g. orphaned encrypted store) must not hide the
    // config-defined accounts, so the failure is logged and treated as empty.
    let metas = state.engine.vault.list().unwrap_or_else(|e| {
        eprintln!("credential vault unavailable, skipping vault accounts: {e:#}");
        Vec::new()
    });
    merge_vault_accounts(&mut accounts, metas);

    Ok(accounts)
}

/// Fold AWS vault credentials into the config-derived account list.
///
/// A credential matching a config account — by id, or by naming the same AWS
/// profile — is stamped ONTO that account. Dropping it instead (the previous
/// behavior) left the config account with no `credential_id`, so every screen
/// needing credentials rejected it with "no vault credential": importing a
/// profile could never take effect, because a more complete `config.toml` only
/// made the match more certain. Config keeps owning region, output_dir and
/// collector overrides; the vault supplies the credential.
///
/// Credentials matching no config account are appended as standalone accounts,
/// so a vault-only credential still works with no config entry.
fn merge_vault_accounts(
    accounts: &mut Vec<AccountDto>,
    metas: Vec<the_grabber::credentials::CredentialMeta>,
) {
    for meta in metas {
        if meta.provider != the_grabber::providers::CloudProvider::Aws {
            continue;
        }
        let id = meta.id.to_string();

        if let Some(existing) = accounts.iter_mut().find(|a| {
            a.credential_id.as_deref() == Some(id.as_str())
                || (meta.profile_name.is_some() && a.profile == meta.profile_name)
        }) {
            if existing.credential_id.is_none() {
                existing.credential_id = Some(id);
            }
            if existing.account_id.is_none() {
                existing.account_id = meta.account_id.clone();
            }
            continue;
        }

        if accounts.iter().any(|a| a.name == meta.name) {
            continue;
        }
        accounts.push(AccountDto {
            name: meta.name,
            provider: meta.provider.to_string(),
            account_id: meta.account_id,
            credential_id: Some(id),
            profile: meta.profile_name,
            region: String::new(),
            output_dir: None,
        });
    }
}

#[tauri::command]
pub async fn test_account(
    name: String,
    state: State<'_, AppState>,
) -> Result<IdentityInfoDto, GuiError> {
    let account = state
        .config
        .account
        .iter()
        .find(|a| a.name == name)
        .ok_or_else(|| GuiError::NotFound(format!("Account {name}")))?;

    let (entry, secret) = resolve_credential(&state, account.credential_id.as_deref()).await?;
    let region = account.region.clone().or_else(|| Some("us-east-1".into()));
    let config = load_aws_sdk_config(&entry, &secret, region)
        .await
        .map_err(|e| GuiError::Collection(e.to_string()))?;

    let client = aws_sdk_sts::Client::new(&config);
    let resp = client
        .get_caller_identity()
        .send()
        .await
        .map_err(|e| GuiError::Collection(format!("STS error: {e}")))?;

    Ok(IdentityInfoDto {
        account: resp.account().map(|s| s.to_string()),
        user_id: resp.user_id().map(|s| s.to_string()),
        arn: resp.arn().map(|s| s.to_string()),
    })
}

#[tauri::command]
pub async fn discover_regions(
    credential_id: String,
    state: State<'_, AppState>,
) -> Result<Vec<String>, GuiError> {
    let (entry, secret) = resolve_credential(&state, Some(&credential_id)).await?;
    let config = load_aws_sdk_config(&entry, &secret, Some("us-east-1".into()))
        .await
        .map_err(|e| GuiError::Collection(e.to_string()))?;

    let client = aws_sdk_ec2::Client::new(&config);
    let resp = client
        .describe_regions()
        .send()
        .await
        .map_err(|e| GuiError::Collection(format!("EC2 error: {e}")))?;

    Ok(resp
        .regions
        .unwrap_or_default()
        .into_iter()
        .filter_map(|r| r.region_name().map(|s| s.to_string()))
        .collect())
}

async fn resolve_credential(
    state: &AppState,
    credential_id: Option<&str>,
) -> Result<
    (
        the_grabber::credentials::CredentialEntry,
        the_grabber::credentials::CredentialSecret,
    ),
    GuiError,
> {
    let id =
        credential_id.ok_or_else(|| GuiError::Validation("Account has no credential".into()))?;
    let uuid = Uuid::parse_str(id).map_err(|e| GuiError::Validation(e.to_string()))?;
    state
        .engine
        .vault
        .get(uuid)
        .map_err(|e| GuiError::Credential(e.to_string()))?
        .ok_or_else(|| GuiError::NotFound(format!("Credential {id}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use the_grabber::credentials::CredentialMeta;
    use the_grabber::providers::CloudProvider;

    fn config_account(name: &str, profile: Option<&str>) -> AccountDto {
        AccountDto {
            name: name.to_string(),
            provider: "aws".to_string(),
            account_id: None,
            credential_id: None,
            profile: profile.map(|p| p.to_string()),
            region: "us-east-1".to_string(),
            output_dir: Some("./evidence-output/x".to_string()),
        }
    }

    fn vault_meta(id: Uuid, name: &str, profile: Option<&str>) -> CredentialMeta {
        CredentialMeta {
            id,
            name: name.to_string(),
            provider: CloudProvider::Aws,
            kind_tag: "aws_profile_reference".to_string(),
            domain: None,
            host: None,
            access_key_id: None,
            account_id: Some("123456789012".to_string()),
            profile_name: profile.map(|p| p.to_string()),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    #[test]
    fn vault_credential_is_stamped_onto_matching_config_account() {
        let id = Uuid::new_v4();
        let mut accounts = vec![config_account("Prod", Some("org:ProdAdmin-1"))];
        merge_vault_accounts(
            &mut accounts,
            vec![vault_meta(id, "imported-prod", Some("org:ProdAdmin-1"))],
        );

        assert_eq!(accounts.len(), 1, "must not add a duplicate account");
        assert_eq!(
            accounts[0].credential_id.as_deref(),
            Some(id.to_string().as_str())
        );
        // Config keeps owning its own settings.
        assert_eq!(accounts[0].name, "Prod");
        assert_eq!(accounts[0].region, "us-east-1");
        assert_eq!(
            accounts[0].output_dir.as_deref(),
            Some("./evidence-output/x")
        );
        // account_id is backfilled from the vault when config omitted it.
        assert_eq!(accounts[0].account_id.as_deref(), Some("123456789012"));
    }

    #[test]
    fn unmatched_vault_credential_is_added_as_its_own_account() {
        let id = Uuid::new_v4();
        let mut accounts = vec![config_account("Prod", Some("org:ProdAdmin-1"))];
        merge_vault_accounts(
            &mut accounts,
            vec![vault_meta(id, "standalone", Some("other:DevAdmin-2"))],
        );

        assert_eq!(accounts.len(), 2);
        assert_eq!(accounts[1].name, "standalone");
        assert_eq!(
            accounts[1].credential_id.as_deref(),
            Some(id.to_string().as_str())
        );
    }

    #[test]
    fn existing_credential_id_is_not_overwritten() {
        let existing_id = Uuid::new_v4();
        let other_id = Uuid::new_v4();
        let mut accounts = vec![AccountDto {
            credential_id: Some(existing_id.to_string()),
            ..config_account("Prod", Some("org:ProdAdmin-1"))
        }];
        merge_vault_accounts(
            &mut accounts,
            vec![vault_meta(other_id, "imported", Some("org:ProdAdmin-1"))],
        );

        assert_eq!(accounts.len(), 1);
        assert_eq!(
            accounts[0].credential_id.as_deref(),
            Some(existing_id.to_string().as_str()),
            "an explicit config credential_id wins over a profile-name match"
        );
    }

    #[test]
    fn non_aws_credentials_are_ignored() {
        let mut accounts = vec![config_account("Prod", Some("org:ProdAdmin-1"))];
        let mut meta = vault_meta(Uuid::new_v4(), "okta-tenant", None);
        meta.provider = CloudProvider::Okta;
        merge_vault_accounts(&mut accounts, vec![meta]);

        assert_eq!(accounts.len(), 1);
        assert!(accounts[0].credential_id.is_none());
    }

    #[test]
    fn profileless_credential_does_not_match_profileless_account() {
        let mut accounts = vec![config_account("Prod", None)];
        merge_vault_accounts(
            &mut accounts,
            vec![vault_meta(Uuid::new_v4(), "vault-only", None)],
        );

        assert_eq!(
            accounts.len(),
            2,
            "two accounts that both lack a profile are not the same account"
        );
    }
}
