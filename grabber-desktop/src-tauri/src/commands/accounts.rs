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
    let metas = state
        .engine
        .vault
        .list()
        .map_err(|e| GuiError::Credential(e.to_string()))?;
    for meta in metas {
        if meta.provider != the_grabber::providers::CloudProvider::Aws {
            continue;
        }
        let id = meta.id.to_string();
        let already_referenced = state.config.account.iter().any(|a| {
            a.credential_id.as_deref() == Some(id.as_str())
                || (meta.profile_name.is_some() && a.profile == meta.profile_name)
        });
        if already_referenced || accounts.iter().any(|a| a.name == meta.name) {
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

    Ok(accounts)
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
