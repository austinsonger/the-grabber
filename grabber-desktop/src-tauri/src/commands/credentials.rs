use anyhow::Context;
use tauri::State;
use uuid::Uuid;

use the_grabber::credentials::{CredentialKind, CredentialSecret, NewCredential};
use the_grabber::providers::CloudProvider;

use crate::dto::{CredentialMetaDto, CredentialWriteDto};
use crate::error::GuiError;
use crate::state::AppState;

#[tauri::command]
pub async fn list_credentials(
    state: State<'_, AppState>,
) -> Result<Vec<CredentialMetaDto>, GuiError> {
    let metas = state
        .engine
        .vault
        .list()
        .map_err(|e| GuiError::Credential(e.to_string()))?;
    Ok(metas
        .into_iter()
        .map(|m| CredentialMetaDto {
            id: m.id.to_string(),
            name: m.name,
            provider: m.provider.to_string(),
            kind: m.kind_tag,
            domain: m.domain,
            host: m.host,
            access_key_id: m.access_key_id,
            account_id: m.account_id,
            profile_name: m.profile_name,
        })
        .collect())
}

#[tauri::command]
pub async fn create_credential(
    dto: CredentialWriteDto,
    state: State<'_, AppState>,
) -> Result<CredentialMetaDto, GuiError> {
    let (kind, secret) =
        parse_credential_dto(&dto).map_err(|e| GuiError::Validation(e.to_string()))?;
    let provider = CloudProvider::try_from(dto.provider.as_str())
        .map_err(|_| GuiError::Validation(format!("Unknown provider {}", dto.provider)))?;
    let new = NewCredential {
        name: dto.name,
        provider,
        kind,
        secret,
    };
    let meta = state
        .engine
        .vault
        .create(new)
        .map_err(|e| GuiError::Credential(e.to_string()))?;
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

#[tauri::command]
pub async fn delete_credential(id: String, state: State<'_, AppState>) -> Result<(), GuiError> {
    let uuid = Uuid::parse_str(&id).map_err(|e| GuiError::Validation(e.to_string()))?;
    state
        .engine
        .vault
        .delete(uuid)
        .map_err(|e| GuiError::Credential(e.to_string()))?;
    Ok(())
}

fn parse_credential_dto(
    dto: &CredentialWriteDto,
) -> anyhow::Result<(CredentialKind, CredentialSecret)> {
    Ok(match dto.kind.as_str() {
        "aws_sso" => (
            CredentialKind::AwsSso {
                start_url: dto.start_url.clone().context("start_url required")?,
                account_id: dto.account_id.clone().context("account_id required")?,
                role_name: dto.role_name.clone().context("role_name required")?,
                region: dto.region.clone().context("region required")?,
                session_name: dto
                    .session_name
                    .clone()
                    .unwrap_or_else(|| "the-grabber".into()),
            },
            CredentialSecret::None,
        ),
        "aws_access_key" => (
            CredentialKind::AwsAccessKey {
                access_key_id: dto
                    .access_key_id
                    .clone()
                    .context("access_key_id required")?,
            },
            CredentialSecret::AwsAccessKeySecret {
                secret_access_key: dto
                    .secret_access_key
                    .clone()
                    .context("secret_access_key required")?,
                session_token: dto.session_token.clone(),
            },
        ),
        "api_token" => (
            CredentialKind::ApiToken {
                domain: dto.domain.clone().context("domain required")?,
            },
            CredentialSecret::ApiToken {
                token: dto.token.clone().context("token required")?,
            },
        ),
        "basic_auth" => (
            CredentialKind::BasicAuth {
                host: dto.host.clone().context("host required")?,
                username: dto.username.clone().context("username required")?,
            },
            CredentialSecret::BasicAuth {
                password: dto.password.clone().context("password required")?,
            },
        ),
        "oauth" => (
            CredentialKind::OAuth {
                domain: dto.domain.clone().context("domain required")?,
                client_id: dto.client_id.clone().context("client_id required")?,
            },
            CredentialSecret::OAuth {
                client_secret: dto
                    .client_secret
                    .clone()
                    .context("client_secret required")?,
            },
        ),
        "aws_profile_reference" => (
            CredentialKind::AwsProfileReference {
                profile_name: dto.profile_name.clone().context("profile_name required")?,
            },
            CredentialSecret::None,
        ),
        _ => anyhow::bail!("Unsupported credential kind: {}", dto.kind),
    })
}
