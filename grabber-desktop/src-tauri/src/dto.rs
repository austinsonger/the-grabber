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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfigDto {
    pub accounts: Vec<AccountDto>,
    pub defaults: DefaultsDto,
}

#[derive(Debug, Clone, Serialize)]
pub struct CollectorMetaDto {
    pub key: String,
    pub name: String,
    pub category: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CollectionRequestDto {
    pub account_name: String,
    pub credential_id: String,
    pub regions: Vec<String>,
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

#[derive(Debug, Clone, Serialize)]
pub struct ArtifactDto {
    pub name: String,
    pub path: String,
    pub extension: String,
    pub size_bytes: u64,
    pub modified_epoch_secs: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct IdentityInfoDto {
    pub account: Option<String>,
    pub user_id: Option<String>,
    pub arn: Option<String>,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DefaultsDto {
    pub region: String,
    pub output_dir: String,
    pub start_date_offset_days: i64,
}
