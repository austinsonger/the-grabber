//! Credential domain types used by the desktop GUI vault.

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
            CredentialKind::ApiToken { domain } | CredentialKind::OAuth { domain, .. } => {
                Some(domain)
            }
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
    AwsAccessKeySecret {
        secret_access_key: String,
        session_token: Option<String>,
    },
    ApiToken {
        token: String,
    },
    BasicAuth {
        password: String,
    },
    OAuth {
        client_secret: String,
    },
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
