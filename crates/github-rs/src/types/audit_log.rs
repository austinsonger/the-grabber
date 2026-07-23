use serde::Deserialize;

/// `created_at` is Unix epoch **milliseconds** on this endpoint — unlike every
/// other timestamp field in this crate, which GitHub sends as an RFC 3339
/// string. Do not assume ISO-string parsing works here.
#[derive(Debug, Clone, Deserialize)]
pub struct GithubAuditLogEvent {
    #[serde(default)]
    pub action: String,
    #[serde(default)]
    pub actor: Option<String>,
    #[serde(default)]
    pub user: Option<String>,
    #[serde(default)]
    pub org: Option<String>,
    #[serde(default)]
    pub created_at: Option<i64>,
    #[serde(default, rename = "_document_id")]
    pub document_id: Option<String>,
}
