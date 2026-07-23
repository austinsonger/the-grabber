use serde::Deserialize;

/// One Elasticsearch security role, flattened for CSV output. `name` comes
/// from the `_security/role` response's map key (see `SecurityUser` for the
/// same pattern), not from the JSON body itself.
#[derive(Debug, Clone)]
pub struct SecurityRole {
    pub name: String,
    pub cluster_privileges: Vec<String>,
    pub index_patterns: Vec<String>,
    pub index_privileges: Vec<String>,
    pub application_count: usize,
}

#[derive(Debug, Deserialize)]
pub(crate) struct SecurityRoleRaw {
    #[serde(default)]
    pub cluster: Vec<String>,
    #[serde(default)]
    pub indices: Vec<IndexPrivilegeRaw>,
    #[serde(default)]
    pub applications: Vec<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct IndexPrivilegeRaw {
    #[serde(default)]
    pub names: Vec<String>,
    #[serde(default)]
    pub privileges: Vec<String>,
}
