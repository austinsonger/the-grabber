use serde::{Deserialize, Serialize};

use super::association::MemberRef;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemGroup {
    pub id: String,
    pub name: String,
    #[serde(default, rename = "type")]
    pub kind: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub attributes: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemGroupMember {
    pub to: MemberRef,
}
