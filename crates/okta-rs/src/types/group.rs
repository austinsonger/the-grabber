use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct OktaGroup {
    pub id: String,
    #[serde(default, rename = "type")]
    pub group_type: String,
    #[serde(default)]
    pub created: Option<String>,
    #[serde(default, rename = "lastUpdated")]
    pub last_updated: Option<String>,
    #[serde(default, rename = "lastMembershipUpdated")]
    pub last_membership_updated: Option<String>,
    #[serde(default)]
    pub profile: GroupProfile,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct GroupProfile {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
}
