use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceFinding {
    pub asset:          ComplianceAsset,
    pub audit_file:     Option<String>,
    pub check_id:       Option<String>,
    pub check_name:     Option<String>,
    pub check_info:     Option<String>,
    pub status:         CheckStatus,
    pub expected_value: Option<String>,
    pub actual_value:   Option<String>,
    pub policy_name:    Option<String>,
    pub reference:      Option<Vec<String>>,
    pub see_also:       Option<Vec<String>>,
    pub first_seen:     Option<String>,
    pub last_seen:      Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceAsset {
    pub id:       String,
    pub fqdn:     Option<String>,
    pub hostname: Option<String>,
    pub ipv4:     Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CheckStatus {
    Passed,
    Failed,
    Warning,
    #[serde(other)]
    Unknown,
}
