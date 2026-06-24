use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct JiraIssue {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub key: String,
    #[serde(default)]
    pub fields: IssueFields,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct IssueFields {
    #[serde(default)]
    pub summary: Option<String>,
    #[serde(default)]
    pub status: Option<NamedField>,
    #[serde(default)]
    pub priority: Option<NamedField>,
    #[serde(default)]
    pub issuetype: Option<NamedField>,
    #[serde(default)]
    pub assignee: Option<UserField>,
    #[serde(default)]
    pub reporter: Option<UserField>,
    #[serde(default)]
    pub created: Option<String>,
    #[serde(default)]
    pub updated: Option<String>,
    #[serde(default)]
    pub resolutiondate: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct NamedField {
    #[serde(default)]
    pub name: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct UserField {
    #[serde(rename = "accountId", default)]
    pub account_id: String,
    #[serde(rename = "displayName", default)]
    pub display_name: String,
    #[serde(rename = "emailAddress", default)]
    pub email_address: Option<String>,
}
