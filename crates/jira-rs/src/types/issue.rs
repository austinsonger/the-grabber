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
    #[serde(default)]
    pub duedate: Option<String>,
    #[serde(default)]
    pub resolution: Option<NamedField>,
    #[serde(default)]
    pub labels: Vec<String>,
    #[serde(default)]
    pub components: Vec<NamedField>,
    #[serde(rename = "fixVersions", default)]
    pub fix_versions: Vec<NamedField>,
    #[serde(default)]
    pub parent: Option<ParentField>,
    /// ADF (Atlassian Document Format) tree. Use `adf_to_plain_text` to flatten.
    #[serde(default)]
    pub description: Option<serde_json::Value>,
    #[serde(default)]
    pub comment: Option<CommentField>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct ParentField {
    #[serde(default)]
    pub key: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct CommentField {
    #[serde(default)]
    pub comments: Vec<Comment>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct Comment {
    #[serde(default)]
    pub author: Option<UserField>,
    #[serde(default)]
    pub created: Option<String>,
    #[serde(default)]
    pub body: Option<serde_json::Value>,
}

/// Flatten an ADF (Atlassian Document Format) JSON tree to plain text.
/// Walks `content` arrays and collects `text` leaves; joins paragraphs with newlines.
pub fn adf_to_plain_text(value: &serde_json::Value) -> String {
    let mut out = String::new();
    walk_adf(value, &mut out);
    out.trim().to_string()
}

fn walk_adf(value: &serde_json::Value, out: &mut String) {
    if let Some(text) = value.get("text").and_then(|t| t.as_str()) {
        out.push_str(text);
    }
    if let Some(arr) = value.get("content").and_then(|c| c.as_array()) {
        for child in arr {
            walk_adf(child, out);
        }
        let ty = value.get("type").and_then(|t| t.as_str()).unwrap_or("");
        if matches!(
            ty,
            "paragraph" | "heading" | "bulletList" | "orderedList" | "listItem" | "blockquote"
        ) {
            out.push('\n');
        }
    }
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
