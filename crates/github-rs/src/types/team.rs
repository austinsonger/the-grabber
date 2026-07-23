use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct GithubTeam {
    pub id: i64,
    pub name: String,
    pub slug: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub privacy: String,
    #[serde(default)]
    pub permission: String,
}
