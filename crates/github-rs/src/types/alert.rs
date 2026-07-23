use serde::Deserialize;

#[derive(Debug, Clone, Default, Deserialize)]
pub struct GithubAlertRepo {
    #[serde(default)]
    pub full_name: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct DependabotPackage {
    #[serde(default)]
    pub ecosystem: String,
    #[serde(default)]
    pub name: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DependabotDependency {
    #[serde(default)]
    pub package: DependabotPackage,
    #[serde(default)]
    pub manifest_path: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DependabotAdvisory {
    #[serde(default)]
    pub ghsa_id: String,
    #[serde(default)]
    pub cve_id: Option<String>,
    #[serde(default)]
    pub severity: String,
    #[serde(default)]
    pub summary: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct GithubDependabotAlert {
    pub number: i64,
    #[serde(default)]
    pub state: String,
    pub dependency: DependabotDependency,
    #[serde(default)]
    pub security_advisory: Option<DependabotAdvisory>,
    #[serde(default)]
    pub created_at: String,
    #[serde(default)]
    pub updated_at: Option<String>,
    #[serde(default)]
    pub repository: GithubAlertRepo,
}

#[derive(Debug, Clone, Deserialize)]
pub struct GithubSecretScanningAlert {
    pub number: i64,
    #[serde(default)]
    pub created_at: String,
    #[serde(default)]
    pub state: String,
    #[serde(default)]
    pub resolution: Option<String>,
    #[serde(default)]
    pub secret_type: String,
    #[serde(default)]
    pub secret_type_display_name: Option<String>,
    #[serde(default)]
    pub push_protection_bypassed: bool,
    #[serde(default)]
    pub repository: GithubAlertRepo,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CodeScanningRule {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub severity: Option<String>,
    #[serde(default)]
    pub security_severity_level: Option<String>,
    #[serde(default)]
    pub description: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct GithubCodeScanningAlert {
    pub number: i64,
    #[serde(default)]
    pub created_at: String,
    #[serde(default)]
    pub state: String,
    pub rule: CodeScanningRule,
    #[serde(default)]
    pub repository: GithubAlertRepo,
}
