use github_rs::GithubClient;

use crate::evidence::{CsvCollector, EvidenceCollector, JsonCollector};
use crate::providers::{CloudProvider, ProviderFactory};

use super::alerts::{
    GithubCodeScanningAlertsCollector, GithubDependabotAlertsCollector,
    GithubSecretScanningAlertsCollector,
};
use super::audit_log::GithubAuditLogCollector;
use super::branch_protection::GithubBranchProtectionCollector;
use super::members::GithubMembersCollector;
use super::repos::GithubReposCollector;
use super::security_settings::GithubSecuritySettingsCollector;
use super::teams::{GithubTeamMembersCollector, GithubTeamsCollector};

pub struct GithubProviderFactory {
    client: GithubClient,
    org_name: String,
    selected: Vec<String>,
}

impl GithubProviderFactory {
    pub fn new(client: GithubClient, org_name: String, selected: Vec<String>) -> Self {
        Self {
            client,
            org_name,
            selected,
        }
    }

    fn has(&self, key: &str) -> bool {
        self.selected.iter().any(|s| s == key)
    }
}

impl ProviderFactory for GithubProviderFactory {
    fn provider(&self) -> CloudProvider {
        CloudProvider::Github
    }
    fn account_id(&self) -> &str {
        &self.org_name
    }
    fn region(&self) -> &str {
        ""
    }

    fn csv_collectors(&self) -> Vec<Box<dyn CsvCollector>> {
        let mut v: Vec<Box<dyn CsvCollector>> = Vec::new();
        if self.has("github-members") {
            v.push(Box::new(GithubMembersCollector::new(self.client.clone())));
        }
        if self.has("github-teams") {
            v.push(Box::new(GithubTeamsCollector::new(self.client.clone())));
        }
        if self.has("github-team-members") {
            v.push(Box::new(GithubTeamMembersCollector::new(
                self.client.clone(),
            )));
        }
        if self.has("github-security-settings") {
            v.push(Box::new(GithubSecuritySettingsCollector::new(
                self.client.clone(),
            )));
        }
        if self.has("github-repos") {
            v.push(Box::new(GithubReposCollector::new(self.client.clone())));
        }
        if self.has("github-branch-protection") {
            v.push(Box::new(GithubBranchProtectionCollector::new(
                self.client.clone(),
            )));
        }
        if self.has("github-audit-log") {
            v.push(Box::new(GithubAuditLogCollector::new(self.client.clone())));
        }
        if self.has("github-dependabot-alerts") {
            v.push(Box::new(GithubDependabotAlertsCollector::new(
                self.client.clone(),
            )));
        }
        if self.has("github-secret-scanning-alerts") {
            v.push(Box::new(GithubSecretScanningAlertsCollector::new(
                self.client.clone(),
            )));
        }
        if self.has("github-code-scanning-alerts") {
            v.push(Box::new(GithubCodeScanningAlertsCollector::new(
                self.client.clone(),
            )));
        }
        v
    }

    fn json_collectors(&self) -> Vec<Box<dyn JsonCollector>> {
        Vec::new()
    }
    fn evidence_collectors(&self) -> Vec<Box<dyn EvidenceCollector>> {
        Vec::new()
    }
}
