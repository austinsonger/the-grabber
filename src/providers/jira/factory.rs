use jira_rs::JiraClient;

use crate::evidence::{CsvCollector, EvidenceCollector, JsonCollector};
use crate::providers::{CloudProvider, ProviderFactory};

pub struct JiraProviderFactory {
    client: JiraClient,
    tenant_name: String,
    selected: Vec<String>,
    project_keys: Vec<String>,
}

impl JiraProviderFactory {
    pub fn new(client: JiraClient, tenant_name: String, selected: Vec<String>) -> Self {
        Self {
            client,
            tenant_name,
            selected,
            project_keys: Vec::new(),
        }
    }

    pub fn with_project_keys(mut self, project_keys: Vec<String>) -> Self {
        self.project_keys = project_keys;
        self
    }
}

impl ProviderFactory for JiraProviderFactory {
    fn provider(&self) -> CloudProvider {
        CloudProvider::Jira
    }
    fn account_id(&self) -> &str {
        &self.tenant_name
    }
    fn region(&self) -> &str {
        ""
    }

    fn csv_collectors(&self) -> Vec<Box<dyn CsvCollector>> {
        let mut v: Vec<Box<dyn CsvCollector>> = Vec::new();
        if self.selected.iter().any(|s| s == "jira-projects") {
            v.push(Box::new(super::projects::JiraProjectsCollector::new(
                self.client.clone(),
            )));
        }
        if self.selected.iter().any(|s| s == "jira-issues") {
            v.push(Box::new(super::issues::JiraIssuesCollector::with_projects(
                self.client.clone(),
                self.project_keys.clone(),
            )));
        }
        if self.selected.iter().any(|s| s == "jira-offboarding-sla") {
            // TODO: wire project_keys from AppConfig via factory constructor
            let key = "HR-OFF".to_string();
            v.push(Box::new(super::offboarding_sla::JiraOffboardingSlaCollector::new(
                self.client.clone(),
                key,
            )));
        }
        if self.selected.iter().any(|s| s == "jira-remote-access-approvals") {
            // TODO: wire project_keys from AppConfig via factory constructor
            let key = "SEC".to_string();
            v.push(Box::new(super::remote_access_approvals::JiraRemoteAccessApprovalsCollector::new(
                self.client.clone(),
                key,
            )));
        }
        if self.selected.iter().any(|s| s == "jira-external-system-approvals") {
            // TODO: wire project_keys from AppConfig via factory constructor
            let key = "SEC".to_string();
            v.push(Box::new(super::external_system_approvals::JiraExternalSystemApprovalsCollector::new(
                self.client.clone(),
                key,
            )));
        }
        if self.selected.iter().any(|s| s == "jira-public-content") {
            // TODO: wire project_keys from AppConfig via factory constructor
            let key = "MKT".to_string();
            v.push(Box::new(super::public_content_review::JiraPublicContentReviewCollector::new(
                self.client.clone(),
                key,
            )));
        }
        if self.selected.iter().any(|s| s == "jira-logging-coordination") {
            // TODO: wire project_keys from AppConfig via factory constructor
            let key = "SEC".to_string();
            v.push(Box::new(super::logging_coordination::JiraLoggingCoordinationCollector::new(
                self.client.clone(),
                key,
            )));
        }
        if self.selected.iter().any(|s| s == "jira-audit-posture") {
            // TODO: wire project_keys from AppConfig via factory constructor
            let key = "SEC".to_string();
            v.push(Box::new(super::audit_posture_change::JiraAuditPostureChangeCollector::new(
                self.client.clone(),
                key,
            )));
        }
        if self.selected.iter().any(|s| s == "jira-isa-annual") {
            // TODO: wire project_keys from AppConfig via factory constructor
            let key = "SEC".to_string();
            v.push(Box::new(super::isa_annual_review::JiraIsaAnnualReviewCollector::new(
                self.client.clone(),
                key,
            )));
        }
        if self.selected.iter().any(|s| s == "jira-change-retention") {
            // TODO: wire project_keys from AppConfig via factory constructor
            let key = "CHG".to_string();
            v.push(Box::new(super::change_retention::JiraChangeRetentionCollector::new(
                self.client.clone(),
                key,
            )));
        }
        if self.selected.iter().any(|s| s == "jira-baseline-exceptions") {
            // TODO: wire project_keys from AppConfig via factory constructor
            let key = "SEC".to_string();
            v.push(Box::new(super::baseline_exceptions::JiraBaselineExceptionsCollector::new(
                self.client.clone(),
                key,
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
