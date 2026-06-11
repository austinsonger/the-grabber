use jira_rs::JiraClient;

use crate::evidence::{CsvCollector, EvidenceCollector, JsonCollector};
use crate::providers::{CloudProvider, ProviderFactory};

pub struct JiraProviderFactory {
    client: JiraClient,
    tenant_name: String,
    selected: Vec<String>,
}

impl JiraProviderFactory {
    pub fn new(client: JiraClient, tenant_name: String, selected: Vec<String>) -> Self {
        Self {
            client,
            tenant_name,
            selected,
        }
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
            v.push(Box::new(super::issues::JiraIssuesCollector::new(
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
