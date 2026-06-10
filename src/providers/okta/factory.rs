use okta_rs::OktaClient;

use crate::evidence::{CsvCollector, EvidenceCollector, JsonCollector};
use crate::providers::{CloudProvider, ProviderFactory};

pub struct OktaProviderFactory {
    client: OktaClient,
    tenant_name: String,
    selected: Vec<String>,
}

impl OktaProviderFactory {
    pub fn new(client: OktaClient, tenant_name: String, selected: Vec<String>) -> Self {
        Self {
            client,
            tenant_name,
            selected,
        }
    }
}

impl ProviderFactory for OktaProviderFactory {
    fn provider(&self) -> CloudProvider {
        CloudProvider::Okta
    }
    fn account_id(&self) -> &str {
        &self.tenant_name
    }
    fn region(&self) -> &str {
        ""
    }

    fn csv_collectors(&self) -> Vec<Box<dyn CsvCollector>> {
        let mut v: Vec<Box<dyn CsvCollector>> = Vec::new();
        if self.selected.iter().any(|s| s == "okta-users") {
            v.push(Box::new(super::users::OktaUsersCollector::new(
                self.client.clone(),
            )));
        }
        if self.selected.iter().any(|s| s == "okta-groups") {
            v.push(Box::new(super::groups::OktaGroupsCollector::new(
                self.client.clone(),
            )));
        }
        if self.selected.iter().any(|s| s == "okta-apps") {
            v.push(Box::new(super::apps::OktaAppsCollector::new(
                self.client.clone(),
            )));
        }
        if self.selected.iter().any(|s| s == "okta-factors") {
            v.push(Box::new(super::factors::OktaFactorsCollector::new(
                self.client.clone(),
            )));
        }
        v
    }
    fn json_collectors(&self) -> Vec<Box<dyn JsonCollector>> {
        let mut v: Vec<Box<dyn JsonCollector>> = Vec::new();
        if self.selected.iter().any(|s| s == "okta-group-members") {
            v.push(Box::new(super::groups::OktaGroupMembersCollector::new(
                self.client.clone(),
            )));
        }
        if self.selected.iter().any(|s| s == "okta-policies") {
            v.push(Box::new(super::policies::OktaPoliciesCollector::new(
                self.client.clone(),
            )));
        }
        v
    }
    fn evidence_collectors(&self) -> Vec<Box<dyn EvidenceCollector>> {
        let mut v: Vec<Box<dyn EvidenceCollector>> = Vec::new();
        if self.selected.iter().any(|s| s == "okta-system-log") {
            v.push(Box::new(super::system_log::OktaSystemLogCollector::new(
                self.client.clone(),
            )));
        }
        v
    }
}
