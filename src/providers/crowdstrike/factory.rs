use crowdstrike_rs::CrowdStrikeClient;

use crate::evidence::{CsvCollector, EvidenceCollector, JsonCollector};
use crate::providers::{CloudProvider, ProviderFactory};

use super::alerts::CrowdStrikeAlertsCollector;
use super::hosts::CrowdStrikeHostsCollector;
use super::prevention_policies::CrowdStrikePreventionPoliciesCollector;
use super::sensor_update_policies::CrowdStrikeSensorUpdatePoliciesCollector;
use super::vulnerabilities::CrowdStrikeVulnerabilitiesCollector;

pub struct CrowdStrikeProviderFactory {
    client: CrowdStrikeClient,
    tenant_name: String,
    selected: Vec<String>,
}

impl CrowdStrikeProviderFactory {
    pub fn new(client: CrowdStrikeClient, tenant_name: String, selected: Vec<String>) -> Self {
        Self {
            client,
            tenant_name,
            selected,
        }
    }
}

impl ProviderFactory for CrowdStrikeProviderFactory {
    fn provider(&self) -> CloudProvider {
        CloudProvider::CrowdStrike
    }
    fn account_id(&self) -> &str {
        &self.tenant_name
    }
    fn region(&self) -> &str {
        "" // CrowdStrike has no region concept
    }

    fn csv_collectors(&self) -> Vec<Box<dyn CsvCollector>> {
        let mut v: Vec<Box<dyn CsvCollector>> = Vec::new();
        if self.selected.iter().any(|s| s == "crowdstrike-hosts") {
            v.push(Box::new(CrowdStrikeHostsCollector::new(
                self.client.clone(),
            )));
        }
        if self.selected.iter().any(|s| s == "crowdstrike-alerts") {
            v.push(Box::new(CrowdStrikeAlertsCollector::new(
                self.client.clone(),
            )));
        }
        if self
            .selected
            .iter()
            .any(|s| s == "crowdstrike-vulnerabilities")
        {
            v.push(Box::new(CrowdStrikeVulnerabilitiesCollector::new(
                self.client.clone(),
            )));
        }
        if self
            .selected
            .iter()
            .any(|s| s == "crowdstrike-prevention-policies")
        {
            v.push(Box::new(CrowdStrikePreventionPoliciesCollector::new(
                self.client.clone(),
            )));
        }
        if self
            .selected
            .iter()
            .any(|s| s == "crowdstrike-sensor-update-policies")
        {
            v.push(Box::new(CrowdStrikeSensorUpdatePoliciesCollector::new(
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
