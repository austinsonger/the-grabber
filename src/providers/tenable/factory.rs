use tenable_rs::TenableClient;

use crate::evidence::{CsvCollector, EvidenceCollector, JsonCollector};
use crate::providers::{CloudProvider, ProviderFactory};

use super::assets::TenableAssetsCollector;
use super::compliance::TenableComplianceCollector;
use super::pci_asv::TenablePciAsvCollector;
use super::vulnerabilities::TenableVulnerabilitiesCollector;
use super::was::TenableWasCollector;

pub struct TenableProviderFactory {
    client: TenableClient,
    site_name: String,
    selected: Vec<String>,
    selected_scan_ids: Vec<i64>,
    selected_was_scan_ids: Vec<String>,
}

impl TenableProviderFactory {
    pub fn new(
        client: TenableClient,
        site_name: String,
        selected: Vec<String>,
        selected_scan_ids: Vec<i64>,
        selected_was_scan_ids: Vec<String>,
    ) -> Self {
        Self {
            client,
            site_name,
            selected,
            selected_scan_ids,
            selected_was_scan_ids,
        }
    }
}

impl ProviderFactory for TenableProviderFactory {
    fn provider(&self) -> CloudProvider {
        CloudProvider::Tenable
    }
    fn account_id(&self) -> &str {
        &self.site_name
    }
    fn region(&self) -> &str {
        ""
    } // Tenable has no region concept

    fn csv_collectors(&self) -> Vec<Box<dyn CsvCollector>> {
        let mut v: Vec<Box<dyn CsvCollector>> = Vec::new();
        if self.selected.iter().any(|s| s == "tenable-vulns") {
            v.push(Box::new(TenableVulnerabilitiesCollector::new(
                self.client.clone(),
                self.selected_scan_ids.clone(),
            )));
        }
        if self.selected.iter().any(|s| s == "tenable-was") {
            v.push(Box::new(TenableWasCollector::new(
                self.client.clone(),
                self.selected_was_scan_ids.clone(),
            )));
        }
        if self.selected.iter().any(|s| s == "tenable-pci-asv") {
            v.push(Box::new(TenablePciAsvCollector::new(self.client.clone())));
        }
        if self.selected.iter().any(|s| s == "tenable-assets") {
            v.push(Box::new(TenableAssetsCollector::new(self.client.clone())));
        }
        if self.selected.iter().any(|s| s == "tenable-compliance") {
            v.push(Box::new(TenableComplianceCollector::new(
                self.client.clone(),
            )));
        }
        v
    }
    fn json_collectors(&self) -> Vec<Box<dyn JsonCollector>> {
        vec![]
    }
    fn evidence_collectors(&self) -> Vec<Box<dyn EvidenceCollector>> {
        vec![]
    }
}
