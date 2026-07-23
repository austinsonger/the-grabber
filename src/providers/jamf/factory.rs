use jamf_rs::JamfClient;

use crate::evidence::{CsvCollector, EvidenceCollector, JsonCollector};
use crate::providers::{CloudProvider, ProviderFactory};

pub struct JamfProviderFactory {
    client: JamfClient,
    tenant_name: String,
    selected: Vec<String>,
}

impl JamfProviderFactory {
    pub fn new(client: JamfClient, tenant_name: String, selected: Vec<String>) -> Self {
        Self {
            client,
            tenant_name,
            selected,
        }
    }
}

impl ProviderFactory for JamfProviderFactory {
    fn provider(&self) -> CloudProvider {
        CloudProvider::Jamf
    }
    fn account_id(&self) -> &str {
        &self.tenant_name
    }
    fn region(&self) -> &str {
        ""
    }

    fn csv_collectors(&self) -> Vec<Box<dyn CsvCollector>> {
        let mut v: Vec<Box<dyn CsvCollector>> = Vec::new();
        if self.selected.iter().any(|s| s == "jamf-computers") {
            v.push(Box::new(super::computers::JamfComputersCollector::new(
                self.client.clone(),
            )));
        }
        if self.selected.iter().any(|s| s == "jamf-mobile-devices") {
            v.push(Box::new(
                super::mobile_devices::JamfMobileDevicesCollector::new(self.client.clone()),
            ));
        }
        if self.selected.iter().any(|s| s == "jamf-computer-config-profiles") {
            v.push(Box::new(
                super::computer_config_profiles::JamfComputerConfigProfilesCollector::new(
                    self.client.clone(),
                ),
            ));
        }
        if self.selected.iter().any(|s| s == "jamf-mobile-config-profiles") {
            v.push(Box::new(
                super::mobile_config_profiles::JamfMobileConfigProfilesCollector::new(
                    self.client.clone(),
                ),
            ));
        }
        if self.selected.iter().any(|s| s == "jamf-computer-groups") {
            v.push(Box::new(super::computer_groups::JamfComputerGroupsCollector::new(
                self.client.clone(),
            )));
        }
        if self.selected.iter().any(|s| s == "jamf-mobile-device-groups") {
            v.push(Box::new(
                super::mobile_device_groups::JamfMobileDeviceGroupsCollector::new(self.client.clone()),
            ));
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
