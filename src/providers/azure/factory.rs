//! Azure provider factory.
//!
//! `AzureProviderFactory` is the entry point for instantiating Azure collectors.
//! It holds a shared credential and subscription ID, and produces lists of
//! `CsvCollector` and `JsonCollector` instances for the selected Azure services.

use std::sync::Arc;

use crate::evidence::{CsvCollector, JsonCollector};
use crate::providers::azure::{
    acr::AcrCollector,
    aks::AksCollector,
    app_service::AppServiceCollector,
    defender::DefenderCollector,
    key_vault::KeyVaultCollector,
    monitor_alerts::MonitorAlertsCollector,
    nsg::NsgCollector,
    policy::PolicyCollector,
};

/// Factory for Azure evidence collectors.
pub struct AzureProviderFactory {
    /// Azure credential shared by all collectors.
    credential:      Arc<dyn azure_core::auth::TokenCredential>,
    /// Azure subscription ID to collect from.
    subscription_id: String,
    /// Selector keys for which collectors are enabled.  An empty list means
    /// all collectors are enabled.
    selected:        Vec<String>,
}

impl AzureProviderFactory {
    /// Create a new factory.
    ///
    /// # Arguments
    /// * `credential`      – Any type that implements
    ///   `azure_core::auth::TokenCredential` (e.g. `DefaultAzureCredential`).
    /// * `subscription_id` – Azure subscription UUID.
    /// * `selected`        – Optional list of collector selector keys.  Pass
    ///   an empty `Vec` to enable every collector.
    pub fn new(
        credential: Arc<dyn azure_core::auth::TokenCredential>,
        subscription_id: String,
        selected: Vec<String>,
    ) -> Self {
        Self { credential, subscription_id, selected }
    }

    fn is_selected(&self, key: &str) -> bool {
        self.selected.is_empty() || self.selected.iter().any(|s| s == key)
    }

    /// Return the list of CSV-based Azure collectors that match the selection.
    pub fn csv_collectors(&self) -> Vec<Box<dyn CsvCollector>> {
        let mut out: Vec<Box<dyn CsvCollector>> = Vec::new();

        if self.is_selected("azure-aks") {
            out.push(Box::new(AksCollector::new(
                Arc::clone(&self.credential),
                self.subscription_id.clone(),
            )));
        }
        if self.is_selected("azure-acr") {
            out.push(Box::new(AcrCollector::new(
                Arc::clone(&self.credential),
                self.subscription_id.clone(),
            )));
        }
        if self.is_selected("azure-app-service") {
            out.push(Box::new(AppServiceCollector::new(
                Arc::clone(&self.credential),
                self.subscription_id.clone(),
            )));
        }
        if self.is_selected("azure-defender") {
            out.push(Box::new(DefenderCollector::new(
                Arc::clone(&self.credential),
                self.subscription_id.clone(),
            )));
        }
        if self.is_selected("azure-nsg") {
            out.push(Box::new(NsgCollector::new(
                Arc::clone(&self.credential),
                self.subscription_id.clone(),
            )));
        }
        if self.is_selected("azure-monitor-alerts") {
            out.push(Box::new(MonitorAlertsCollector::new(
                Arc::clone(&self.credential),
                self.subscription_id.clone(),
            )));
        }

        out
    }

    /// Return the list of JSON-based Azure collectors that match the selection.
    pub fn json_collectors(&self) -> Vec<Box<dyn JsonCollector>> {
        let mut out: Vec<Box<dyn JsonCollector>> = Vec::new();

        if self.is_selected("azure-key-vault") {
            out.push(Box::new(KeyVaultCollector::new(
                Arc::clone(&self.credential),
                self.subscription_id.clone(),
            )));
        }
        if self.is_selected("azure-policy") {
            out.push(Box::new(PolicyCollector::new(
                Arc::clone(&self.credential),
                self.subscription_id.clone(),
            )));
        }

        out
    }
}
