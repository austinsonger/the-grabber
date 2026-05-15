//! Azure provider collectors.
//!
//! Each sub-module implements one or more `CsvCollector` or `JsonCollector`
//! traits (from `crate::evidence`) for an Azure service.

pub mod acr;
pub mod aks;
pub mod app_service;
pub mod defender;
pub mod factory;
pub mod key_vault;
pub mod monitor_alerts;
pub mod nsg;
pub mod policy;
