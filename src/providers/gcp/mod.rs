//! GCP provider — all cloud collectors for Google Cloud Platform.
//!
//! Every submodule is gated by the `gcp` feature flag (inherited from the parent
//! `providers` module, which is already inside `#[cfg(feature = "gcp")]`).

pub mod asset_inventory;
pub mod audit_logs_config;
pub mod cloud_armor;
pub mod cloud_audit_logs;
pub mod cloud_dns;
pub mod cloud_dlp;
pub mod cloud_functions;
pub mod cloud_monitoring;
pub mod cloud_run;
pub mod cloud_sql;
pub mod cloud_sql_backups;
pub mod cloud_storage_config;
pub mod cloud_storage_inventory;
pub mod cloud_storage_policies;
pub mod compute_config;
pub mod compute_inventory;
pub mod factory;
pub mod filestore;
pub mod gke;
pub mod iam_policies;
pub mod iam_service_account_keys;
pub mod iam_service_accounts;
pub mod kms;
pub mod kms_policies;
pub mod memorystore;
pub mod org_policy;
pub mod organizations;
pub mod persistent_disk;
pub mod pubsub_topics;
pub mod scc_config;
pub mod scc_findings;
pub mod scc_standards;
pub mod scc_vulnerabilities;
pub mod secret_manager;
pub mod secret_manager_extended;
pub mod vpc;
pub mod vpc_flow_logs;

pub(crate) mod client;
