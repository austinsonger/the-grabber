pub mod access_certification_campaigns;
pub mod apps;
pub mod automated_provisioning_events;
pub mod deprovisioning_timeliness;
pub mod factors;
pub mod factory;
pub mod group_inventory_shared;
pub mod groups;
pub mod lifecycle_hris_config;
pub mod policies;
pub mod risk_account_suspend_timing;
pub mod system_log;
pub mod threat_insight_detections;
pub mod users;

// Authentication:
//   Authorization: SSWS <api_token>
//
// Base URL: per-tenant (e.g. https://acme.okta.com or https://acme.oktapreview.com).
// Supplied via the `okta_domain` config field or the `OKTA_DOMAIN` env var.
