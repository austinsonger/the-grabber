pub mod access_certification_campaigns;
pub mod apps;
pub mod automated_provisioning_events;
pub mod contractor_deprovisioning;
pub mod deprovisioning_timeliness;
pub mod factors;
pub mod factory;
pub mod group_inventory_shared;
pub mod group_membership_change_log;
pub mod groups;
pub mod lifecycle_hris_config;
pub mod offboarding_sla;
pub mod password_policy_first_use;
pub mod policies;
pub mod prod_access_recertification;
pub mod publisher_group_membership;
pub mod risk_account_suspend_timing;
pub mod session_policy;
pub mod shared_account_broker_config;
pub mod signin_widget_config;
pub mod stig;
pub mod stig_compliance;
pub mod system_log;
pub mod threat_insight_detections;
pub mod transfer_access_diff;
pub mod users;

// Authentication:
//   Authorization: SSWS <api_token>
//
// Base URL: per-tenant (e.g. https://acme.okta.com or https://acme.oktapreview.com).
// Supplied via the `okta_domain` config field or the `OKTA_DOMAIN` env var.
