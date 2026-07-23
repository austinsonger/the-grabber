//! JumpCloud provider.
//!
//! Authentication:
//!   x-api-key: <api_token>
//!   x-org-id:  <org_id>   (only for MTP/MSP org-scoped keys)
//!
//! Base URL: `https://console.jumpcloud.com` unless overridden per account.

pub mod admin_roles;
pub mod applications;
pub mod directory_alerts;
pub mod directory_insights;
pub mod factory;
pub mod mfa_factors;
pub mod password_policy;
pub mod policies;
pub mod session_policy;
pub mod systems;
pub mod system_groups;
pub mod system_user_associations;
pub mod user_groups;
pub mod users;
