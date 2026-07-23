//! JumpCloud provider.
//!
//! Authentication:
//!   x-api-key: <api_token>
//!   x-org-id:  <org_id>   (only for MTP/MSP org-scoped keys)
//!
//! Base URL: `https://console.jumpcloud.com` unless overridden per account.

pub mod applications;
pub mod directory_insights;
pub mod factory;
pub mod mfa_factors;
pub mod policies;
pub mod user_groups;
pub mod users;
