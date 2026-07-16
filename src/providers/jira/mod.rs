pub mod audit_posture_change;
pub mod baseline_exceptions;
pub mod change_retention;
pub mod external_system_approvals;
pub mod factory;
pub mod isa_annual_review;
pub mod issues;
pub mod logging_coordination;
pub mod offboarding_sla;
pub mod projects;
pub mod public_content_review;
pub mod remote_access_approvals;

// Authentication:
//   Authorization: Basic base64(email:api_token)
//
// Base URL: per-tenant (e.g. https://acme.atlassian.net).
// Supplied via the `jira_domain` config field or the `JIRA_DOMAIN` env var.
// Email + token come from `jira_email` / `jira_api_token` (or `JIRA_EMAIL` / `JIRA_API_TOKEN`).
