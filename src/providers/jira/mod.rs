pub mod allowlist_review;
pub mod audit_posture_change;
pub mod baseline_exceptions;
pub mod change_retention;
pub mod cp_test_poam;
pub mod cp_update_trigger;
pub mod dr_test_results;
pub mod external_system_approvals;
pub mod factory;
pub mod ir_cp_coordination;
pub mod ir_external_reporting;
pub mod ir_lessons_learned;
pub mod ir_severity_vs_rigor;
pub mod isa_annual_review;
pub mod issues;
pub mod logging_coordination;
pub mod offboarding_sla;
pub mod projects;
pub mod public_content_review;
pub mod remote_access_approvals;
pub mod special_protection_approvals;

// Authentication:
//   Authorization: Basic base64(email:api_token)
//
// Base URL: per-tenant (e.g. https://acme.atlassian.net).
// Supplied via the `jira_domain` config field or the `JIRA_DOMAIN` env var.
// Email + token come from `jira_email` / `jira_api_token` (or `JIRA_EMAIL` / `JIRA_API_TOKEN`).
