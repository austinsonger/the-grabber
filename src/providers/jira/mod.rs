pub mod factory;
pub mod issues;
pub mod projects;

// Authentication:
//   Authorization: Basic base64(email:api_token)
//
// Base URL: per-tenant (e.g. https://acme.atlassian.net).
// Supplied via the `jira_domain` config field or the `JIRA_DOMAIN` env var.
// Email + token come from `jira_email` / `jira_api_token` (or `JIRA_EMAIL` / `JIRA_API_TOKEN`).
