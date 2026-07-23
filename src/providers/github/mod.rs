pub mod alerts;
pub mod audit_log;
pub mod branch_protection;
pub mod factory;
pub mod members;
pub mod repos;
pub mod security_settings;
pub mod teams;

// Authentication:
//   Authorization: Bearer <personal_access_token>
//
// Base URL: full REST API root, per-account (e.g. https://api.github.com for
// GitHub.com, or https://HOST/api/v3 for GitHub Enterprise Server). Supplied
// via the `github_base_url` config field or the `GITHUB_BASE_URL` env var.
