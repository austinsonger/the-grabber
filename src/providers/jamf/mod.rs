pub mod computer_config_profiles;
pub mod computer_groups;
pub mod computers;
pub mod factory;
pub mod mobile_config_profiles;
pub mod mobile_devices;
pub mod mobile_device_groups;
pub mod patch_compliance;
pub mod patch_titles;
pub mod policies;

// Authentication:
//   POST {base_url}/api/oauth/token  (client_id + client_secret, grant_type=client_credentials)
//   -> Authorization: Bearer <access_token> on every subsequent request.
//
// Base URL: per-tenant Jamf Pro server (e.g. https://acme.jamfcloud.com, or a
// self-hosted URL). Supplied via the `jamf_base_url` config field or the
// `JAMF_BASE_URL` env var.
