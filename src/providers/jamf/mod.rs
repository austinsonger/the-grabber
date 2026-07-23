pub mod computer_config_profiles;
pub mod computers;
pub mod factory;
pub mod mobile_config_profiles;
pub mod mobile_devices;

// Authentication:
//   POST {base_url}/api/oauth/token  (client_id + client_secret, grant_type=client_credentials)
//   -> Authorization: Bearer <access_token> on every subsequent request.
//
// Base URL: per-tenant Jamf Pro server (e.g. https://acme.jamfcloud.com, or a
// self-hosted URL). Supplied via the `jamf_base_url` config field or the
// `JAMF_BASE_URL` env var.
