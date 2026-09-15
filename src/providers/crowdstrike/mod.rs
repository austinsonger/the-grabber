pub mod alerts;
pub mod factory;
pub mod hosts;
pub mod prevention_policies;
pub mod sensor_update_policies;
pub mod vulnerabilities;

// Authentication:
//   OAuth2 client-credentials grant — POST /oauth2/token (client_id +
//   client_secret, form-encoded), returns a bearer token with a ~30 minute
//   lifespan. crowdstrike-rs caches and refreshes the token automatically;
//   collectors never touch it directly.
//
// Base URLs (Falcon "cloud"):
//   US-1 (default) — https://api.crowdstrike.com
//   US-2           — https://api.us-2.crowdstrike.com
//   EU-1           — https://api.eu-1.crowdstrike.com
//   US-GOV-1       — https://api.laggar.gcw.crowdstrike.com
