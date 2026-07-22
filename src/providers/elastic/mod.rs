pub mod alerts;
pub mod cases;
pub mod detection_rules;
pub mod exception_items;
pub mod factory;
pub mod fleet_agents;
pub mod roles;
pub mod users;

// Authentication:
//   Authorization: ApiKey <base64 id:api_key>  (the "Encoded" value from
//   Kibana's API Keys UI — works against both Kibana and Elasticsearch).
//
// Two base URLs are required: the Kibana URL (Detection Engine, Exception
// Lists, and Cases APIs) and the Elasticsearch URL (direct alert search).
// Supplied via the `elastic_kibana_url` / `elastic_es_url` / `elastic_api_key`
// config fields or the ELASTIC_KIBANA_URL / ELASTIC_ES_URL / ELASTIC_API_KEY
// env vars.
