use serde::Deserialize;

/// One configured Kibana alerting connector (email, Slack, PagerDuty,
/// webhook, etc.), as returned by `GET /api/actions/connectors`.
#[derive(Debug, Clone, Deserialize)]
pub struct Connector {
    pub id: String,
    pub name: String,
    pub connector_type_id: String,
    #[serde(default)]
    pub is_preconfigured: bool,
    #[serde(default)]
    pub is_deprecated: bool,
    #[serde(default)]
    pub is_missing_secrets: bool,
    #[serde(default)]
    pub referenced_by_count: i64,
}
