use serde::Deserialize;

/// One enrolled Fleet agent, as returned by `GET /api/fleet/agents`.
#[derive(Debug, Clone, Deserialize)]
pub struct FleetAgent {
    pub id: String,
    #[serde(default)]
    pub policy_id: Option<String>,
    #[serde(default)]
    pub policy_revision: Option<i64>,
    #[serde(default)]
    pub active: bool,
    #[serde(default)]
    pub enrolled_at: Option<String>,
    #[serde(default)]
    pub last_checkin: Option<String>,
    #[serde(default)]
    pub last_checkin_status: Option<String>,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub agent: Option<AgentVersion>,
    /// Host/OS metadata as a raw JSON blob — its exact nested shape varies
    /// by Elastic Agent version, so callers read specific fields (e.g.
    /// `host.hostname`) defensively rather than through a fixed struct.
    #[serde(default)]
    pub local_metadata: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AgentVersion {
    #[serde(default)]
    pub version: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct FleetAgentsFindResponse {
    pub items: Vec<FleetAgent>,
    pub total: u64,
}
