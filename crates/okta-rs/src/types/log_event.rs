use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct OktaLogEvent {
    pub uuid: String,
    #[serde(default)]
    pub published: String,
    #[serde(default, rename = "eventType")]
    pub event_type: String,
    #[serde(default, rename = "displayMessage")]
    pub display_message: String,
    #[serde(default)]
    pub severity: Option<String>,
    #[serde(default)]
    pub outcome: Option<Outcome>,
    #[serde(default)]
    pub actor: Option<Actor>,
    #[serde(default)]
    pub client: serde_json::Value,
    #[serde(default)]
    pub target: serde_json::Value,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Outcome {
    #[serde(default)]
    pub result: String,
    #[serde(default)]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Actor {
    #[serde(default)]
    pub id: String,
    #[serde(default, rename = "displayName")]
    pub display_name: Option<String>,
    #[serde(default, rename = "alternateId")]
    pub alternate_id: Option<String>,
    #[serde(default, rename = "type")]
    pub actor_type: Option<String>,
}
