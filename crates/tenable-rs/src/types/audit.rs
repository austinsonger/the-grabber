use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    pub id: String,
    pub action: String,
    pub target: Option<EventTarget>,
    pub actor: Option<EventActor>,
    pub description: Option<String>,
    pub received: Option<String>,
    pub is_failure: Option<bool>,
    pub fields: Option<Vec<EventField>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventActor {
    pub id: Option<String>,
    pub name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventTarget {
    pub id: Option<String>,
    #[serde(rename = "type")]
    pub kind: Option<String>,
    pub name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventField {
    pub key: String,
    pub value: Option<String>,
}
