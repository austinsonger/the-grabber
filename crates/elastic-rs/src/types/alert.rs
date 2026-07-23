use serde::Deserialize;

/// One alert document from `.alerts-security.alerts-*`. Field coverage
/// varies by rule type, so the raw `_source` is kept and common fields are
/// read defensively via dotted-path lookup rather than a fixed struct.
#[derive(Debug, Clone)]
pub struct Alert {
    pub id: String,
    pub index: String,
    pub source: serde_json::Value,
}

impl Alert {
    /// Look up a dotted field path in the nested `_source` document
    /// (e.g. `"kibana.alert.rule.name"`).
    pub fn field(&self, dotted_path: &str) -> Option<&serde_json::Value> {
        let mut cur = &self.source;
        for part in dotted_path.split('.') {
            cur = cur.get(part)?;
        }
        Some(cur)
    }

    /// Render a field as a display string regardless of its JSON type.
    /// Returns an empty string when the field is absent or null.
    pub fn field_string(&self, dotted_path: &str) -> String {
        match self.field(dotted_path) {
            Some(serde_json::Value::String(s)) => s.clone(),
            Some(v) if !v.is_null() => v.to_string(),
            _ => String::new(),
        }
    }
}

#[derive(Debug, Deserialize)]
pub(crate) struct EsHit {
    #[serde(rename = "_id")]
    pub id: String,
    #[serde(rename = "_index")]
    pub index: String,
    #[serde(rename = "_source")]
    pub source: serde_json::Value,
}

#[derive(Debug, Deserialize)]
pub(crate) struct EsHits {
    pub hits: Vec<EsHit>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct EsSearchResponse {
    pub hits: EsHits,
}
