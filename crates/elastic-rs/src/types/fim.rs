/// One File Integrity Monitoring event from the `logs-file_integrity.event-*`
/// data stream. Field coverage varies by OS/agent version, so the raw
/// `_source` is kept and read defensively via dotted-path lookup — the same
/// pattern used by `types::alert::Alert`.
#[derive(Debug, Clone)]
pub struct FimEvent {
    pub id: String,
    pub source: serde_json::Value,
}

impl FimEvent {
    /// Render a field as a display string regardless of its JSON type.
    /// Returns an empty string when the field is absent or null.
    pub fn field_string(&self, dotted_path: &str) -> String {
        let mut cur = &self.source;
        for part in dotted_path.split('.') {
            match cur.get(part) {
                Some(v) => cur = v,
                None => return String::new(),
            }
        }
        match cur {
            serde_json::Value::String(s) => s.clone(),
            v if !v.is_null() => v.to_string(),
            _ => String::new(),
        }
    }
}
