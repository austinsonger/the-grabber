use anyhow::{bail, Result};
use once_cell::sync::Lazy;

const SCHEMA_JSON: &str = include_str!("../../../assets/oscal_poam_schema.v1.1.2.json");

static SCHEMA: Lazy<jsonschema::Validator> = Lazy::new(|| {
    let schema_value: serde_json::Value =
        serde_json::from_str(SCHEMA_JSON).expect("bundled OSCAL schema is valid JSON");
    jsonschema::validator_for(&schema_value).expect("bundled OSCAL schema compiles")
});

/// Validates an arbitrary JSON value against the bundled OSCAL POA&M schema.
/// Takes `serde_json::Value` (not a typed document) so Task 2's model can be
/// validated purely through its `Serialize` output.
pub(in crate::poam) fn validate_document(doc: &serde_json::Value) -> Result<()> {
    let errors: Vec<String> = SCHEMA
        .iter_errors(doc)
        .map(|e| format!("{} (at {})", e, e.instance_path))
        .collect();
    if !errors.is_empty() {
        bail!("OSCAL POA&M document failed schema validation:\n{}", errors.join("\n"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn rejects_document_missing_required_top_level_key() {
        let doc = json!({ "not-plan-of-action-and-milestones": {} });
        let result = validate_document(&doc);
        assert!(result.is_err(), "expected validation to fail for a document with no plan-of-action-and-milestones key");
    }
}
