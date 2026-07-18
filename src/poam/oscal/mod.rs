mod build;
mod custom_item;
mod model;
mod reconcile;
mod tenable_build;
mod validate;

use std::fs;
use std::path::Path;

use anyhow::{Context, Result};
use uuid::Uuid;

pub(super) use build::build_inspector2_triple;
pub(super) use custom_item::{add_custom_item, remove_custom_item, CustomItemInput};
pub(super) use model::{
    Characterization, Facet, Metadata, Observation, Origin, OriginActor,
    PlanOfActionAndMilestones, PoamItem, Prop, RelatedObservation, RelatedRisk, Risk,
    RiskLogEntry, RiskStatus,
};
pub(super) use reconcile::reconcile_document;
pub(super) use tenable_build::{build_tenable_compliance_triple, build_tenable_vuln_triple};
use validate::validate_document;

/// Assembles a full OSCAL POA&M document from a set of observation/risk/
/// poam-item triples (one per finding, as produced by `build_inspector2_triple`).
/// Each triple's three parts are pushed into their respective top-level
/// arrays; cross-linking between them was already established when the
/// triple was built.
pub(super) fn assemble_document(
    title: &str,
    triples: Vec<(Observation, Risk, PoamItem)>,
    now: &str,
) -> PlanOfActionAndMilestones {
    let mut observations = Vec::with_capacity(triples.len());
    let mut risks = Vec::with_capacity(triples.len());
    let mut poam_items = Vec::with_capacity(triples.len());
    for (o, r, i) in triples {
        observations.push(o);
        risks.push(r);
        poam_items.push(i);
    }

    PlanOfActionAndMilestones {
        uuid: Uuid::new_v4().to_string(),
        metadata: Metadata {
            title: title.to_string(),
            last_modified: now.to_string(),
            version: "1".to_string(),
            oscal_version: "1.1.2".to_string(),
        },
        observations,
        risks,
        poam_items,
    }
}

/// Validates `doc` against the bundled OSCAL schema and, only if that
/// succeeds, writes it to `path` as pretty-printed JSON (creating parent
/// directories as needed). Never leaves an invalid document on disk.
pub(super) fn write_oscal_document(path: &Path, doc: &PlanOfActionAndMilestones) -> Result<()> {
    let wrapped = serde_json::json!({ "plan-of-action-and-milestones": doc });
    validate_document(&wrapped).context("generated OSCAL POA&M failed schema validation")?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("cannot create directory {}", parent.display()))?;
    }
    let json = serde_json::to_string_pretty(&wrapped).context("serialize OSCAL POA&M")?;
    fs::write(path, json).with_context(|| format!("cannot write {}", path.display()))?;
    Ok(())
}

/// Reads back a previously written OSCAL POA&M document. Returns `Ok(None)`
/// if `path` does not exist, so callers can distinguish "no baseline yet"
/// from an actual read/parse error.
pub(super) fn read_oscal_document(path: &Path) -> Result<Option<PlanOfActionAndMilestones>> {
    if !path.exists() {
        return Ok(None);
    }
    let contents = fs::read_to_string(path)
        .with_context(|| format!("cannot read {}", path.display()))?;
    let wrapped: serde_json::Value =
        serde_json::from_str(&contents).context("parse existing OSCAL POA&M as JSON")?;
    let inner = wrapped
        .get("plan-of-action-and-milestones")
        .context("existing OSCAL POA&M missing 'plan-of-action-and-milestones' key")?;
    let doc: PlanOfActionAndMilestones =
        serde_json::from_value(inner.clone()).context("deserialize existing OSCAL POA&M")?;
    Ok(Some(doc))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::poam::csv_reader::CsvFinding;
    use std::collections::HashMap;
    use tempfile::tempdir;

    fn finding(stable_key: &str, cve: &str) -> CsvFinding {
        let mut values = HashMap::new();
        values.insert("cveid".to_string(), cve.to_string());
        values.insert("status".to_string(), "ACTIVE".to_string());
        CsvFinding::new_for_test(format!("arn:{stable_key}"), stable_key.to_string(), values)
    }

    #[test]
    fn assemble_document_produces_valid_metadata_and_items() {
        let triple = build_inspector2_triple(&finding("k1", "CVE-2026-0001"), "2026-07-17T00:00:00Z");
        let doc = assemble_document("Test Account POA&M", vec![triple], "2026-07-17T00:00:00Z");

        assert_eq!(doc.metadata.title, "Test Account POA&M");
        assert_eq!(doc.metadata.oscal_version, "1.1.2");
        assert_eq!(doc.metadata.last_modified, "2026-07-17T00:00:00Z");
        assert_eq!(doc.metadata.version, "1");
        assert_eq!(doc.poam_items.len(), 1);
        assert_eq!(doc.observations.len(), 1);
        assert_eq!(doc.risks.len(), 1);
    }

    #[test]
    fn write_then_read_round_trips_and_validates() {
        let triple = build_inspector2_triple(&finding("k1", "CVE-2026-0001"), "2026-07-17T00:00:00Z");
        let doc = assemble_document("Test Account POA&M", vec![triple], "2026-07-17T00:00:00Z");

        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("FedRAMP-POAM.oscal.json");
        write_oscal_document(&path, &doc).expect("write should validate and succeed");

        let read_back = read_oscal_document(&path).expect("read").expect("document should exist");
        assert_eq!(read_back.poam_items.len(), 1);
        assert_eq!(read_back.metadata.title, "Test Account POA&M");
    }

    #[test]
    fn read_missing_file_returns_none_not_error() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("does-not-exist.oscal.json");
        let result = read_oscal_document(&path).expect("missing file is not an error");
        assert!(result.is_none());
    }
}
