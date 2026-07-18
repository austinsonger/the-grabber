use std::collections::HashMap;

use super::model::{Observation, PlanOfActionAndMilestones, PoamItem, Risk, RiskStatus};
use super::{assemble_document, Metadata};

const STABLE_KEY_PROP: &str = "weakness-source-identifier";

/// Reconciles a freshly-scanned set of observation/risk/poam-item triples
/// against a previous run's OSCAL POA&M document (if any), matching items
/// across runs by their `weakness-source-identifier` prop so uuids stay
/// stable and findings are closed (not deleted) when they no longer appear.
/// Poam-items with no such prop (custom items, e.g. added by hand or by a
/// later task) are left completely untouched.
pub(in crate::poam) fn reconcile_document(
    baseline: Option<PlanOfActionAndMilestones>,
    current_triples: Vec<(Observation, Risk, PoamItem)>,
    title: &str,
    now: &str,
) -> (PlanOfActionAndMilestones, usize, usize) {
    let current_by_key: HashMap<String, (Observation, Risk, PoamItem)> = current_triples
        .into_iter()
        .filter_map(|(o, r, i)| stable_key_of(&i).map(|k| (k, (o, r, i))))
        .collect();

    let Some(mut baseline) = baseline else {
        let added = current_by_key.len();
        let doc = assemble_document(title, current_by_key.into_values().collect(), now);
        return (doc, added, 0);
    };

    let mut added = 0;
    let mut closed = 0;
    let mut seen_keys: Vec<String> = Vec::new();

    // Update or leave-in-place every existing scanner-derived item.
    for item in baseline.poam_items.iter_mut() {
        let Some(key) = stable_key_of(item) else {
            continue; // custom item — never touched by scanner reconcile
        };
        seen_keys.push(key.clone());

        let Some((_, _, new_item)) = current_by_key.get(&key) else {
            // Present in baseline, absent from current scan -> close it.
            if let Some(risk) = baseline
                .risks
                .iter_mut()
                .find(|r| item.related_risks.iter().any(|rr| rr.risk_uuid == r.uuid))
            {
                if risk.status != RiskStatus::Closed {
                    risk.status = RiskStatus::Closed;
                    closed += 1;
                }
            }
            continue;
        };

        // Present in both -> refresh title/description in place, keep uuid.
        item.title = new_item.title.clone();
        item.description = new_item.description.clone();
    }

    // Append findings that are new since the baseline.
    for (key, (observation, risk, item)) in current_by_key {
        if seen_keys.contains(&key) {
            continue;
        }
        baseline.observations.push(observation);
        baseline.risks.push(risk);
        baseline.poam_items.push(item);
        added += 1;
    }

    baseline.metadata = Metadata {
        title: title.to_string(),
        last_modified: now.to_string(),
        version: bump_version(&baseline.metadata.version),
        oscal_version: "1.1.2".to_string(),
    };

    (baseline, added, closed)
}

fn stable_key_of(item: &PoamItem) -> Option<String> {
    item.props
        .iter()
        .find(|p| p.name == STABLE_KEY_PROP)
        .map(|p| p.value.clone())
}

fn bump_version(current: &str) -> String {
    current
        .parse::<u64>()
        .map(|n| (n + 1).to_string())
        .unwrap_or_else(|_| "1".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::poam::oscal::build::build_inspector2_triple;
    use crate::poam::oscal::{assemble_document, Prop};
    use crate::poam::csv_reader::CsvFinding;
    use std::collections::HashMap;

    fn finding(stable_key: &str, status: &str) -> CsvFinding {
        let mut values = HashMap::new();
        values.insert("status".to_string(), status.to_string());
        values.insert("cveid".to_string(), stable_key.to_string());
        CsvFinding::new_for_test(format!("arn:{stable_key}"), stable_key.to_string(), values)
    }

    #[test]
    fn first_run_with_no_baseline_appends_all_as_new() {
        let triples = vec![build_inspector2_triple(&finding("k1", "ACTIVE"), "2026-01-01T00:00:00Z")];
        let (doc, added, closed) = reconcile_document(None, triples, "Test POA&M", "2026-01-01T00:00:00Z");
        assert_eq!(added, 1);
        assert_eq!(closed, 0);
        assert_eq!(doc.poam_items.len(), 1);
    }

    #[test]
    fn second_run_same_finding_keeps_same_uuid_no_duplicate() {
        let triple1 = build_inspector2_triple(&finding("k1", "ACTIVE"), "2026-01-01T00:00:00Z");
        let (baseline, _, _) = reconcile_document(None, vec![triple1], "Test POA&M", "2026-01-01T00:00:00Z");
        let original_uuid = baseline.poam_items[0].uuid.clone();

        let triple2 = build_inspector2_triple(&finding("k1", "ACTIVE"), "2026-02-01T00:00:00Z");
        let (doc2, added, closed) = reconcile_document(Some(baseline), vec![triple2], "Test POA&M", "2026-02-01T00:00:00Z");

        assert_eq!(added, 0, "finding already present in baseline should not count as newly added");
        assert_eq!(closed, 0);
        assert_eq!(doc2.poam_items.len(), 1, "same stable key must not produce a duplicate item");
        assert_eq!(doc2.poam_items[0].uuid, original_uuid, "uuid must be stable across runs");
    }

    #[test]
    fn finding_absent_from_new_scan_transitions_to_closed_not_deleted() {
        let triple1 = build_inspector2_triple(&finding("k1", "ACTIVE"), "2026-01-01T00:00:00Z");
        let (baseline, _, _) = reconcile_document(None, vec![triple1], "Test POA&M", "2026-01-01T00:00:00Z");

        let (doc2, added, closed) = reconcile_document(Some(baseline), vec![], "Test POA&M", "2026-02-01T00:00:00Z");

        assert_eq!(added, 0);
        assert_eq!(closed, 1);
        assert_eq!(doc2.poam_items.len(), 1, "closed item must remain in the document, not be deleted");
        assert_eq!(doc2.risks[0].status, super::super::RiskStatus::Closed);
    }

    #[test]
    fn custom_item_with_no_weakness_source_identifier_prop_survives_reconcile_untouched() {
        let triple = build_inspector2_triple(&finding("k1", "ACTIVE"), "2026-01-01T00:00:00Z");
        let (mut baseline, _, _) = reconcile_document(None, vec![triple], "Test POA&M", "2026-01-01T00:00:00Z");

        // Simulate a custom item added out-of-band (Task 7), i.e. one with no
        // "weakness-source-identifier" prop at all.
        baseline.poam_items.push(crate::poam::oscal::PoamItem {
            uuid: "custom-uuid-0000".to_string(),
            title: "Manual risk acceptance".to_string(),
            description: "Accepted per CAB decision 2026-01".to_string(),
            props: vec![Prop { name: "finding-source".to_string(), value: "manual".to_string(), ns: None }],
            related_risks: vec![],
            related_observations: vec![],
        });
        let custom_items_before = baseline.poam_items.len();

        let (doc2, _, _) = reconcile_document(Some(baseline), vec![], "Test POA&M", "2026-02-01T00:00:00Z");

        assert_eq!(doc2.poam_items.len(), custom_items_before, "custom item must not be removed");
        assert!(doc2.poam_items.iter().any(|i| i.uuid == "custom-uuid-0000" && i.title == "Manual risk acceptance"));
    }
}
