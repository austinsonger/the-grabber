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

        let Some((_, new_risk, new_item)) = current_by_key.get(&key) else {
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

        // Present in both -> refresh title/description/status in place, keep uuid.
        item.title = new_item.title.clone();
        item.description = new_item.description.clone();
        if let Some(risk) = baseline
            .risks
            .iter_mut()
            .find(|r| item.related_risks.iter().any(|rr| rr.risk_uuid == r.uuid))
        {
            risk.status = new_risk.status;
        }
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
    fn finding_reappearing_after_close_reopens_risk_status() {
        let triple1 = build_inspector2_triple(&finding("k1", "ACTIVE"), "2026-01-01T00:00:00Z");
        let (baseline1, _, _) = reconcile_document(None, vec![triple1], "Test POA&M", "2026-01-01T00:00:00Z");

        // Run 2: finding absent from the scan -> risk transitions to Closed.
        let (baseline2, _, closed) = reconcile_document(Some(baseline1), vec![], "Test POA&M", "2026-02-01T00:00:00Z");
        assert_eq!(closed, 1);
        assert_eq!(baseline2.risks[0].status, RiskStatus::Closed);

        // Run 3: the same stable key reappears in the scan, active again.
        let triple3 = build_inspector2_triple(&finding("k1", "ACTIVE"), "2026-03-01T00:00:00Z");
        let (doc3, added, closed3) =
            reconcile_document(Some(baseline2), vec![triple3], "Test POA&M", "2026-03-01T00:00:00Z");

        assert_eq!(added, 0, "matched stable key must not be re-appended as a new finding");
        assert_eq!(closed3, 0);
        assert_eq!(doc3.poam_items.len(), 1, "must not duplicate the item");
        assert_eq!(
            doc3.risks[0].status,
            RiskStatus::Open,
            "risk status must be refreshed from the new scan, not remain Closed forever"
        );
    }

    #[test]
    fn finding_present_in_both_but_scanner_marks_it_closed_updates_risk_status() {
        let triple1 = build_inspector2_triple(&finding("k1", "ACTIVE"), "2026-01-01T00:00:00Z");
        let (baseline, _, _) = reconcile_document(None, vec![triple1], "Test POA&M", "2026-01-01T00:00:00Z");
        assert_eq!(baseline.risks[0].status, RiskStatus::Open);

        // Run 2: same stable key present again, but this time the scanner
        // itself reports the underlying finding as CLOSED/SUPPRESSED (e.g.
        // Inspector2 marks it CLOSED while it still appears in the export).
        let triple2 = build_inspector2_triple(&finding("k1", "CLOSED"), "2026-02-01T00:00:00Z");
        let (doc2, added, closed) =
            reconcile_document(Some(baseline), vec![triple2], "Test POA&M", "2026-02-01T00:00:00Z");

        assert_eq!(added, 0);
        assert_eq!(closed, 0, "this is an in-place status refresh, not the 'absent -> close' path");
        assert_eq!(doc2.poam_items.len(), 1);
        assert_eq!(
            doc2.risks[0].status,
            RiskStatus::Closed,
            "risk status must reflect the new scan's status, not the stale baseline Open status"
        );
    }

    #[test]
    fn custom_item_with_no_weakness_source_identifier_prop_survives_reconcile_untouched() {
        let triple = build_inspector2_triple(&finding("k1", "ACTIVE"), "2026-01-01T00:00:00Z");
        let (mut baseline, _, _) = reconcile_document(None, vec![triple], "Test POA&M", "2026-01-01T00:00:00Z");

        // Simulate a custom item added out-of-band (Task 7), i.e. one with no
        // "weakness-source-identifier" prop at all. Give it a non-empty value
        // in every field (including related_risks/related_observations) so a
        // regression that clears any one of them cannot hide behind an
        // already-empty default.
        let custom_item = crate::poam::oscal::PoamItem {
            uuid: "custom-uuid-0000".to_string(),
            title: "Manual risk acceptance".to_string(),
            description: "Accepted per CAB decision 2026-01".to_string(),
            props: vec![Prop { name: "finding-source".to_string(), value: "manual".to_string(), ns: None }],
            related_risks: vec![crate::poam::oscal::RelatedRisk {
                risk_uuid: "custom-risk-uuid-0000".to_string(),
            }],
            related_observations: vec![crate::poam::oscal::RelatedObservation {
                observation_uuid: "custom-observation-uuid-0000".to_string(),
            }],
        };
        // `PoamItem` derives `Clone` (and now `PartialEq`); snapshot it here
        // so we can assert the item that survives reconcile is byte-for-byte
        // identical to what went in, not just matching on uuid/title.
        let expected = custom_item.clone();

        baseline.poam_items.push(custom_item);
        let custom_items_before = baseline.poam_items.len();

        let (doc2, _, _) = reconcile_document(Some(baseline), vec![], "Test POA&M", "2026-02-01T00:00:00Z");

        assert_eq!(doc2.poam_items.len(), custom_items_before, "custom item must not be removed");
        let found_item = doc2
            .poam_items
            .iter()
            .find(|i| i.uuid == "custom-uuid-0000")
            .expect("custom item must still be present by uuid");
        assert_eq!(
            found_item, &expected,
            "custom item must be left completely untouched by reconcile -- every field, not just uuid/title"
        );
    }
}
