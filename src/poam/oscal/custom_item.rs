use std::ops::Not;

use anyhow::{bail, Result};
use uuid::Uuid;

use super::model::{Observation, PoamItem, Prop, RelatedObservation, RelatedRisk, Risk, RiskStatus};
use super::PlanOfActionAndMilestones;

const FINDING_SOURCE_PROP: &str = "finding-source";
const MANUAL_SOURCE_VALUE: &str = "manual";
const STABLE_KEY_PROP: &str = "weakness-source-identifier";

pub(in crate::poam) struct CustomItemInput {
    pub(in crate::poam) title: String,
    pub(in crate::poam) description: String,
    pub(in crate::poam) status: Option<String>,
    pub(in crate::poam) deadline: Option<String>,
}

pub(in crate::poam) fn add_custom_item(
    doc: &mut PlanOfActionAndMilestones,
    input: CustomItemInput,
    now: &str,
) -> Result<String> {
    if input.title.trim().is_empty() {
        bail!("custom POA&M item requires a non-empty title");
    }
    if input.description.trim().is_empty() {
        bail!("custom POA&M item requires a non-empty description");
    }

    let observation_uuid = Uuid::new_v4().to_string();
    let risk_uuid = Uuid::new_v4().to_string();
    let item_uuid = Uuid::new_v4().to_string();

    let status = match input.status.as_deref() {
        None | Some("open") => RiskStatus::Open,
        Some("closed") => RiskStatus::Closed,
        Some(other) => bail!("unsupported --poam-item-status '{other}' (expected open or closed)"),
    };

    doc.observations.push(Observation {
        uuid: observation_uuid.clone(),
        description: format!("Manually added: {}", input.title),
        methods: vec!["EXAMINE".to_string()],
        collected: now.to_string(),
        props: vec![Prop {
            name: FINDING_SOURCE_PROP.to_string(),
            value: MANUAL_SOURCE_VALUE.to_string(),
            ns: None,
        }],
    });

    doc.risks.push(Risk {
        uuid: risk_uuid.clone(),
        title: input.title.clone(),
        description: input.description.clone(),
        statement: input.description.clone(),
        status,
        characterizations: vec![],
        related_observations: vec![RelatedObservation {
            observation_uuid: observation_uuid.clone(),
        }],
    });

    doc.poam_items.push(PoamItem {
        uuid: item_uuid.clone(),
        title: input.title,
        description: input.description,
        props: vec![Prop {
            name: FINDING_SOURCE_PROP.to_string(),
            value: MANUAL_SOURCE_VALUE.to_string(),
            ns: None,
        }],
        related_risks: vec![RelatedRisk { risk_uuid }],
        related_observations: vec![RelatedObservation { observation_uuid }],
    });

    let _ = input.deadline; // deadline plumbing deferred — no schema field wired to it in v1 beyond acceptance

    Ok(item_uuid)
}

pub(in crate::poam) fn remove_custom_item(
    doc: &mut PlanOfActionAndMilestones,
    uuid: &str,
    now: &str,
) -> Result<bool> {
    let Some(item) = doc.poam_items.iter().find(|i| i.uuid == uuid) else {
        return Ok(false);
    };
    let is_custom = item.props.iter().any(|p| p.name == STABLE_KEY_PROP).not();
    if !is_custom {
        bail!("uuid {uuid} refers to a scanner-derived item; only custom items can be removed through --poam-remove-item");
    }

    let risk_uuid = item.related_risks.first().map(|rr| rr.risk_uuid.clone());
    let _ = now; // reserved for a future risk-log entry recording the closure event
    if let Some(risk_uuid) = risk_uuid {
        if let Some(risk) = doc.risks.iter_mut().find(|r| r.uuid == risk_uuid) {
            risk.status = RiskStatus::Closed;
        }
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::poam::oscal::assemble_document;

    #[test]
    fn add_custom_item_requires_only_title_and_description() {
        let mut doc = assemble_document("Test POA&M", vec![], "2026-01-01T00:00:00Z");
        let input = CustomItemInput {
            title: "Risk acceptance: legacy TLS 1.0 endpoint".to_string(),
            description: "Accepted per CAB 2026-01, compensating control: WAF rule 42".to_string(),
            status: None,
            deadline: None,
        };
        let uuid = add_custom_item(&mut doc, input, "2026-01-01T00:00:00Z").expect("add should succeed");

        assert_eq!(doc.poam_items.len(), 1);
        let item = &doc.poam_items[0];
        assert_eq!(item.uuid, uuid);
        assert_eq!(item.title, "Risk acceptance: legacy TLS 1.0 endpoint");
        assert!(item.props.iter().any(|p| p.name == "finding-source" && p.value == "manual"));
        assert!(doc.risks.iter().any(|r| r.status == super::super::RiskStatus::Open));
    }

    #[test]
    fn add_custom_item_rejects_empty_title() {
        let mut doc = assemble_document("Test POA&M", vec![], "2026-01-01T00:00:00Z");
        let input = CustomItemInput {
            title: "".to_string(),
            description: "some description".to_string(),
            status: None,
            deadline: None,
        };
        let result = add_custom_item(&mut doc, input, "2026-01-01T00:00:00Z");
        assert!(result.is_err(), "empty title violates the OSCAL-required poam-item.title field");
    }

    #[test]
    fn remove_custom_item_closes_it_by_uuid() {
        let mut doc = assemble_document("Test POA&M", vec![], "2026-01-01T00:00:00Z");
        let input = CustomItemInput {
            title: "Temp exception".to_string(),
            description: "temp".to_string(),
            status: None,
            deadline: None,
        };
        let uuid = add_custom_item(&mut doc, input, "2026-01-01T00:00:00Z").expect("add");

        let found = remove_custom_item(&mut doc, &uuid, "2026-02-01T00:00:00Z").expect("remove should not error");
        assert!(found);
        let risk = doc
            .risks
            .iter()
            .find(|r| doc.poam_items.iter().any(|i| i.uuid == uuid && i.related_risks.iter().any(|rr| rr.risk_uuid == r.uuid)))
            .expect("risk for the custom item");
        assert_eq!(risk.status, super::super::RiskStatus::Closed);
        assert_eq!(doc.poam_items.len(), 1, "closing must not delete the item");
    }

    #[test]
    fn remove_custom_item_rejects_scanner_derived_item() {
        use crate::poam::oscal::build::build_inspector2_triple;
        use crate::poam::csv_reader::CsvFinding;
        use std::collections::HashMap;

        let finding = CsvFinding::new_for_test("arn:1".to_string(), "k1".to_string(), HashMap::new());
        let triple = build_inspector2_triple(&finding, "2026-01-01T00:00:00Z");
        let mut doc = assemble_document("Test POA&M", vec![triple], "2026-01-01T00:00:00Z");
        let scanner_item_uuid = doc.poam_items[0].uuid.clone();

        let result = remove_custom_item(&mut doc, &scanner_item_uuid, "2026-02-01T00:00:00Z");
        assert!(result.is_err(), "removing a scanner-derived item through this path must be rejected");
    }
}
