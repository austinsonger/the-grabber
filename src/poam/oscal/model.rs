use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(in crate::poam) struct PlanOfActionAndMilestones {
    pub(in crate::poam) uuid: String,
    pub(in crate::poam) metadata: Metadata,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(in crate::poam) observations: Vec<Observation>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(in crate::poam) risks: Vec<Risk>,
    #[serde(rename = "poam-items")]
    pub(in crate::poam) poam_items: Vec<PoamItem>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(in crate::poam) struct Metadata {
    pub(in crate::poam) title: String,
    #[serde(rename = "last-modified")]
    pub(in crate::poam) last_modified: String,
    pub(in crate::poam) version: String,
    #[serde(rename = "oscal-version")]
    pub(in crate::poam) oscal_version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(in crate::poam) struct Observation {
    pub(in crate::poam) uuid: String,
    pub(in crate::poam) description: String,
    pub(in crate::poam) methods: Vec<String>,
    pub(in crate::poam) collected: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(in crate::poam) props: Vec<Prop>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(in crate::poam) struct Risk {
    pub(in crate::poam) uuid: String,
    pub(in crate::poam) title: String,
    pub(in crate::poam) description: String,
    pub(in crate::poam) statement: String,
    pub(in crate::poam) status: RiskStatus,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(in crate::poam) characterizations: Vec<Characterization>,
    #[serde(rename = "related-observations", default, skip_serializing_if = "Vec::is_empty")]
    pub(in crate::poam) related_observations: Vec<RelatedObservation>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(in crate::poam) enum RiskStatus {
    Open,
    Investigating,
    Remediating,
    DeviationRequested,
    DeviationApproved,
    Closed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(in crate::poam) struct Characterization {
    pub(in crate::poam) origin: Origin,
    pub(in crate::poam) facets: Vec<Prop>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(in crate::poam) struct Origin {
    pub(in crate::poam) actors: Vec<OriginActor>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(in crate::poam) struct OriginActor {
    #[serde(rename = "type")]
    pub(in crate::poam) actor_type: String,
    #[serde(rename = "actor-uuid")]
    pub(in crate::poam) actor_uuid: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(in crate::poam) struct Prop {
    pub(in crate::poam) name: String,
    pub(in crate::poam) value: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(in crate::poam) ns: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(in crate::poam) struct PoamItem {
    pub(in crate::poam) uuid: String,
    pub(in crate::poam) title: String,
    pub(in crate::poam) description: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(in crate::poam) props: Vec<Prop>,
    #[serde(rename = "related-risks", default, skip_serializing_if = "Vec::is_empty")]
    pub(in crate::poam) related_risks: Vec<RelatedRisk>,
    #[serde(rename = "related-observations", default, skip_serializing_if = "Vec::is_empty")]
    pub(in crate::poam) related_observations: Vec<RelatedObservation>,
}

/// A reference to an observation by UUID. The schema requires this as an
/// object (`{ "observation-uuid": "..." }`), not a bare UUID string.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(in crate::poam) struct RelatedObservation {
    #[serde(rename = "observation-uuid")]
    pub(in crate::poam) observation_uuid: String,
}

/// A reference to a risk by UUID. The schema requires this as an object
/// (`{ "risk-uuid": "..." }`), not a bare UUID string.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(in crate::poam) struct RelatedRisk {
    #[serde(rename = "risk-uuid")]
    pub(in crate::poam) risk_uuid: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(in crate::poam) struct RiskLogEntry {
    pub(in crate::poam) uuid: String,
    pub(in crate::poam) title: String,
    pub(in crate::poam) description: String,
    pub(in crate::poam) start: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::poam::oscal::validate::validate_document;

    fn minimal_doc() -> PlanOfActionAndMilestones {
        PlanOfActionAndMilestones {
            uuid: "11111111-1111-4111-8111-111111111111".to_string(),
            metadata: Metadata {
                title: "Test POA&M".to_string(),
                last_modified: "2026-07-17T00:00:00Z".to_string(),
                version: "1".to_string(),
                oscal_version: "1.1.2".to_string(),
            },
            observations: vec![Observation {
                uuid: "22222222-2222-4222-8222-222222222222".to_string(),
                description: "test observation".to_string(),
                methods: vec!["TEST-AUTOMATED".to_string()],
                collected: "2026-07-17T00:00:00Z".to_string(),
                props: vec![],
            }],
            risks: vec![Risk {
                uuid: "33333333-3333-4333-8333-333333333333".to_string(),
                title: "test risk".to_string(),
                description: "test risk description".to_string(),
                statement: "test risk statement".to_string(),
                status: RiskStatus::Open,
                characterizations: vec![],
                related_observations: vec![RelatedObservation {
                    observation_uuid: "22222222-2222-4222-8222-222222222222".to_string(),
                }],
            }],
            poam_items: vec![PoamItem {
                uuid: "44444444-4444-4444-8444-444444444444".to_string(),
                title: "test item".to_string(),
                description: "test item description".to_string(),
                props: vec![],
                related_risks: vec![RelatedRisk {
                    risk_uuid: "33333333-3333-4333-8333-333333333333".to_string(),
                }],
                related_observations: vec![RelatedObservation {
                    observation_uuid: "22222222-2222-4222-8222-222222222222".to_string(),
                }],
            }],
        }
    }

    #[test]
    fn minimal_document_serializes_and_validates_against_schema() {
        let doc = minimal_doc();
        let wrapped = serde_json::json!({ "plan-of-action-and-milestones": doc });
        validate_document(&wrapped).expect("minimal document should validate cleanly");
    }

    #[test]
    fn serde_uses_kebab_case_field_names() {
        let doc = minimal_doc();
        let json = serde_json::to_value(&doc).expect("serialize");
        // `last-modified`/`oscal-version` live under the nested `metadata` object per the
        // schema (see `oscal-poam-oscal-poam:plan-of-action-and-milestones`, which requires
        // `metadata` as its own object and forbids additional top-level properties), not at
        // the document's top level.
        let metadata = json.get("metadata").expect("metadata object present");
        assert!(metadata.get("last-modified").is_some(), "expected kebab-case 'last-modified' key, got: {json}");
        assert!(metadata.get("oscal-version").is_some(), "expected kebab-case 'oscal-version' key, got: {json}");
    }
}
