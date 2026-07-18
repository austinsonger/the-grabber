use uuid::Uuid;

use crate::poam::csv_reader::CsvFinding;

use super::model::{
    Characterization, Facet, Observation, Origin, OriginActor, PoamItem, Prop, RelatedObservation,
    RelatedRisk, Risk, RiskStatus,
};

/// Maps a single AWS Inspector2 ECR CSV finding to the three linked OSCAL
/// records that describe it: an `observation` (raw scanner evidence), a
/// `risk` (the assessed consequence, carrying CVSS/severity as
/// `characterizations`), and a `poam-item` (the tracked remediation entry).
/// The three are cross-linked by UUID so downstream consumers can navigate
/// poam-item -> risk -> observation.
pub(in crate::poam) fn build_inspector2_triple(
    finding: &CsvFinding,
    now: &str,
) -> (Observation, Risk, PoamItem) {
    let cve_id = finding.get("cve id");
    let package = finding.get("package name");
    let title = finding.get("title");
    let severity = finding.get("severity");
    let cvss = finding.get("cvss score");
    let status = finding.get("status");
    let image_uri = finding.get("image uri");

    let observation_uuid = Uuid::new_v4().to_string();
    let risk_uuid = Uuid::new_v4().to_string();
    let item_uuid = Uuid::new_v4().to_string();

    let description = format!(
        "AWS Inspector2 ECR finding: {cve_id} in package {package} (image: {image_uri})"
    );

    let observation = Observation {
        uuid: observation_uuid.clone(),
        description,
        methods: vec!["TEST-AUTOMATED".to_string()],
        collected: now.to_string(),
        props: vec![Prop {
            name: "finding-source".to_string(),
            value: "AWS Inspector2 - ECR".to_string(),
            ns: None,
        }],
    };

    let risk_status = map_inspector2_status(&status);

    // CVSS/severity are the risk's characterization: each facet needs its own
    // naming `system` (unlike `Prop`, which has no such field), since the
    // schema's `facets[]` requires `{name, system, value}`.
    let mut characterizations = Vec::new();
    if !cvss.is_empty() {
        characterizations.push(Characterization {
            origin: Origin {
                actors: vec![OriginActor {
                    actor_type: "tool".to_string(),
                    actor_uuid: "aws-inspector2-ecr".to_string(),
                }],
            },
            facets: vec![
                Facet {
                    name: "cvss-score".to_string(),
                    system: "https://www.first.org/cvss/v3-1".to_string(),
                    value: cvss.clone(),
                },
                Facet {
                    name: "severity".to_string(),
                    system: "aws-inspector2-severity".to_string(),
                    value: severity.clone(),
                },
            ],
        });
    }

    let risk = Risk {
        uuid: risk_uuid.clone(),
        title: title.clone(),
        description: format!("Risk from AWS Inspector2 ECR finding {}", finding.arn),
        statement: format!(
            "{cve_id} affects package {package} in image {image_uri}, severity {severity}"
        ),
        status: risk_status,
        characterizations,
        related_observations: vec![RelatedObservation {
            observation_uuid: observation_uuid.clone(),
        }],
    };

    let item = PoamItem {
        uuid: item_uuid,
        title,
        description: format!("Remediate {cve_id} in {package} ({image_uri})"),
        props: vec![
            Prop {
                name: "weakness-source-identifier".to_string(),
                value: finding.stable_key.clone(),
                ns: None,
            },
            Prop {
                name: "finding-source".to_string(),
                value: "AWS Inspector2 - ECR".to_string(),
                ns: None,
            },
        ],
        related_risks: vec![RelatedRisk { risk_uuid }],
        related_observations: vec![RelatedObservation { observation_uuid }],
    };

    (observation, risk, item)
}

fn map_inspector2_status(status: &str) -> RiskStatus {
    match status.trim().to_ascii_uppercase().as_str() {
        "CLOSED" => RiskStatus::Closed,
        "SUPPRESSED" => RiskStatus::DeviationRequested,
        _ => RiskStatus::Open,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::poam::csv_reader::CsvFinding;
    use std::collections::HashMap;

    fn sample_finding() -> CsvFinding {
        let mut values = HashMap::new();
        values.insert(normalize_test_key("cve id"), "CVE-2026-1234".to_string());
        values.insert(normalize_test_key("package name"), "openssl".to_string());
        values.insert(normalize_test_key("title"), "openssl vulnerable to CVE-2026-1234".to_string());
        values.insert(normalize_test_key("severity"), "HIGH".to_string());
        values.insert(normalize_test_key("cvss score"), "7.5".to_string());
        values.insert(normalize_test_key("status"), "ACTIVE".to_string());
        values.insert(normalize_test_key("image uri"), "123456789012.dkr.ecr.us-east-1.amazonaws.com/app:latest".to_string());
        CsvFinding::new_for_test(
            "arn:aws:inspector2:us-east-1:123456789012:finding/abc123".to_string(),
            "CVE-2026-1234|openssl".to_string(),
            values,
        )
    }

    fn normalize_test_key(s: &str) -> String {
        s.chars().filter(|c| c.is_ascii_alphanumeric()).map(|c| c.to_ascii_lowercase()).collect()
    }

    #[test]
    fn builds_observation_risk_poam_item_linked_by_uuid() {
        let finding = sample_finding();
        let (observation, risk, item) = build_inspector2_triple(&finding, "2026-07-17T00:00:00Z");

        assert!(observation.description.contains("CVE-2026-1234"));
        assert!(observation.description.contains("openssl"));
        assert!(observation.description.contains("123456789012.dkr.ecr.us-east-1.amazonaws.com/app:latest"));
        assert_eq!(observation.methods, vec!["TEST-AUTOMATED".to_string()]);
        assert_eq!(observation.collected, "2026-07-17T00:00:00Z");

        // `Risk.related_observations` / `PoamItem.related_risks` / `PoamItem.related_observations`
        // are `Vec<RelatedObservation>` / `Vec<RelatedRisk>` wrapper types (the schema requires
        // `{ "observation-uuid": ... }` / `{ "risk-uuid": ... }` objects, not bare UUID strings),
        // and neither wrapper derives `PartialEq`, so assert on the extracted uuid fields instead
        // of comparing whole vecs.
        assert_eq!(risk.related_observations.len(), 1);
        assert_eq!(risk.related_observations[0].observation_uuid, observation.uuid);
        assert_eq!(risk.status, RiskStatus::Open);
        assert!(risk.characterizations.iter().any(|c| c.facets.iter().any(|p| p.name == "cvss-score" && p.value == "7.5")));

        assert_eq!(item.related_risks.len(), 1);
        assert_eq!(item.related_risks[0].risk_uuid, risk.uuid);
        assert_eq!(item.related_observations.len(), 1);
        assert_eq!(item.related_observations[0].observation_uuid, observation.uuid);
        assert!(item.props.iter().any(|p| p.name == "weakness-source-identifier" && p.value == "CVE-2026-1234|openssl"));
        assert!(item.title.contains("openssl"));
    }

    #[test]
    fn closed_status_maps_to_risk_status_closed() {
        let mut values = HashMap::new();
        values.insert(normalize_test_key("status"), "CLOSED".to_string());
        let finding = CsvFinding::new_for_test("arn:1".to_string(), "key1".to_string(), values);
        let (_, risk, _) = build_inspector2_triple(&finding, "2026-07-17T00:00:00Z");
        assert_eq!(risk.status, RiskStatus::Closed);
    }
}
