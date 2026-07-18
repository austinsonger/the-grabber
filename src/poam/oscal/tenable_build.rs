use uuid::Uuid;

use crate::poam::tenable_csv_reader::{TenableComplianceRow, TenableVulnRow};

use super::model::{
    Characterization, Facet, Observation, Origin, OriginActor, PoamItem, Prop, RelatedObservation,
    RelatedRisk, Risk, RiskStatus,
};

const TENABLE_SOURCE_LABEL: &str = "Tenable.io";

/// Fixed tool identity for the "Tenable.io" origin actor referenced by
/// `characterizations[].origin.actors[].actor-uuid`. Mirrors
/// `INSPECTOR2_TOOL_UUID` in `build.rs`: the schema's `actor-uuid` field is
/// `$ref: UUIDDatatype`, which requires a strict RFC 4122 UUID, so a
/// descriptive slug like `"tenable-io"` fails validation. This is a stable,
/// arbitrarily chosen UUID naming that tool, not a random per-run value.
const TENABLE_TOOL_UUID: &str = "862e904f-a7a5-48ea-a9ce-4e3acbb878a1";

/// Maps a single Tenable vulnerability CSV row to the three linked OSCAL
/// records that describe it: an `observation` (raw scanner evidence), a
/// `risk` (the assessed consequence, carrying CVSS3/VPR/severity as
/// `characterizations`), and a `poam-item` (the tracked remediation entry).
/// The three are cross-linked by UUID so downstream consumers can navigate
/// poam-item -> risk -> observation. Mirrors `build_inspector2_triple` in
/// `build.rs`.
pub(in crate::poam) fn build_tenable_vuln_triple(
    row: &TenableVulnRow,
    now: &str,
) -> (Observation, Risk, PoamItem) {
    let plugin_name = row.get("plugin name");
    let cves = row.get("cves");
    let severity = row.get("severity");
    let cvss3 = row.get("cvss3 base score");
    let vpr = row.get("vpr score");
    let state = row.get("state");
    let hostname = row.get("hostname");

    let observation_uuid = Uuid::new_v4().to_string();
    let risk_uuid = Uuid::new_v4().to_string();
    let item_uuid = Uuid::new_v4().to_string();

    let observation = Observation {
        uuid: observation_uuid.clone(),
        description: format!(
            "Tenable vulnerability finding: {plugin_name} ({cves}) on {hostname}"
        ),
        methods: vec!["TEST-AUTOMATED".to_string()],
        collected: now.to_string(),
        props: vec![Prop {
            name: "finding-source".to_string(),
            value: TENABLE_SOURCE_LABEL.to_string(),
            ns: None,
        }],
    };

    // CVSS3/VPR/severity are the risk's characterization: each facet needs its
    // own naming `system` (unlike `Prop`, which has no such field), since the
    // schema's `facets[]` requires `{name, system, value}`. VPR is
    // Tenable-proprietary and not in the schema's `system` enum, so it is
    // named with a real (if informal) URI instead.
    let mut facets = Vec::new();
    if !cvss3.is_empty() {
        facets.push(Facet {
            name: "cvss3-base-score".to_string(),
            system: "http://www.first.org/cvss/v3.1".to_string(),
            value: cvss3.clone(),
        });
    }
    if !vpr.is_empty() {
        facets.push(Facet {
            name: "vpr-score".to_string(),
            system: "https://www.tenable.com/vulnerability-priority-rating".to_string(),
            value: vpr.clone(),
        });
    }
    if !severity.is_empty() {
        facets.push(Facet {
            name: "severity".to_string(),
            system: "http://csrc.nist.gov/ns/oscal/unknown".to_string(),
            value: severity.clone(),
        });
    }
    let characterizations = if facets.is_empty() {
        vec![]
    } else {
        vec![Characterization {
            origin: Origin {
                actors: vec![OriginActor {
                    actor_type: "tool".to_string(),
                    actor_uuid: TENABLE_TOOL_UUID.to_string(),
                }],
            },
            facets,
        }]
    };

    let risk = Risk {
        uuid: risk_uuid.clone(),
        title: plugin_name.clone(),
        description: format!("Tenable vulnerability risk: {plugin_name}"),
        statement: format!("{plugin_name} ({cves}) detected on {hostname}"),
        status: map_tenable_vuln_state(&state),
        characterizations,
        related_observations: vec![RelatedObservation {
            observation_uuid: observation_uuid.clone(),
        }],
    };

    let item = PoamItem {
        uuid: item_uuid,
        title: plugin_name.clone(),
        description: format!("Remediate {plugin_name} on {hostname}"),
        props: vec![
            Prop {
                name: "weakness-source-identifier".to_string(),
                value: row.stable_key.clone(),
                ns: None,
            },
            Prop {
                name: "finding-source".to_string(),
                value: TENABLE_SOURCE_LABEL.to_string(),
                ns: None,
            },
            Prop {
                name: "finding-type".to_string(),
                value: "vulnerability".to_string(),
                ns: None,
            },
        ],
        related_risks: vec![RelatedRisk { risk_uuid }],
        related_observations: vec![RelatedObservation { observation_uuid }],
    };

    (observation, risk, item)
}

fn map_tenable_vuln_state(state: &str) -> RiskStatus {
    match state.trim().to_ascii_lowercase().as_str() {
        "fixed" => RiskStatus::Closed,
        _ => RiskStatus::Open,
    }
}

/// Maps a single Tenable compliance CSV row to the three linked OSCAL records
/// that describe it, following the same shape as `build_tenable_vuln_triple`.
/// Compliance checks carry no CVSS/VPR data, so `characterizations` is always
/// empty here.
pub(in crate::poam) fn build_tenable_compliance_triple(
    row: &TenableComplianceRow,
    now: &str,
) -> (Observation, Risk, PoamItem) {
    let check_name = row.get("check name");
    let status = row.get("status");
    let policy_name = row.get("policy name");
    let hostname = row.get("hostname");

    let observation_uuid = Uuid::new_v4().to_string();
    let risk_uuid = Uuid::new_v4().to_string();
    let item_uuid = Uuid::new_v4().to_string();

    let observation = Observation {
        uuid: observation_uuid.clone(),
        description: format!(
            "Tenable compliance check: {check_name} ({policy_name}) on {hostname}, status {status}"
        ),
        methods: vec!["TEST-AUTOMATED".to_string()],
        collected: now.to_string(),
        props: vec![Prop {
            name: "finding-source".to_string(),
            value: TENABLE_SOURCE_LABEL.to_string(),
            ns: None,
        }],
    };

    let risk = Risk {
        uuid: risk_uuid.clone(),
        title: check_name.clone(),
        description: format!("Tenable compliance risk: {check_name} ({policy_name})"),
        statement: format!("{check_name} failed policy {policy_name} on {hostname}"),
        status: map_tenable_compliance_status(&status),
        characterizations: vec![],
        related_observations: vec![RelatedObservation {
            observation_uuid: observation_uuid.clone(),
        }],
    };

    let item = PoamItem {
        uuid: item_uuid,
        title: check_name.clone(),
        description: format!("Remediate compliance failure: {check_name} on {hostname}"),
        props: vec![
            Prop {
                name: "weakness-source-identifier".to_string(),
                value: row.stable_key.clone(),
                ns: None,
            },
            Prop {
                name: "finding-source".to_string(),
                value: TENABLE_SOURCE_LABEL.to_string(),
                ns: None,
            },
            Prop {
                name: "finding-type".to_string(),
                value: "compliance-check".to_string(),
                ns: None,
            },
        ],
        related_risks: vec![RelatedRisk { risk_uuid }],
        related_observations: vec![RelatedObservation { observation_uuid }],
    };

    (observation, risk, item)
}

fn map_tenable_compliance_status(status: &str) -> RiskStatus {
    match status.trim().to_ascii_uppercase().as_str() {
        "FAILED" | "WARNING" => RiskStatus::Open,
        _ => RiskStatus::Closed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::poam::tenable_csv_reader::{TenableComplianceRow, TenableVulnRow};
    use std::collections::HashMap;

    fn vuln_row() -> TenableVulnRow {
        let mut values = HashMap::new();
        values.insert("pluginname".to_string(), "SSL Certificate Cannot Be Trusted".to_string());
        values.insert("cves".to_string(), "CVE-2026-0001".to_string());
        values.insert("severity".to_string(), "High".to_string());
        values.insert("cvss3basescore".to_string(), "8.1".to_string());
        values.insert("vprscore".to_string(), "7.2".to_string());
        values.insert("state".to_string(), "open".to_string());
        values.insert("hostname".to_string(), "host1".to_string());
        TenableVulnRow { stable_key: "asset-1:19506:443:tcp".to_string(), values }
    }

    fn compliance_row() -> TenableComplianceRow {
        let mut values = HashMap::new();
        values.insert("checkname".to_string(), "Password complexity".to_string());
        values.insert("status".to_string(), "FAILED".to_string());
        values.insert("policyname".to_string(), "CIS Level 1".to_string());
        values.insert("hostname".to_string(), "host2".to_string());
        TenableComplianceRow { stable_key: "asset-2:check-123".to_string(), values }
    }

    #[test]
    fn tenable_vuln_triple_carries_vpr_and_cvss_and_source_label() {
        let (observation, risk, item) = build_tenable_vuln_triple(&vuln_row(), "2026-07-17T00:00:00Z");
        assert!(item.props.iter().any(|p| p.name == "weakness-source-identifier" && p.value == "asset-1:19506:443:tcp"));
        assert!(item.props.iter().any(|p| p.name == "finding-source" && p.value == "Tenable.io"));
        assert!(risk.characterizations.iter().any(|c| c.facets.iter().any(|p| p.name == "vpr-score" && p.value == "7.2")));
        assert!(risk.characterizations.iter().any(|c| c.facets.iter().any(|p| p.name == "cvss3-base-score" && p.value == "8.1")));
        assert_eq!(risk.status, super::super::RiskStatus::Open);
        assert!(observation.description.contains("CVE-2026-0001"));
    }

    #[test]
    fn tenable_vuln_fixed_state_maps_to_closed() {
        let mut row = vuln_row();
        row.values.insert("state".to_string(), "fixed".to_string());
        let (_, risk, _) = build_tenable_vuln_triple(&row, "2026-07-17T00:00:00Z");
        assert_eq!(risk.status, super::super::RiskStatus::Closed);
    }

    #[test]
    fn tenable_compliance_triple_marks_finding_type_as_compliance_check() {
        let (_, risk, item) = build_tenable_compliance_triple(&compliance_row(), "2026-07-17T00:00:00Z");
        assert!(item.props.iter().any(|p| p.name == "weakness-source-identifier" && p.value == "asset-2:check-123"));
        assert!(item.props.iter().any(|p| p.name == "finding-type" && p.value == "compliance-check"));
        assert_eq!(risk.status, super::super::RiskStatus::Open, "FAILED compliance checks map to open, same vocabulary as vulnerabilities");
    }

    #[test]
    fn tenable_compliance_passed_status_maps_to_closed() {
        let mut row = compliance_row();
        row.values.insert("status".to_string(), "PASSED".to_string());
        let (_, risk, _) = build_tenable_compliance_triple(&row, "2026-07-17T00:00:00Z");
        assert_eq!(risk.status, super::super::RiskStatus::Closed);
    }
}
