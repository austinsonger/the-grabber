use anyhow::Result;
use async_trait::async_trait;
use aws_sdk_securityhub::types::AwsSecurityFindingFilters;
use aws_sdk_securityhub::Client as ShClient;

use crate::evidence::CsvCollector;

// ══════════════════════════════════════════════════════════════════════════════
// Security Hub Insights
// ══════════════════════════════════════════════════════════════════════════════

pub struct SecurityHubInsightsCollector {
    client: ShClient,
}

impl SecurityHubInsightsCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self {
            client: ShClient::new(config),
        }
    }
}

/// Build a concise summary like "ResourceType:3, SeverityLabel:2" by counting
/// the non-empty filter slices on a curated set of common fields.
fn summarize_filters(f: &AwsSecurityFindingFilters) -> String {
    let entries: &[(&str, usize)] = &[
        ("ProductArn", f.product_arn().len()),
        ("AwsAccountId", f.aws_account_id().len()),
        ("Id", f.id().len()),
        ("GeneratorId", f.generator_id().len()),
        ("Region", f.region().len()),
        ("Type", f.r#type().len()),
        ("FirstObservedAt", f.first_observed_at().len()),
        ("LastObservedAt", f.last_observed_at().len()),
        ("CreatedAt", f.created_at().len()),
        ("UpdatedAt", f.updated_at().len()),
        ("SeverityProduct", f.severity_product().len()),
        ("SeverityNormalized", f.severity_normalized().len()),
        ("SeverityLabel", f.severity_label().len()),
        ("Confidence", f.confidence().len()),
        ("Criticality", f.criticality().len()),
        ("Title", f.title().len()),
        ("Description", f.description().len()),
        ("RecommendationText", f.recommendation_text().len()),
        ("SourceUrl", f.source_url().len()),
        ("ProductFields", f.product_fields().len()),
        ("ProductName", f.product_name().len()),
        ("CompanyName", f.company_name().len()),
        ("UserDefinedFields", f.user_defined_fields().len()),
        ("MalwareName", f.malware_name().len()),
        ("MalwareType", f.malware_type().len()),
        ("NetworkDirection", f.network_direction().len()),
        ("NetworkProtocol", f.network_protocol().len()),
        ("ProcessName", f.process_name().len()),
        ("ProcessPath", f.process_path().len()),
        (
            "ThreatIntelIndicatorType",
            f.threat_intel_indicator_type().len(),
        ),
        (
            "ThreatIntelIndicatorValue",
            f.threat_intel_indicator_value().len(),
        ),
        ("ResourceType", f.resource_type().len()),
        ("ResourceId", f.resource_id().len()),
        ("ResourcePartition", f.resource_partition().len()),
        ("ResourceRegion", f.resource_region().len()),
        ("ResourceTags", f.resource_tags().len()),
        ("ComplianceStatus", f.compliance_status().len()),
        ("VerificationState", f.verification_state().len()),
        ("WorkflowState", f.workflow_state().len()),
        ("WorkflowStatus", f.workflow_status().len()),
        ("RecordState", f.record_state().len()),
        (
            "RelatedFindingsProductArn",
            f.related_findings_product_arn().len(),
        ),
        ("RelatedFindingsId", f.related_findings_id().len()),
        ("NoteText", f.note_text().len()),
        ("NoteUpdatedAt", f.note_updated_at().len()),
        ("NoteUpdatedBy", f.note_updated_by().len()),
        ("Keyword", f.keyword().len()),
    ];

    entries
        .iter()
        .filter(|(_, n)| *n > 0)
        .map(|(k, n)| format!("{k}:{n}"))
        .collect::<Vec<_>>()
        .join(", ")
}

#[async_trait]
impl CsvCollector for SecurityHubInsightsCollector {
    fn name(&self) -> &str {
        "Security Hub Insights"
    }
    fn filename_prefix(&self) -> &str {
        "SecurityHub_Insights"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Insight ARN",
            "Name",
            "Group By Attribute",
            "Filters Summary",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let mut rows = Vec::new();
        let mut next_token: Option<String> = None;
        loop {
            let mut req = self.client.get_insights();
            if let Some(ref t) = next_token {
                req = req.next_token(t);
            }
            let resp = match req.send().await {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("  WARN: SecurityHub get_insights: {e:#}");
                    break;
                }
            };
            for ins in resp.insights() {
                let arn = ins.insight_arn().unwrap_or("").to_string();
                let name = ins.name().unwrap_or("").to_string();
                let group_by = ins.group_by_attribute().unwrap_or("").to_string();
                let filters = ins.filters().map(summarize_filters).unwrap_or_default();
                rows.push(vec![arn, name, group_by, filters]);
            }
            match resp.next_token() {
                Some(t) if !t.is_empty() => next_token = Some(t.to_string()),
                _ => break,
            }
        }
        Ok(rows)
    }
}
