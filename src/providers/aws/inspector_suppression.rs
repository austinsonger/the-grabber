use anyhow::Result;
use async_trait::async_trait;
use aws_sdk_inspector2::types::FilterAction;
use aws_sdk_inspector2::Client as Inspector2Client;

use crate::evidence::CsvCollector;

fn secs_to_rfc3339(secs: i64) -> String {
    chrono::DateTime::<chrono::Utc>::from_timestamp(secs, 0)
        .map(|c| c.to_rfc3339())
        .unwrap_or_default()
}

pub struct Inspector2SuppressionCollector {
    client: Inspector2Client,
}

impl Inspector2SuppressionCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self {
            client: Inspector2Client::new(config),
        }
    }
}

#[async_trait]
impl CsvCollector for Inspector2SuppressionCollector {
    fn name(&self) -> &str {
        "Inspector2 Suppression Rules"
    }
    fn filename_prefix(&self) -> &str {
        "Inspector2_Suppression_Rules"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Filter ARN",
            "Name",
            "Created At",
            "Updated At",
            "Owner",
            "Reason",
            "Filter Criteria Fields",
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
            let mut req = self.client.list_filters().max_results(100);
            if let Some(ref t) = next_token {
                req = req.next_token(t);
            }

            let resp = match req.send().await {
                Ok(r) => r,
                Err(e) => {
                    let msg = format!("{e:#}");
                    if msg.contains("AccessDeniedException")
                        || msg.contains("ResourceNotFoundException")
                        || msg.contains("ValidationException")
                        || msg.contains("BadRequestException")
                    {
                        eprintln!("  WARN: Inspector2 list_filters (not enabled?): {msg}");
                        return Ok(rows);
                    }
                    eprintln!("  WARN: Inspector2 list_filters: {msg}");
                    break;
                }
            };

            for f in resp.filters() {
                if !matches!(f.action(), FilterAction::Suppress) {
                    continue;
                }

                let arn = f.arn().to_string();
                let name = f.name().to_string();
                let created_at = secs_to_rfc3339(f.created_at().secs());
                let updated_at = secs_to_rfc3339(f.updated_at().secs());
                let owner = f.owner_id().to_string();
                let reason = f.reason().unwrap_or("").to_string();

                let criteria_fields = f
                    .criteria()
                    .map(|c| {
                        let mut fields: Vec<&str> = Vec::new();
                        if !c.aws_account_id().is_empty() {
                            fields.push("aws_account_id");
                        }
                        if !c.severity().is_empty() {
                            fields.push("severity");
                        }
                        if !c.resource_id().is_empty() {
                            fields.push("resource_id");
                        }
                        if !c.resource_type().is_empty() {
                            fields.push("resource_type");
                        }
                        if !c.vulnerability_id().is_empty() {
                            fields.push("vulnerability_id");
                        }
                        if !c.finding_status().is_empty() {
                            fields.push("finding_status");
                        }
                        if !c.finding_type().is_empty() {
                            fields.push("finding_type");
                        }
                        if !c.fix_available().is_empty() {
                            fields.push("fix_available");
                        }
                        if !c.exploit_available().is_empty() {
                            fields.push("exploit_available");
                        }
                        if !c.title().is_empty() {
                            fields.push("title");
                        }
                        if !c.component_id().is_empty() {
                            fields.push("component_id");
                        }
                        if !c.component_type().is_empty() {
                            fields.push("component_type");
                        }
                        if !c.ecr_image_tags().is_empty() {
                            fields.push("ecr_image_tags");
                        }
                        if !c.ecr_image_hash().is_empty() {
                            fields.push("ecr_image_hash");
                        }
                        if !c.lambda_function_name().is_empty() {
                            fields.push("lambda_function_name");
                        }
                        fields.join(", ")
                    })
                    .unwrap_or_default();

                rows.push(vec![
                    arn,
                    name,
                    created_at,
                    updated_at,
                    owner,
                    reason,
                    criteria_fields,
                ]);
            }

            next_token = resp.next_token().map(|s| s.to_string());
            if next_token.is_none() {
                break;
            }
        }

        Ok(rows)
    }
}
