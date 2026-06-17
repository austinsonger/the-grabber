use anyhow::Result;
use async_trait::async_trait;
use aws_sdk_resourcegroupstagging::Client as TagClient;

use crate::evidence::CsvCollector;

pub struct TaggingComplianceCollector {
    client: TagClient,
}

impl TaggingComplianceCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self {
            client: TagClient::new(config),
        }
    }
}

fn is_benign(err: &str) -> bool {
    err.contains("AccessDenied")
        || err.contains("AccessDeniedException")
        || err.contains("not enabled")
        || err.contains("not opted in")
}

#[async_trait]
impl CsvCollector for TaggingComplianceCollector {
    fn name(&self) -> &str {
        "Tagging Compliance"
    }
    fn filename_prefix(&self) -> &str {
        "Tagging_Compliance"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Type",
            "Target / Resource ARN",
            "Resource Type / Status",
            "Region",
            "Non-Compliant Count / Keys",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let mut rows = Vec::new();

        // 1. Compliance summary (only populated when tag policies are enabled).
        let mut next_token: Option<String> = None;
        loop {
            let mut req = self.client.get_compliance_summary();
            if let Some(t) = next_token.as_ref() {
                req = req.pagination_token(t);
            }
            let resp = match req.send().await {
                Ok(r) => r,
                Err(e) => {
                    let msg = format!("{e:#}");
                    if is_benign(&msg) {
                        break;
                    }
                    eprintln!("  WARN: TaggingCompliance get_compliance_summary: {e:#}");
                    break;
                }
            };
            for s in resp.summary_list() {
                let target_id = s.target_id().unwrap_or("").to_string();
                let target_type = s
                    .target_id_type()
                    .map(|t| t.as_str().to_string())
                    .unwrap_or_default();
                let region_s = s.region().unwrap_or("").to_string();
                let resource_type = s.resource_type().unwrap_or("").to_string();
                let nc = s.non_compliant_resources();
                let resource_status = if resource_type.is_empty() {
                    target_type
                } else {
                    format!("{target_type} / {resource_type}")
                };
                rows.push(vec![
                    "Summary".to_string(),
                    target_id,
                    resource_status,
                    region_s,
                    nc.to_string(),
                ]);
            }
            next_token = resp.pagination_token().and_then(|t| {
                if t.is_empty() {
                    None
                } else {
                    Some(t.to_string())
                }
            });
            if next_token.is_none() {
                break;
            }
        }

        // 2. Per-resource non-compliance details.
        let mut next_token: Option<String> = None;
        loop {
            let mut req = self.client.get_resources().include_compliance_details(true);
            if let Some(t) = next_token.as_ref() {
                req = req.pagination_token(t);
            }
            let resp = match req.send().await {
                Ok(r) => r,
                Err(e) => {
                    let msg = format!("{e:#}");
                    if is_benign(&msg) {
                        break;
                    }
                    eprintln!("  WARN: TaggingCompliance get_resources: {e:#}");
                    break;
                }
            };
            for r in resp.resource_tag_mapping_list() {
                let arn = r.resource_arn().unwrap_or("").to_string();
                if let Some(cd) = r.compliance_details() {
                    let compliant = cd.compliance_status().unwrap_or(true);
                    if compliant {
                        continue;
                    }
                    let status = "NON_COMPLIANT".to_string();
                    let keys = cd.keys_with_noncompliant_values().join(",");
                    rows.push(vec![
                        "Resource".to_string(),
                        arn,
                        status,
                        region.to_string(),
                        keys,
                    ]);
                }
            }
            next_token = resp.pagination_token().and_then(|t| {
                if t.is_empty() {
                    None
                } else {
                    Some(t.to_string())
                }
            });
            if next_token.is_none() {
                break;
            }
        }

        Ok(rows)
    }
}
