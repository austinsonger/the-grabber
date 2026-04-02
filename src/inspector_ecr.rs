use anyhow::Result;
use async_trait::async_trait;
use aws_sdk_inspector2::Client as Inspector2Client;
use aws_sdk_inspector2::types::{FilterCriteria, StringFilter, StringComparison};

use crate::evidence::CsvCollector;

pub struct InspectorEcrCollector {
    client: Inspector2Client,
}

impl InspectorEcrCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self { client: Inspector2Client::new(config) }
    }
}

#[async_trait]
impl CsvCollector for InspectorEcrCollector {
    fn name(&self) -> &str { "Inspector2 ECR Findings" }
    fn filename_prefix(&self) -> &str { "Inspector2_ECR_Findings" }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Finding ARN", "Severity", "Type", "CVE ID",
            "Repository", "Image Tag", "Image Digest",
            "Package Name", "Package Version", "Fixed Version",
            "Status", "Fix Available", "Title",
        ]
    }

    async fn collect_rows(&self, _account_id: &str, _region: &str) -> Result<Vec<Vec<String>>> {
        let mut rows = Vec::new();
        let mut next_token: Option<String> = None;

        let ecr_filter = match StringFilter::builder()
            .comparison(StringComparison::Equals)
            .value("AWS_ECR_CONTAINER_IMAGE")
            .build()
        {
            Ok(f) => f,
            Err(e) => {
                eprintln!("  WARN: Inspector2 ECR filter build error: {e:#}");
                return Ok(rows);
            }
        };

        let filter_criteria = FilterCriteria::builder()
            .resource_type(ecr_filter)
            .build();

        loop {
            let mut req = self.client
                .list_findings()
                .filter_criteria(filter_criteria.clone())
                .max_results(100);
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
                    {
                        eprintln!("  WARN: Inspector2 ECR list_findings (not enabled?): {msg}");
                        return Ok(rows);
                    }
                    eprintln!("  WARN: Inspector2 ECR list_findings: {msg}");
                    break;
                }
            };

            for finding in resp.findings() {
                let finding_arn = finding.finding_arn().to_string();
                let severity    = finding.severity().as_str().to_string();
                let f_type      = finding.r#type().as_str().to_string();
                let title       = finding.title().unwrap_or("").to_string();
                let status      = finding.status().as_str().to_string();
                let fix_available = finding.fix_available()
                    .map(|f| f.as_str().to_string())
                    .unwrap_or_default();

                // CVE ID and package details from package vulnerability
                let (cve_id, pkg_name, pkg_version, fixed_version) =
                    if let Some(vuln) = finding.package_vulnerability_details() {
                        let cve = vuln.vulnerability_id().to_string();
                        // Take the first affected package
                        let (name, ver, fixed) = vuln.vulnerable_packages()
                            .first()
                            .map(|p| (
                                p.name().to_string(),
                                p.version().to_string(),
                                p.fixed_in_version().unwrap_or("").to_string(),
                            ))
                            .unwrap_or_default();
                        (cve, name, ver, fixed)
                    } else {
                        (String::new(), String::new(), String::new(), String::new())
                    };

                // ECR-specific resource details
                let (repo, tag, digest) = finding.resources()
                    .first()
                    .and_then(|r| r.details())
                    .and_then(|d| d.aws_ecr_container_image())
                    .map(|ecr| (
                        ecr.repository_name().to_string(),
                        ecr.image_tags().first().map(|s| s.as_str()).unwrap_or("").to_string(),
                        ecr.image_hash().to_string(),
                    ))
                    .unwrap_or_else(|| {
                        // Fall back to resource ID if ECR details not present
                        let id = finding.resources()
                            .first()
                            .map(|r| r.id().to_string())
                            .unwrap_or_default();
                        (id, String::new(), String::new())
                    });

                rows.push(vec![
                    finding_arn,
                    severity,
                    f_type,
                    cve_id,
                    repo,
                    tag,
                    digest,
                    pkg_name,
                    pkg_version,
                    fixed_version,
                    status,
                    fix_available,
                    title,
                ]);
            }

            next_token = resp.next_token().map(|s| s.to_string());
            if next_token.is_none() { break; }
        }

        Ok(rows)
    }
}
