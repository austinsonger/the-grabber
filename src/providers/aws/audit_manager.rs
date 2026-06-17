use anyhow::Result;
use async_trait::async_trait;
use aws_sdk_auditmanager::types::AssessmentStatus;
use aws_sdk_auditmanager::Client as AmClient;

use crate::evidence::CsvCollector;

pub struct AuditManagerCollector {
    client: AmClient,
}

impl AuditManagerCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self {
            client: AmClient::new(config),
        }
    }
}

fn is_benign(err: &str) -> bool {
    err.contains("AccessDenied")
        || err.contains("ResourceNotFoundException")
        || err.contains("ValidationException")
        || err.contains("not enabled")
        || err.contains("not subscribed")
}

#[async_trait]
impl CsvCollector for AuditManagerCollector {
    fn name(&self) -> &str {
        "Audit Manager Assessments"
    }
    fn filename_prefix(&self) -> &str {
        "AuditManager_Assessments"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Assessment ID",
            "Name",
            "Framework",
            "Status",
            "Last Updated",
            "Total Control Sets",
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
            let mut req = self
                .client
                .list_assessments()
                .status(AssessmentStatus::Active);
            if let Some(t) = next_token.as_ref() {
                req = req.next_token(t);
            }
            let resp = match req.send().await {
                Ok(r) => r,
                Err(e) => {
                    let msg = format!("{e:#}");
                    if is_benign(&msg) {
                        return Ok(rows);
                    }
                    eprintln!("  WARN: AuditManager list_assessments: {e:#}");
                    break;
                }
            };

            for item in resp.assessment_metadata() {
                let id = item.id().map(|s| s.to_string()).unwrap_or_default();
                let name = item.name().map(|s| s.to_string()).unwrap_or_default();
                let framework = item
                    .compliance_type()
                    .map(|s| s.to_string())
                    .unwrap_or_default();
                let status = item
                    .status()
                    .map(|s| s.as_str().to_string())
                    .unwrap_or_default();
                let last_updated = item
                    .last_updated()
                    .map(|t| t.to_string())
                    .unwrap_or_default();

                // Fetch detail for control set count.
                let total_sets = if !id.is_empty() {
                    match self.client.get_assessment().assessment_id(&id).send().await {
                        Ok(g) => g
                            .assessment()
                            .and_then(|a| a.framework())
                            .map(|f| f.control_sets().len())
                            .unwrap_or(0)
                            .to_string(),
                        Err(_) => String::new(),
                    }
                } else {
                    String::new()
                };

                rows.push(vec![id, name, framework, status, last_updated, total_sets]);
            }

            next_token = resp.next_token().map(|s| s.to_string());
            if next_token.is_none() {
                break;
            }
        }

        Ok(rows)
    }
}
