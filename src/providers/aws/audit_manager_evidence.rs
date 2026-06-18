use anyhow::Result;
use async_trait::async_trait;
use aws_sdk_auditmanager::types::AssessmentStatus;
use aws_sdk_auditmanager::Client as AmClient;

use crate::evidence::CsvCollector;

fn is_benign(err: &str) -> bool {
    err.contains("AccessDenied")
        || err.contains("ResourceNotFoundException")
        || err.contains("ValidationException")
        || err.contains("not enabled")
        || err.contains("not subscribed")
        || err.contains("UnknownService")
        || err.contains("dispatch failure")
}

pub struct AuditManagerEvidenceCollector {
    client: AmClient,
}

impl AuditManagerEvidenceCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self {
            client: AmClient::new(config),
        }
    }
}

#[async_trait]
impl CsvCollector for AuditManagerEvidenceCollector {
    fn name(&self) -> &str {
        "Audit Manager Evidence Folders"
    }
    fn filename_prefix(&self) -> &str {
        "AuditManager_Evidence"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Assessment ID",
            "Folder Name",
            "Control Set",
            "Control ID",
            "Data Source",
            "Evidence Count",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let mut rows: Vec<Vec<String>> = Vec::new();

        let mut assessment_ids: Vec<String> = Vec::new();
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
                    return Ok(rows);
                }
            };

            for a in resp.assessment_metadata() {
                if let Some(id) = a.id() {
                    assessment_ids.push(id.to_string());
                }
            }

            next_token = resp.next_token().map(|s| s.to_string());
            if next_token.is_none() {
                break;
            }
        }

        for aid in assessment_ids {
            let mut next_token: Option<String> = None;
            loop {
                let mut req = self
                    .client
                    .get_evidence_folders_by_assessment()
                    .assessment_id(&aid);
                if let Some(t) = next_token.as_ref() {
                    req = req.next_token(t);
                }
                let resp = match req.send().await {
                    Ok(r) => r,
                    Err(e) => {
                        let msg = format!("{e:#}");
                        if !is_benign(&msg) {
                            eprintln!(
                                "  WARN: AuditManager get_evidence_folders_by_assessment({aid}): {e:#}"
                            );
                        }
                        break;
                    }
                };

                for f in resp.evidence_folders() {
                    let name = f.name().unwrap_or("").to_string();
                    let control_set = f.control_set_id().unwrap_or("").to_string();
                    let control_id = f.control_id().unwrap_or("").to_string();
                    let data_source = f.data_source().unwrap_or("").to_string();
                    let total = f.total_evidence();

                    rows.push(vec![
                        aid.clone(),
                        name,
                        control_set,
                        control_id,
                        data_source,
                        total.to_string(),
                    ]);
                }

                next_token = resp.next_token().map(|s| s.to_string());
                if next_token.is_none() {
                    break;
                }
            }
        }

        Ok(rows)
    }
}
