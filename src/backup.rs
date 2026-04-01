use anyhow::{Context, Result};
use async_trait::async_trait;
use aws_sdk_backup::primitives::DateTime as AwsDateTime;
use aws_sdk_backup::Client;

use crate::evidence::{CollectParams, EvidenceCollector, EvidenceRecord, EvidenceSource};

pub struct BackupCollector {
    client: Client,
}

impl BackupCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self {
            client: Client::new(config),
        }
    }
}

#[async_trait]
impl EvidenceCollector for BackupCollector {
    fn name(&self) -> &str {
        "AWS Backup"
    }

    fn filename_prefix(&self) -> &str {
        "AWS_Backup_job_history_exports"
    }

    async fn collect(&self, params: &CollectParams) -> Result<Vec<EvidenceRecord>> {
        let mut records = Vec::new();
        let mut next_token: Option<String> = None;

        loop {
            let mut req = self
                .client
                .list_backup_jobs()
                .by_created_after(to_aws_dt(params.start_time))
                .by_created_before(to_aws_dt(params.end_time));

            if let Some(ref token) = next_token {
                req = req.next_token(token);
            }

            let resp = req
                .send()
                .await
                .context("Failed to list backup jobs from AWS Backup")?;

            if let Some(ref jobs) = resp.backup_jobs {
                for job in jobs {
                    // backup_plan_id lives on the RecoveryPointCreator, not BackupJob directly.
                    let plan_id = job
                        .created_by()
                        .and_then(|c| c.backup_plan_id())
                        .map(|s| s.to_string());

                    // Client-side filter by backup plan ID if requested.
                    if let Some(ref filter_id) = params.filter {
                        if plan_id.as_deref() != Some(filter_id.as_str()) {
                            continue;
                        }
                    }

                    let creation = job.creation_date().map(fmt_aws_dt);
                    let completion = job.completion_date().map(fmt_aws_dt);
                    let state = job.state().map(|s| s.as_str().to_string());

                    // Emit a StartBackupJob record from the creation timestamp.
                    records.push(EvidenceRecord {
                        source: EvidenceSource::BackupApi,
                        event_name: "StartBackupJob".to_string(),
                        timestamp: creation.clone().unwrap_or_default(),
                        job_id: job.backup_job_id().map(|s| s.to_string()),
                        plan_id: plan_id.clone(),
                        resource_arn: job.resource_arn().map(|s| s.to_string()),
                        resource_type: job.resource_type().map(|s| s.to_string()),
                        status: state.clone(),
                        completion_timestamp: completion.clone(),
                        raw: None,
                    });

                    // If the job completed (or failed), emit a completion record too.
                    if completion.is_some() {
                        records.push(EvidenceRecord {
                            source: EvidenceSource::BackupApi,
                            event_name: "BackupJobCompleted".to_string(),
                            timestamp: completion.clone().unwrap_or_default(),
                            job_id: job.backup_job_id().map(|s| s.to_string()),
                            plan_id,
                            resource_arn: job.resource_arn().map(|s| s.to_string()),
                            resource_type: job.resource_type().map(|s| s.to_string()),
                            status: state,
                            completion_timestamp: completion,
                            raw: None,
                        });
                    }
                }
            }

            next_token = resp.next_token().map(|s| s.to_string());
            if next_token.is_none() {
                break;
            }
        }

        Ok(records)
    }
}

fn to_aws_dt(dt: chrono::DateTime<chrono::Utc>) -> AwsDateTime {
    AwsDateTime::from_secs(dt.timestamp())
}

fn fmt_aws_dt(dt: &AwsDateTime) -> String {
    chrono::DateTime::<chrono::Utc>::from_timestamp(dt.secs(), dt.subsec_nanos())
        .map(|c| c.to_rfc3339())
        .unwrap_or_else(|| format!("epoch:{}", dt.secs()))
}
