use anyhow::{Context, Result};
use async_trait::async_trait;
use aws_sdk_cloudtrail::primitives::DateTime as AwsDateTime;
use aws_sdk_cloudtrail::types::LookupAttribute;
use aws_sdk_cloudtrail::Client;

use crate::evidence::{CollectParams, EvidenceCollector, EvidenceRecord, EvidenceSource};

/// All event names this collector queries.  Add new ones here to extend coverage.
const EVENT_NAMES: &[&str] = &[
    // AWS Backup
    "StartBackupJob",
    "BackupJobCompleted",
    // RDS automated snapshots (instance + Aurora cluster)
    "CreateDBSnapshot",
    "CreateDBClusterSnapshot",
];

pub struct CloudTrailCollector {
    client: Client,
}

impl CloudTrailCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self {
            client: Client::new(config),
        }
    }
}

#[async_trait]
impl EvidenceCollector for CloudTrailCollector {
    fn name(&self) -> &str {
        "CloudTrail"
    }

    fn filename_prefix(&self) -> &str {
        "CloudTrail_backup_and_snapshot_events"
    }

    async fn collect(&self, params: &CollectParams) -> Result<Vec<EvidenceRecord>> {
        let mut records = Vec::new();

        for event_name in EVENT_NAMES {
            let mut page_records = self
                .lookup_events(event_name, params)
                .await
                .with_context(|| format!("CloudTrail lookup failed for {event_name}"))?;
            records.append(&mut page_records);
        }

        // Optional filter: keep only records where any key field contains the string.
        if let Some(ref f) = params.filter {
            records.retain(|r| {
                let haystack = format!(
                    "{} {} {}",
                    r.plan_id.as_deref().unwrap_or(""),
                    r.job_id.as_deref().unwrap_or(""),
                    r.resource_arn.as_deref().unwrap_or(""),
                );
                haystack.contains(f.as_str())
            });
        }

        Ok(records)
    }
}

impl CloudTrailCollector {
    async fn lookup_events(
        &self,
        event_name: &str,
        params: &CollectParams,
    ) -> Result<Vec<EvidenceRecord>> {
        let start_dt = AwsDateTime::from_secs(params.start_time.timestamp());
        let end_dt = AwsDateTime::from_secs(params.end_time.timestamp());

        let attr = LookupAttribute::builder()
            .attribute_key(aws_sdk_cloudtrail::types::LookupAttributeKey::EventName)
            .attribute_value(event_name)
            .build()
            .context("Failed to build LookupAttribute")?;

        let mut records = Vec::new();
        let mut next_token: Option<String> = None;

        loop {
            let mut req = self
                .client
                .lookup_events()
                .lookup_attributes(attr.clone())
                .start_time(start_dt)
                .end_time(end_dt)
                .max_results(50);

            if let Some(ref token) = next_token {
                req = req.next_token(token);
            }

            let resp = req
                .send()
                .await
                .context("CloudTrail LookupEvents call failed")?;

            if let Some(ref events) = resp.events {
                for event in events {
                    records.push(parse_event(event, params.include_raw));
                }
            }

            next_token = resp.next_token().map(|s| s.to_string());
            if next_token.is_none() {
                break;
            }

            // CloudTrail rate limit: ~2 req/s.
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        }

        Ok(records)
    }
}

fn parse_event(event: &aws_sdk_cloudtrail::types::Event, include_raw: bool) -> EvidenceRecord {
    let timestamp = event
        .event_time()
        .and_then(|d| {
            chrono::DateTime::<chrono::Utc>::from_timestamp(d.secs(), d.subsec_nanos())
                .map(|c| c.to_rfc3339())
        })
        .unwrap_or_default();

    let event_name = event.event_name().unwrap_or("Unknown").to_string();

    let parsed: Option<serde_json::Value> = event
        .cloud_trail_event()
        .and_then(|s| serde_json::from_str(s).ok());

    let (job_id, plan_id, resource_arn, resource_type, status) =
        extract_fields(parsed.as_ref(), &event_name);

    let raw = if include_raw { parsed } else { None };

    EvidenceRecord {
        source: EvidenceSource::CloudTrail,
        event_name,
        timestamp,
        job_id,
        plan_id,
        resource_arn,
        resource_type,
        status,
        completion_timestamp: None,
        raw,
    }
}

type ExtractedFields = (
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
);

fn extract_fields(val: Option<&serde_json::Value>, event_name: &str) -> ExtractedFields {
    let val = match val {
        Some(v) => v,
        None => return (None, None, None, None, None),
    };

    let is_rds = event_name.contains("DB");

    // job_id: snapshot identifier for RDS, backup job ID for Backup
    let job_id = if is_rds {
        try_str(val, &["responseElements", "dbClusterSnapshot", "dbClusterSnapshotIdentifier"])
            .or_else(|| try_str(val, &["responseElements", "dbSnapshot", "dbSnapshotIdentifier"]))
    } else {
        try_str(val, &["responseElements", "backupJobId"])
            .or_else(|| try_str(val, &["requestParameters", "backupJobId"]))
    };

    // plan_id: cluster/instance identifier for RDS, backup plan ID for Backup
    let plan_id = if is_rds {
        try_str(val, &["requestParameters", "dbClusterIdentifier"])
            .or_else(|| try_str(val, &["requestParameters", "dbInstanceIdentifier"]))
    } else {
        try_str(val, &["requestParameters", "backupPlanId"])
            .or_else(|| try_str(val, &["additionalEventData", "backupPlanId"]))
    };

    // resource_arn
    let resource_arn = if is_rds {
        try_str(val, &["responseElements", "dbClusterSnapshot", "dbClusterSnapshotArn"])
            .or_else(|| try_str(val, &["responseElements", "dbSnapshot", "dbSnapshotArn"]))
    } else {
        try_str(val, &["requestParameters", "resourceArn"])
            .or_else(|| try_str(val, &["resources", "0", "ARN"]))
    };

    // resource_type
    let resource_type = if is_rds {
        Some(if event_name.contains("Cluster") {
            "Aurora Cluster".to_string()
        } else {
            "RDS Instance".to_string()
        })
    } else {
        try_str(val, &["requestParameters", "resourceType"])
            .or_else(|| try_str(val, &["resources", "0", "type"]))
    };

    // status
    let status = if is_rds {
        try_str(val, &["responseElements", "dbClusterSnapshot", "status"])
            .or_else(|| try_str(val, &["responseElements", "dbSnapshot", "status"]))
    } else {
        try_str(val, &["responseElements", "status"])
            .or_else(|| try_str(val, &["additionalEventData", "status"]))
    };

    (job_id, plan_id, resource_arn, resource_type, status)
}

fn try_str(val: &serde_json::Value, path: &[&str]) -> Option<String> {
    let mut current = val;
    for key in path {
        current = current.get(key)?;
    }
    current.as_str().map(|s| s.to_string())
}
