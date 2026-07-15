//! GCP Cloud SQL backup runs — equivalent to AWS RDS snapshots.

use anyhow::Result;
use async_trait::async_trait;

use crate::evidence::CsvCollector;
use crate::providers::gcp::client::GcpClient;

pub struct CloudSqlBackupsCollector {
    client: GcpClient,
    project_id: String,
}

impl CloudSqlBackupsCollector {
    pub fn new(client: GcpClient, project_id: impl Into<String>) -> Self {
        Self {
            client,
            project_id: project_id.into(),
        }
    }
}

#[async_trait]
impl CsvCollector for CloudSqlBackupsCollector {
    fn name(&self) -> &str {
        "GCP Cloud SQL Backups"
    }
    fn filename_prefix(&self) -> &str {
        "GCP_Cloud_SQL_Backups"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "project_id",
            "instance",
            "id",
            "status",
            "type",
            "start_time",
            "end_time",
            "backup_kind",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let instances_url = format!(
            "https://sqladmin.googleapis.com/sql/v1beta4/projects/{}/instances",
            self.project_id
        );
        let instances = self.client.paginate(&instances_url, "items").await?;

        let mut rows = Vec::new();
        for inst in &instances {
            let inst_name = inst
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_owned();
            let backups_url = format!(
                "https://sqladmin.googleapis.com/sql/v1beta4/projects/{}/instances/{}/backupRuns",
                self.project_id, inst_name
            );
            let backups = self.client.paginate(&backups_url, "items").await?;
            for backup in &backups {
                rows.push(vec![
                    self.project_id.clone(),
                    inst_name.clone(),
                    backup
                        .get("id")
                        .and_then(|v| v.as_i64())
                        .map(|i| i.to_string())
                        .unwrap_or_default(),
                    backup
                        .get("status")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_owned(),
                    backup
                        .get("type")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_owned(),
                    backup
                        .get("startTime")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_owned(),
                    backup
                        .get("endTime")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_owned(),
                    backup
                        .get("backupKind")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_owned(),
                ]);
            }
        }
        Ok(rows)
    }
}
