//! For every S3 bucket, emits its versioning + replication status and any
//! AWS Backup vault that targets buckets. Auditors use this to prove the
//! 3-copy backup posture on documentation stores for FedRAMP CP-09c.

use anyhow::{Context, Result};
use async_trait::async_trait;
use aws_sdk_backup::Client as BackupClient;
use aws_sdk_s3::Client as S3Client;

use crate::evidence::CsvCollector;

pub struct DocRepoBackupConfigCollector {
    s3: S3Client,
    backup: BackupClient,
}

impl DocRepoBackupConfigCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self {
            s3: S3Client::new(config),
            backup: BackupClient::new(config),
        }
    }
}

#[async_trait]
impl CsvCollector for DocRepoBackupConfigCollector {
    fn name(&self) -> &str {
        "Documentation Repository Backup Config (S3 + Backup vaults)"
    }
    fn filename_prefix(&self) -> &str {
        "Doc_Repo_Backup_Config"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Kind",
            "Name / ARN",
            "Region",
            "Versioning",
            "Replication",
            "Vault Recovery Points",
            "Notes",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let mut rows: Vec<Vec<String>> = Vec::new();

        // S3 buckets — versioning + replication
        let buckets = self.s3.list_buckets().send().await.context("s3:ListBuckets")?;
        for b in buckets.buckets() {
            let name = match b.name() {
                Some(n) => n.to_string(),
                None => continue,
            };
            let ver = self
                .s3
                .get_bucket_versioning()
                .bucket(&name)
                .send()
                .await
                .map(|r| {
                    r.status()
                        .map(|s| s.as_str().to_string())
                        .unwrap_or_else(|| "Disabled".into())
                })
                .unwrap_or_else(|_| "Unknown".into());
            let repl = self
                .s3
                .get_bucket_replication()
                .bucket(&name)
                .send()
                .await
                .map(|r| {
                    r.replication_configuration()
                        .map(|c| {
                            c.rules()
                                .iter()
                                .map(|r| {
                                    format!(
                                        "{}→{}",
                                        r.id().unwrap_or(""),
                                        r.destination()
                                            .map(|d| d.bucket())
                                            .unwrap_or("?"),
                                    )
                                })
                                .collect::<Vec<_>>()
                                .join(";")
                        })
                        .unwrap_or_default()
                })
                .unwrap_or_default();
            rows.push(vec![
                "S3Bucket".into(),
                name,
                region.into(),
                ver,
                repl,
                String::new(),
                String::new(),
            ]);
        }

        // Backup vaults
        let mut next: Option<String> = None;
        loop {
            let mut req = self.backup.list_backup_vaults();
            if let Some(t) = next.as_ref() {
                req = req.next_token(t);
            }
            let resp = req.send().await.context("backup:ListBackupVaults")?;
            for v in resp.backup_vault_list() {
                rows.push(vec![
                    "BackupVault".into(),
                    v.backup_vault_arn().unwrap_or("").into(),
                    region.into(),
                    String::new(),
                    String::new(),
                    v.number_of_recovery_points().to_string(),
                    v.encryption_key_arn().unwrap_or("").into(),
                ]);
            }
            next = resp.next_token().map(|s| s.to_string());
            if next.is_none() {
                break;
            }
        }
        Ok(rows)
    }
}
