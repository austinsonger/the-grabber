use anyhow::{Context, Result};
use async_trait::async_trait;
use aws_sdk_backup::Client as BackupClient;

use crate::evidence::CsvCollector;

// ══════════════════════════════════════════════════════════════════════════════
// Backup Vault Lock Configuration Collector
// ══════════════════════════════════════════════════════════════════════════════

pub struct BackupVaultLockCollector {
    client: BackupClient,
}

impl BackupVaultLockCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self {
            client: BackupClient::new(config),
        }
    }
}

fn fmt_dt(dt: &aws_sdk_backup::primitives::DateTime) -> String {
    chrono::DateTime::<chrono::Utc>::from_timestamp(dt.secs(), dt.subsec_nanos())
        .map(|c| c.to_rfc3339())
        .unwrap_or_default()
}

#[async_trait]
impl CsvCollector for BackupVaultLockCollector {
    fn name(&self) -> &str {
        "Backup Vault Lock Configuration"
    }
    fn filename_prefix(&self) -> &str {
        "Backup_VaultLock_Config"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Vault Name",
            "Vault ARN",
            "Locked",
            "Lock Date",
            "Min Retention (days)",
            "Max Retention (days)",
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
            let mut req = self.client.list_backup_vaults();
            if let Some(ref t) = next_token {
                req = req.next_token(t);
            }
            let resp = req.send().await.context("Backup list_backup_vaults")?;

            for vault in resp.backup_vault_list() {
                let vault_name = match vault.backup_vault_name() {
                    Some(n) => n.to_string(),
                    None => continue,
                };

                match self
                    .client
                    .describe_backup_vault()
                    .backup_vault_name(&vault_name)
                    .send()
                    .await
                {
                    Ok(d) => {
                        let arn = d.backup_vault_arn().unwrap_or("").to_string();
                        let locked = d
                            .locked()
                            .map(|b| if b { "Yes" } else { "No" }.to_string())
                            .unwrap_or_default();
                        let lock_date = d.lock_date().map(fmt_dt).unwrap_or_default();
                        let min_ret = d
                            .min_retention_days()
                            .map(|n| n.to_string())
                            .unwrap_or_default();
                        let max_ret = d
                            .max_retention_days()
                            .map(|n| n.to_string())
                            .unwrap_or_default();

                        rows.push(vec![vault_name, arn, locked, lock_date, min_ret, max_ret]);
                    }
                    Err(e) => {
                        eprintln!("  WARN: Backup describe_backup_vault {vault_name}: {e:#}");
                    }
                }
            }

            next_token = resp.next_token().map(|s| s.to_string());
            if next_token.is_none() {
                break;
            }
        }

        Ok(rows)
    }
}
