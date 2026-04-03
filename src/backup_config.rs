use anyhow::{Context, Result};
use async_trait::async_trait;
use aws_sdk_backup::Client as BackupClient;
use aws_sdk_rds::Client as RdsClient;

use crate::evidence::CsvCollector;

// ══════════════════════════════════════════════════════════════════════════════
// 1. AWS Backup Plans
// ══════════════════════════════════════════════════════════════════════════════

pub struct BackupPlanConfigCollector {
    client: BackupClient,
}

impl BackupPlanConfigCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self { client: BackupClient::new(config) }
    }
}

#[async_trait]
impl CsvCollector for BackupPlanConfigCollector {
    fn name(&self) -> &str { "AWS Backup Plans" }
    fn filename_prefix(&self) -> &str { "Backup_Plans_Config" }
    fn headers(&self) -> &'static [&'static str] {
        &["Plan ID", "Plan Name", "Version ID", "Rules Count", "Rules Summary"]
    }

    async fn collect_rows(&self, _account_id: &str, _region: &str, _dates: Option<(i64, i64)>) -> Result<Vec<Vec<String>>> {
        let mut rows = Vec::new();
        let mut next_token: Option<String> = None;

        loop {
            let mut req = self.client.list_backup_plans();
            if let Some(ref t) = next_token {
                req = req.next_token(t);
            }
            let resp = req.send().await.context("Backup list_backup_plans")?;

            for plan in resp.backup_plans_list() {
                let plan_id   = plan.backup_plan_id().unwrap_or("").to_string();
                let plan_name = plan.backup_plan_name().unwrap_or("").to_string();
                let version   = plan.version_id().unwrap_or("").to_string();

                let (rules_count, rules_summary) = match self.client
                    .get_backup_plan()
                    .backup_plan_id(&plan_id)
                    .send()
                    .await
                {
                    Ok(r) => {
                        let rules: Vec<String> = r.backup_plan()
                            .map(|bp| bp.rules())
                            .unwrap_or_default()
                            .iter()
                            .map(|rule| {
                                let rule_name = rule.rule_name();
                                let vault     = rule.target_backup_vault_name();
                                let schedule  = rule.schedule_expression().unwrap_or("");
                                let retention = rule.lifecycle()
                                    .and_then(|l| l.delete_after_days())
                                    .map(|n| format!("delete={n}d"))
                                    .unwrap_or_default();
                                format!("{rule_name}→{vault} sched={schedule} {retention}")
                            })
                            .collect();
                        (rules.len().to_string(), rules.join(" | "))
                    }
                    Err(e) => {
                        eprintln!("  WARN: Backup get_backup_plan {plan_id}: {e:#}");
                        (String::new(), String::new())
                    }
                };

                rows.push(vec![plan_id, plan_name, version, rules_count, rules_summary]);
            }

            next_token = resp.next_token().map(|s| s.to_string());
            if next_token.is_none() { break; }
        }

        Ok(rows)
    }
}

// ══════════════════════════════════════════════════════════════════════════════
// 2. Backup Vault Config
// ══════════════════════════════════════════════════════════════════════════════

pub struct BackupVaultConfigCollector {
    client: BackupClient,
}

impl BackupVaultConfigCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self { client: BackupClient::new(config) }
    }
}

#[async_trait]
impl CsvCollector for BackupVaultConfigCollector {
    fn name(&self) -> &str { "Backup Vault Configuration" }
    fn filename_prefix(&self) -> &str { "Backup_Vault_Config" }
    fn headers(&self) -> &'static [&'static str] {
        &["Vault Name", "Vault ARN", "Encryption Key ARN", "Recovery Points", "Has Access Policy"]
    }

    async fn collect_rows(&self, _account_id: &str, _region: &str, _dates: Option<(i64, i64)>) -> Result<Vec<Vec<String>>> {
        let mut rows = Vec::new();
        let mut next_token: Option<String> = None;

        loop {
            let mut req = self.client.list_backup_vaults();
            if let Some(ref t) = next_token {
                req = req.next_token(t);
            }
            let resp = req.send().await.context("Backup list_backup_vaults")?;

            for vault in resp.backup_vault_list() {
                let vault_name    = vault.backup_vault_name().unwrap_or("").to_string();
                let vault_arn     = vault.backup_vault_arn().unwrap_or("").to_string();
                let enc_key       = vault.encryption_key_arn().unwrap_or("").to_string();
                let recovery_pts  = vault.number_of_recovery_points().to_string();

                let has_policy = match self.client
                    .get_backup_vault_access_policy()
                    .backup_vault_name(&vault_name)
                    .send()
                    .await
                {
                    Ok(r) => if r.policy().map(|p| !p.is_empty()).unwrap_or(false) { "Yes" } else { "No" },
                    Err(e) => {
                        let msg = format!("{e}");
                        if msg.contains("ResourceNotFoundException") { "No" } else { "Unknown" }
                    }
                }.to_string();

                rows.push(vec![vault_name, vault_arn, enc_key, recovery_pts, has_policy]);
            }

            next_token = resp.next_token().map(|s| s.to_string());
            if next_token.is_none() { break; }
        }

        Ok(rows)
    }
}

// ══════════════════════════════════════════════════════════════════════════════
// 3. RDS Backup Config
// ══════════════════════════════════════════════════════════════════════════════

pub struct RdsBackupConfigCollector {
    client: RdsClient,
}

impl RdsBackupConfigCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self { client: RdsClient::new(config) }
    }
}

#[async_trait]
impl CsvCollector for RdsBackupConfigCollector {
    fn name(&self) -> &str { "RDS Backup Configuration" }
    fn filename_prefix(&self) -> &str { "RDS_Backup_Config" }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "DB Instance ID", "Engine", "Multi-AZ", "Backup Retention (days)",
            "Preferred Backup Window", "Auto Minor Upgrade", "Deletion Protection",
        ]
    }

    async fn collect_rows(&self, _account_id: &str, _region: &str, _dates: Option<(i64, i64)>) -> Result<Vec<Vec<String>>> {
        let mut rows = Vec::new();
        let mut marker: Option<String> = None;

        loop {
            let mut req = self.client.describe_db_instances();
            if let Some(ref m) = marker {
                req = req.marker(m);
            }
            let resp = req.send().await.context("RDS describe_db_instances")?;

            for db in resp.db_instances() {
                let id          = db.db_instance_identifier().unwrap_or("").to_string();
                let engine      = db.engine().unwrap_or("").to_string();
                let multi_az    = db.multi_az().unwrap_or(false).to_string();
                let retention   = db.backup_retention_period()
                    .map(|n| n.to_string())
                    .unwrap_or_else(|| "0".to_string());
                let backup_win  = db.preferred_backup_window().unwrap_or("").to_string();
                let auto_minor  = db.auto_minor_version_upgrade().unwrap_or(false).to_string();
                let del_protect = db.deletion_protection().unwrap_or(false).to_string();

                rows.push(vec![id, engine, multi_az, retention, backup_win, auto_minor, del_protect]);
            }

            marker = resp.marker().map(|s| s.to_string());
            if marker.is_none() { break; }
        }

        Ok(rows)
    }
}
