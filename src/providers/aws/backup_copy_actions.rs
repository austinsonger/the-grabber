use anyhow::{Context, Result};
use async_trait::async_trait;
use aws_sdk_backup::Client as BackupClient;

use crate::evidence::CsvCollector;

// ══════════════════════════════════════════════════════════════════════════════
// Backup Plan Cross-Region / Cross-Account Copy Actions Collector
// ══════════════════════════════════════════════════════════════════════════════

pub struct BackupCopyActionsCollector {
    client: BackupClient,
}

impl BackupCopyActionsCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self {
            client: BackupClient::new(config),
        }
    }
}

/// Parse `arn:aws:backup:<region>:<account_id>:backup-vault:<vault-name>`
/// → (region, account_id). Returns ("", "") if shape is unexpected.
fn parse_vault_arn(arn: &str) -> (String, String) {
    let parts: Vec<&str> = arn.split(':').collect();
    if parts.len() >= 6 && parts[0] == "arn" && parts[2] == "backup" {
        (parts[3].to_string(), parts[4].to_string())
    } else {
        (String::new(), String::new())
    }
}

#[async_trait]
impl CsvCollector for BackupCopyActionsCollector {
    fn name(&self) -> &str {
        "Backup Plan Copy Actions"
    }
    fn filename_prefix(&self) -> &str {
        "Backup_Plan_Copy_Actions"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Plan ID",
            "Plan Name",
            "Rule Name",
            "Destination Vault ARN",
            "Destination Region",
            "Destination Account",
            "Cold Storage After (days)",
            "Delete After (days)",
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
            let mut req = self.client.list_backup_plans();
            if let Some(ref t) = next_token {
                req = req.next_token(t);
            }
            let resp = req.send().await.context("Backup list_backup_plans")?;

            for plan in resp.backup_plans_list() {
                let plan_id = plan.backup_plan_id().unwrap_or("").to_string();
                let plan_name = plan.backup_plan_name().unwrap_or("").to_string();
                if plan_id.is_empty() {
                    continue;
                }

                let plan_resp = match self
                    .client
                    .get_backup_plan()
                    .backup_plan_id(&plan_id)
                    .send()
                    .await
                {
                    Ok(r) => r,
                    Err(e) => {
                        eprintln!("  WARN: Backup get_backup_plan {plan_id}: {e:#}");
                        continue;
                    }
                };

                let rules = plan_resp
                    .backup_plan()
                    .map(|bp| bp.rules())
                    .unwrap_or_default();

                for rule in rules {
                    let rule_name = rule.rule_name().to_string();
                    for ca in rule.copy_actions() {
                        let dest_arn = ca.destination_backup_vault_arn().to_string();
                        let (region, account) = parse_vault_arn(&dest_arn);
                        let (cold, del) = ca
                            .lifecycle()
                            .map(|l| {
                                (
                                    l.move_to_cold_storage_after_days()
                                        .map(|n| n.to_string())
                                        .unwrap_or_default(),
                                    l.delete_after_days()
                                        .map(|n| n.to_string())
                                        .unwrap_or_default(),
                                )
                            })
                            .unwrap_or_default();

                        rows.push(vec![
                            plan_id.clone(),
                            plan_name.clone(),
                            rule_name.clone(),
                            dest_arn,
                            region,
                            account,
                            cold,
                            del,
                        ]);
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
