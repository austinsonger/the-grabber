use anyhow::Result;
use async_trait::async_trait;
use aws_sdk_backup::Client as BackupClient;

use crate::evidence::CsvCollector;

// ══════════════════════════════════════════════════════════════════════════════
// Backup Restore Testing Plans Collector
// ══════════════════════════════════════════════════════════════════════════════

pub struct BackupRestoreTestingCollector {
    client: BackupClient,
}

impl BackupRestoreTestingCollector {
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
impl CsvCollector for BackupRestoreTestingCollector {
    fn name(&self) -> &str {
        "Backup Restore Testing Plans"
    }
    fn filename_prefix(&self) -> &str {
        "Backup_RestoreTesting"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Test Plan Name",
            "Schedule",
            "Selection Window (days)",
            "Last Execution Time",
            "Last Status",
            "Selections",
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
            let mut req = self.client.list_restore_testing_plans();
            if let Some(ref t) = next_token {
                req = req.next_token(t);
            }
            let resp = match req.send().await {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("  WARN: Backup list_restore_testing_plans not available: {e:#}");
                    return Ok(rows);
                }
            };

            for plan_for_list in resp.restore_testing_plans() {
                let name = plan_for_list.restore_testing_plan_name().to_string();

                // get_restore_testing_plan for schedule + selection window
                let (schedule, sel_window, plan_arn) = match self
                    .client
                    .get_restore_testing_plan()
                    .restore_testing_plan_name(&name)
                    .send()
                    .await
                {
                    Ok(r) => {
                        let bp = r.restore_testing_plan();
                        let schedule = bp
                            .map(|p| p.schedule_expression().to_string())
                            .unwrap_or_default();
                        let sel_window = bp
                            .and_then(|p| p.recovery_point_selection())
                            .map(|s| s.selection_window_days().to_string())
                            .unwrap_or_default();
                        let arn = bp
                            .map(|p| p.restore_testing_plan_arn().to_string())
                            .unwrap_or_default();
                        (schedule, sel_window, arn)
                    }
                    Err(e) => {
                        eprintln!("  WARN: Backup get_restore_testing_plan {name}: {e:#}");
                        (String::new(), String::new(), String::new())
                    }
                };

                // list_restore_testing_selections for resource types
                let mut selections: Vec<String> = Vec::new();
                let mut sel_token: Option<String> = None;
                loop {
                    let mut sreq = self
                        .client
                        .list_restore_testing_selections()
                        .restore_testing_plan_name(&name);
                    if let Some(ref t) = sel_token {
                        sreq = sreq.next_token(t);
                    }
                    match sreq.send().await {
                        Ok(sresp) => {
                            for sel in sresp.restore_testing_selections() {
                                selections.push(format!(
                                    "{}:{}",
                                    sel.restore_testing_selection_name(),
                                    sel.protected_resource_type()
                                ));
                            }
                            sel_token = sresp.next_token().map(|s| s.to_string());
                            if sel_token.is_none() {
                                break;
                            }
                        }
                        Err(e) => {
                            eprintln!(
                                "  WARN: Backup list_restore_testing_selections {name}: {e:#}"
                            );
                            break;
                        }
                    }
                }
                let selections_str = selections.join(" | ");

                // list_restore_jobs filtered by this test plan ARN — take most recent
                let (last_exec, last_status) = if !plan_arn.is_empty() {
                    match self
                        .client
                        .list_restore_jobs()
                        .by_restore_testing_plan_arn(&plan_arn)
                        .max_results(50)
                        .send()
                        .await
                    {
                        Ok(jresp) => {
                            let jobs = jresp.restore_jobs();
                            let latest = jobs
                                .iter()
                                .max_by_key(|j| j.creation_date().map(|d| d.secs()).unwrap_or(0));
                            match latest {
                                Some(j) => {
                                    let t = j.creation_date().map(fmt_dt).unwrap_or_default();
                                    let s = j
                                        .status()
                                        .map(|s| s.as_str().to_string())
                                        .unwrap_or_default();
                                    (t, s)
                                }
                                None => (String::new(), String::new()),
                            }
                        }
                        Err(e) => {
                            eprintln!("  WARN: Backup list_restore_jobs {name}: {e:#}");
                            (String::new(), String::new())
                        }
                    }
                } else {
                    (String::new(), String::new())
                };

                rows.push(vec![
                    name,
                    schedule,
                    sel_window,
                    last_exec,
                    last_status,
                    selections_str,
                ]);
            }

            next_token = resp.next_token().map(|s| s.to_string());
            if next_token.is_none() {
                break;
            }
        }

        Ok(rows)
    }
}
