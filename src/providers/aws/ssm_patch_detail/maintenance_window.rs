use anyhow::Result;
use async_trait::async_trait;
use aws_sdk_ssm::Client as SsmClient;

use crate::evidence::CsvCollector;

pub struct SsmMaintenanceWindowCollector {
    client: SsmClient,
}

impl SsmMaintenanceWindowCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self {
            client: SsmClient::new(config),
        }
    }
}

#[async_trait]
impl CsvCollector for SsmMaintenanceWindowCollector {
    fn name(&self) -> &str {
        "SSM Maintenance Windows"
    }
    fn filename_prefix(&self) -> &str {
        "SSM_Maintenance_Window"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Window ID",
            "Name",
            "Enabled",
            "Schedule",
            "Duration (hrs)",
            "Targets",
            "Tasks",
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
            let mut req = self.client.describe_maintenance_windows();
            if let Some(ref t) = next_token {
                req = req.next_token(t);
            }
            let resp = match req.send().await {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("  WARN: SSM describe_maintenance_windows: {e:#}");
                    break;
                }
            };

            for window in resp.window_identities() {
                let window_id = window.window_id().unwrap_or("").to_string();
                let name = window.name().unwrap_or("").to_string();
                let enabled = window.enabled().to_string();
                let schedule = window.schedule().unwrap_or("").to_string();
                let duration = window.duration().unwrap_or(0).to_string();

                // Targets for this window
                let targets_summary = match self
                    .client
                    .describe_maintenance_window_targets()
                    .window_id(&window_id)
                    .send()
                    .await
                {
                    Ok(r) => r
                        .targets()
                        .iter()
                        .flat_map(|wt| wt.targets())
                        .map(|t| {
                            let key = t.key().unwrap_or("");
                            let vals = t.values().join(",");
                            format!("{key}={vals}")
                        })
                        .collect::<Vec<_>>()
                        .join("; "),
                    Err(_) => String::new(),
                };

                // Tasks for this window
                let tasks_summary = match self
                    .client
                    .describe_maintenance_window_tasks()
                    .window_id(&window_id)
                    .send()
                    .await
                {
                    Ok(r) => r
                        .tasks()
                        .iter()
                        .map(|t| {
                            let task_name = t.name().unwrap_or("unknown");
                            let task_arn = t.task_arn().unwrap_or("?");
                            format!("{task_name}[{task_arn}]")
                        })
                        .collect::<Vec<_>>()
                        .join("; "),
                    Err(_) => String::new(),
                };

                rows.push(vec![
                    window_id,
                    name,
                    enabled,
                    schedule,
                    duration,
                    targets_summary,
                    tasks_summary,
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
