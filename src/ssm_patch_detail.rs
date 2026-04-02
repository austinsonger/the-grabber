use anyhow::Result;
use async_trait::async_trait;
use aws_sdk_ssm::Client as SsmClient;

use crate::evidence::CsvCollector;

fn epoch_to_rfc3339(secs: i64) -> String {
    chrono::DateTime::<chrono::Utc>::from_timestamp(secs, 0)
        .map(|c| c.to_rfc3339())
        .unwrap_or_default()
}

// ══════════════════════════════════════════════════════════════════════════════
// 1. SSM Patch Compliance (detailed per-patch)
// ══════════════════════════════════════════════════════════════════════════════

pub struct SsmPatchDetailCollector {
    client: SsmClient,
}

impl SsmPatchDetailCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self { client: SsmClient::new(config) }
    }
}

#[async_trait]
impl CsvCollector for SsmPatchDetailCollector {
    fn name(&self) -> &str { "SSM Patch Compliance (Detailed)" }
    fn filename_prefix(&self) -> &str { "SSM_Patch_Compliance_Detail" }
    fn headers(&self) -> &'static [&'static str] {
        &["Instance ID", "Patch ID", "Title", "Severity", "State", "Installed Time"]
    }

    async fn collect_rows(&self, _account_id: &str, _region: &str) -> Result<Vec<Vec<String>>> {
        let mut rows = Vec::new();

        // Get all managed instance IDs first
        let mut instance_ids: Vec<String> = Vec::new();
        let mut next_token: Option<String> = None;
        loop {
            let mut req = self.client.describe_instance_information();
            if let Some(ref t) = next_token {
                req = req.next_token(t);
            }
            let resp = match req.send().await {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("  WARN: SSM describe_instance_information: {e:#}");
                    break;
                }
            };
            for info in resp.instance_information_list() {
                if let Some(id) = info.instance_id() {
                    instance_ids.push(id.to_string());
                }
            }
            next_token = resp.next_token().map(|s| s.to_string());
            if next_token.is_none() { break; }
        }

        // Per instance: get individual patch data (first page only to bound output)
        for instance_id in &instance_ids {
            let resp = match self.client
                .describe_instance_patches()
                .instance_id(instance_id)
                .send()
                .await
            {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("  WARN: SSM describe_instance_patches {instance_id}: {e:#}");
                    continue;
                }
            };

            for patch in resp.patches() {
                let kb_id    = patch.kb_id().to_string();
                let title    = patch.title().to_string();
                let severity = patch.severity().to_string();
                let state    = patch.state().as_str().to_string();
                let installed_time = epoch_to_rfc3339(patch.installed_time().secs());

                rows.push(vec![
                    instance_id.clone(), kb_id, title, severity, state, installed_time,
                ]);
            }
        }

        Ok(rows)
    }
}

// ══════════════════════════════════════════════════════════════════════════════
// 2. SSM Patch Summary (per instance)
// ══════════════════════════════════════════════════════════════════════════════

pub struct SsmPatchSummaryCollector {
    client: SsmClient,
}

impl SsmPatchSummaryCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self { client: SsmClient::new(config) }
    }
}

#[async_trait]
impl CsvCollector for SsmPatchSummaryCollector {
    fn name(&self) -> &str { "SSM Patch Summary" }
    fn filename_prefix(&self) -> &str { "SSM_Patch_Summary" }
    fn headers(&self) -> &'static [&'static str] {
        &["Instance ID", "Compliance Status", "Critical Count", "Security Count",
          "Other Count", "Missing Count", "Installed Count", "Operation"]
    }

    async fn collect_rows(&self, _account_id: &str, _region: &str) -> Result<Vec<Vec<String>>> {
        let mut rows = Vec::new();
        let mut next_token: Option<String> = None;

        loop {
            let mut req = self.client.describe_instance_patch_states();
            if let Some(ref t) = next_token {
                req = req.next_token(t);
            }
            let resp = match req.send().await {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("  WARN: SSM describe_instance_patch_states: {e:#}");
                    break;
                }
            };

            for state in resp.instance_patch_states() {
                let instance_id   = state.instance_id().to_string();
                let missing       = state.missing_count();
                let failed        = state.failed_count();
                let compliance    = if missing > 0 || failed > 0 { "NON_COMPLIANT" } else { "COMPLIANT" };
                let critical      = state.critical_non_compliant_count().unwrap_or(0).to_string();
                let security      = state.security_non_compliant_count().unwrap_or(0).to_string();
                let other         = state.other_non_compliant_count().unwrap_or(0).to_string();
                let installed     = state.installed_count().to_string();
                let operation     = state.operation().as_str().to_string();

                rows.push(vec![
                    instance_id,
                    compliance.to_string(),
                    critical,
                    security,
                    other,
                    missing.to_string(),
                    installed,
                    operation,
                ]);
            }

            next_token = resp.next_token().map(|s| s.to_string());
            if next_token.is_none() { break; }
        }

        Ok(rows)
    }
}

// ══════════════════════════════════════════════════════════════════════════════
// 3. SSM Patch Execution History
// ══════════════════════════════════════════════════════════════════════════════

pub struct SsmPatchExecutionCollector {
    client: SsmClient,
}

impl SsmPatchExecutionCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self { client: SsmClient::new(config) }
    }
}

#[async_trait]
impl CsvCollector for SsmPatchExecutionCollector {
    fn name(&self) -> &str { "SSM Patch Execution History" }
    fn filename_prefix(&self) -> &str { "SSM_Patch_Execution" }
    fn headers(&self) -> &'static [&'static str] {
        &["Command ID", "Instance ID", "Requested Date Time", "Completed Date Time", "Status"]
    }

    async fn collect_rows(&self, _account_id: &str, _region: &str) -> Result<Vec<Vec<String>>> {
        use aws_sdk_ssm::types::CommandFilterKey;

        let mut rows = Vec::new();
        let mut next_token: Option<String> = None;

        // Filter to patch-baseline run commands
        let filter = aws_sdk_ssm::types::CommandFilter::builder()
            .key(CommandFilterKey::DocumentName)
            .value("AWS-RunPatchBaseline")
            .build()
            .unwrap_or_else(|_| {
                aws_sdk_ssm::types::CommandFilter::builder()
                    .key(CommandFilterKey::DocumentName)
                    .value("AWS-RunPatchBaseline")
                    .build()
                    .expect("build CommandFilter")
            });

        loop {
            let mut req = self.client
                .list_commands()
                .filters(filter.clone());
            if let Some(ref t) = next_token {
                req = req.next_token(t);
            }
            let resp = match req.send().await {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("  WARN: SSM list_commands: {e:#}");
                    break;
                }
            };

            for cmd in resp.commands() {
                let command_id    = cmd.command_id().unwrap_or("").to_string();
                let requested_dt  = cmd.requested_date_time()
                    .map(|d| epoch_to_rfc3339(d.secs()))
                    .unwrap_or_default();
                let status        = cmd.status()
                    .map(|s| s.as_str().to_string())
                    .unwrap_or_default();
                let status_detail = cmd.status_details().unwrap_or("").to_string();
                // Instances: join the first few target instance IDs
                let instances: Vec<&str> = cmd.instance_ids()
                    .iter()
                    .map(|s| s.as_str())
                    .collect();
                let instance_summary = if instances.is_empty() {
                    "N/A (targets)".to_string()
                } else {
                    instances.join(", ")
                };

                rows.push(vec![
                    command_id,
                    instance_summary,
                    requested_dt,
                    status_detail, // completed_date_time not directly available; use status_details
                    status,
                ]);
            }

            next_token = resp.next_token().map(|s| s.to_string());
            if next_token.is_none() { break; }
        }

        Ok(rows)
    }
}

// ══════════════════════════════════════════════════════════════════════════════
// 4. SSM Maintenance Windows
// ══════════════════════════════════════════════════════════════════════════════

pub struct SsmMaintenanceWindowCollector {
    client: SsmClient,
}

impl SsmMaintenanceWindowCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self { client: SsmClient::new(config) }
    }
}

#[async_trait]
impl CsvCollector for SsmMaintenanceWindowCollector {
    fn name(&self) -> &str { "SSM Maintenance Windows" }
    fn filename_prefix(&self) -> &str { "SSM_Maintenance_Window" }
    fn headers(&self) -> &'static [&'static str] {
        &["Window ID", "Name", "Enabled", "Schedule", "Duration (hrs)", "Targets", "Tasks"]
    }

    async fn collect_rows(&self, _account_id: &str, _region: &str) -> Result<Vec<Vec<String>>> {
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
                let name      = window.name().unwrap_or("").to_string();
                let enabled   = window.enabled().to_string();
                let schedule  = window.schedule().unwrap_or("").to_string();
                let duration  = window.duration().unwrap_or(0).to_string();

                // Targets for this window
                let targets_summary = match self.client
                    .describe_maintenance_window_targets()
                    .window_id(&window_id)
                    .send()
                    .await
                {
                    Ok(r) => r.targets()
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
                let tasks_summary = match self.client
                    .describe_maintenance_window_tasks()
                    .window_id(&window_id)
                    .send()
                    .await
                {
                    Ok(r) => r.tasks()
                        .iter()
                        .map(|t| {
                            let task_name = t.name().unwrap_or("unknown");
                            let task_arn  = t.task_arn().unwrap_or("?");
                            format!("{task_name}[{task_arn}]")
                        })
                        .collect::<Vec<_>>()
                        .join("; "),
                    Err(_) => String::new(),
                };

                rows.push(vec![
                    window_id, name, enabled, schedule, duration,
                    targets_summary, tasks_summary,
                ]);
            }

            next_token = resp.next_token().map(|s| s.to_string());
            if next_token.is_none() { break; }
        }

        Ok(rows)
    }
}
