use anyhow::{Context, Result};
use async_trait::async_trait;
use aws_sdk_ssm::Client as SsmClient;

use crate::evidence::CsvCollector;

fn fmt_ssm_dt(dt: &aws_sdk_ssm::primitives::DateTime) -> String {
    chrono::DateTime::<chrono::Utc>::from_timestamp(dt.secs(), 0)
        .map(|c| c.to_rfc3339())
        .unwrap_or_default()
}

// ══════════════════════════════════════════════════════════════════════════════
// 1. SSM Patch Baselines
// ══════════════════════════════════════════════════════════════════════════════

pub struct SsmPatchBaselineCollector {
    client: SsmClient,
}

impl SsmPatchBaselineCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self {
            client: SsmClient::new(config),
        }
    }
}

#[async_trait]
impl CsvCollector for SsmPatchBaselineCollector {
    fn name(&self) -> &str {
        "SSM Patch Baselines"
    }
    fn filename_prefix(&self) -> &str {
        "SSM_Patch_Baseline_Config"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Baseline ID",
            "Name",
            "Operating System",
            "Default Baseline",
            "Approved Patches",
            "Patch Rules Summary",
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
            let mut req = self.client.describe_patch_baselines();
            if let Some(ref t) = next_token {
                req = req.next_token(t);
            }
            let resp = req.send().await.context("SSM describe_patch_baselines")?;

            for identity in resp.baseline_identities() {
                let baseline_id = identity.baseline_id().unwrap_or("").to_string();
                let name = identity.baseline_name().unwrap_or("").to_string();
                let os = identity
                    .operating_system()
                    .map(|o| o.as_str().to_string())
                    .unwrap_or_default();
                let is_default = identity.default_baseline().to_string();

                // Get full details for patch rules and approved patches
                let (approved_patches, patch_rules) = match self
                    .client
                    .get_patch_baseline()
                    .baseline_id(&baseline_id)
                    .send()
                    .await
                {
                    Ok(r) => {
                        let approved: Vec<String> =
                            r.approved_patches().iter().map(|s| s.to_string()).collect();

                        let rules: Vec<String> = r
                            .approval_rules()
                            .map(|ar| ar.patch_rules())
                            .unwrap_or_default()
                            .iter()
                            .map(|rule| {
                                let approve_after = rule
                                    .approve_after_days()
                                    .map(|n| format!("after={n}d"))
                                    .unwrap_or_default();
                                let compliance = rule
                                    .compliance_level()
                                    .map(|c| c.as_str().to_string())
                                    .unwrap_or_default();
                                format!("compliance={compliance},{approve_after}")
                            })
                            .collect();

                        (approved.join(", "), rules.join(" | "))
                    }
                    Err(e) => {
                        eprintln!("  WARN: SSM get_patch_baseline {baseline_id}: {e:#}");
                        (String::new(), String::new())
                    }
                };

                rows.push(vec![
                    baseline_id,
                    name,
                    os,
                    is_default,
                    approved_patches,
                    patch_rules,
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

// ══════════════════════════════════════════════════════════════════════════════
// 2. SSM Parameter Store Config
// ══════════════════════════════════════════════════════════════════════════════

pub struct SsmParameterConfigCollector {
    client: SsmClient,
}

impl SsmParameterConfigCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self {
            client: SsmClient::new(config),
        }
    }
}

#[async_trait]
impl CsvCollector for SsmParameterConfigCollector {
    fn name(&self) -> &str {
        "SSM Parameter Store Config"
    }
    fn filename_prefix(&self) -> &str {
        "SSM_Parameter_Config"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Name",
            "Type",
            "KMS Key ID",
            "Last Modified",
            "Description",
            "Tier",
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
            let mut req = self.client.describe_parameters();
            if let Some(ref t) = next_token {
                req = req.next_token(t);
            }
            let resp = req.send().await.context("SSM describe_parameters")?;

            for param in resp.parameters() {
                let name = param.name().unwrap_or("").to_string();
                let param_type = param
                    .r#type()
                    .map(|t| t.as_str().to_string())
                    .unwrap_or_default();
                let kms_key = param.key_id().unwrap_or("").to_string();
                let last_mod = param
                    .last_modified_date()
                    .map(fmt_ssm_dt)
                    .unwrap_or_default();
                let description = param.description().unwrap_or("").to_string();
                let tier = param
                    .tier()
                    .map(|t| t.as_str().to_string())
                    .unwrap_or_default();

                rows.push(vec![name, param_type, kms_key, last_mod, description, tier]);
            }

            next_token = resp.next_token().map(|s| s.to_string());
            if next_token.is_none() {
                break;
            }
        }

        Ok(rows)
    }
}

// ══════════════════════════════════════════════════════════════════════════════
// 3. EC2 Time Sync Config (executes chronyc/w32tm via SSM Run Command)
// ══════════════════════════════════════════════════════════════════════════════

const TIME_SYNC_POLL_INTERVAL_SECS: u64 = 5;
const TIME_SYNC_MAX_POLL_ATTEMPTS: u32 = 24; // 2 minutes

// AWS SSM `SendCommand` caps `InstanceIds` at 50 per call.
const TIME_SYNC_INSTANCE_CHUNK_SIZE: usize = 50;

pub struct TimeSyncConfigCollector {
    client: SsmClient,
}

impl TimeSyncConfigCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self {
            client: SsmClient::new(config),
        }
    }

    /// Runs `command` on up to `TIME_SYNC_INSTANCE_CHUNK_SIZE` instances at a time via
    /// SSM `send_command`, chunking `instance_ids` to stay within AWS's 50-instance-per-call
    /// `InstanceIds` limit. Each chunk gets its own independent send+poll cycle; a failure in
    /// one chunk (e.g. its `send_command` call erroring) leaves that chunk's instances out of
    /// the results map (they fall through to "Not Run" downstream) without affecting any other
    /// chunk's results.
    async fn run_and_collect(
        &self,
        document_name: &str,
        command: &str,
        instance_ids: &[String],
    ) -> Result<std::collections::HashMap<String, (String, String)>> {
        let mut results = std::collections::HashMap::new();

        for chunk in instance_ids.chunks(TIME_SYNC_INSTANCE_CHUNK_SIZE) {
            let chunk_results = self
                .run_and_collect_chunk(document_name, command, chunk)
                .await?;
            results.extend(chunk_results);
        }

        Ok(results)
    }

    /// Sends a single `send_command` call (at most `TIME_SYNC_INSTANCE_CHUNK_SIZE` instance IDs)
    /// and polls for its results. See `run_and_collect` for the chunking wrapper.
    async fn run_and_collect_chunk(
        &self,
        document_name: &str,
        command: &str,
        instance_ids: &[String],
    ) -> Result<std::collections::HashMap<String, (String, String)>> {
        let mut results = std::collections::HashMap::new();
        if instance_ids.is_empty() {
            return Ok(results);
        }

        let send_resp = match self
            .client
            .send_command()
            .document_name(document_name)
            .set_instance_ids(Some(instance_ids.to_vec()))
            .parameters("commands", vec![command.to_string()])
            .send()
            .await
        {
            Ok(r) => r,
            Err(e) => {
                eprintln!("  WARN: SSM send_command [{document_name}]: {e:#}");
                return Ok(results);
            }
        };

        let command_id = match send_resp.command().and_then(|c| c.command_id()) {
            Some(id) => id.to_string(),
            None => return Ok(results),
        };

        let interval = tokio::time::Duration::from_secs(TIME_SYNC_POLL_INTERVAL_SECS);
        for attempt in 1..=TIME_SYNC_MAX_POLL_ATTEMPTS {
            tokio::time::sleep(interval).await;

            let list_resp = match self
                .client
                .list_command_invocations()
                .command_id(&command_id)
                .details(true)
                .send()
                .await
            {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("  WARN: SSM list_command_invocations {command_id}: {e:#}");
                    break;
                }
            };

            let invocations = list_resp.command_invocations();
            // Terminal states per the `status()` enum (the coarse, strongly-typed field --
            // `status_details()` is a free-form string that also uses non-enum values like
            // "Delivery Timed Out" / "Execution Timed Out", so we key off `status()` instead
            // for both this check and the reported "Command Status" column below).
            //
            // `Iterator::all()` is vacuously true on an empty slice, so guard against the
            // eventual-consistency window where AWS hasn't yet materialized invocation
            // records for the just-sent command -- otherwise we'd exit on attempt 1 with
            // zero results and report every instance as "Not Run" despite the command
            // actually running.
            let all_terminal = !invocations.is_empty()
                && invocations.iter().all(|inv| {
                    matches!(
                        inv.status().map(|s| s.as_str()).unwrap_or(""),
                        "Success" | "Failed" | "Cancelled" | "TimedOut"
                    )
                });

            if all_terminal || attempt == TIME_SYNC_MAX_POLL_ATTEMPTS {
                for inv in invocations {
                    let instance_id = inv.instance_id().unwrap_or("").to_string();
                    let status = inv
                        .status()
                        .map(|s| s.as_str().to_string())
                        .unwrap_or_default();
                    let output = inv
                        .command_plugins()
                        .first()
                        .and_then(|p| p.output())
                        .unwrap_or("")
                        .chars()
                        .take(500)
                        .collect::<String>();
                    results.insert(instance_id, (status, output));
                }
                break;
            }
        }

        Ok(results)
    }
}

#[async_trait]
impl CsvCollector for TimeSyncConfigCollector {
    fn name(&self) -> &str {
        "EC2 Time Sync Config (SSM)"
    }
    fn filename_prefix(&self) -> &str {
        "Time_Sync_Config"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Instance ID",
            "Computer Name",
            "Platform",
            "SSM Ping Status",
            "Command Status",
            "Command Output",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let mut instances: Vec<(String, String, String, String)> = Vec::new();
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
                instances.push((
                    info.instance_id().unwrap_or("").to_string(),
                    info.computer_name().unwrap_or("").to_string(),
                    info.platform_type()
                        .map(|p| p.as_str().to_string())
                        .unwrap_or_default(),
                    info.ping_status()
                        .map(|p| p.as_str().to_string())
                        .unwrap_or_default(),
                ));
            }

            next_token = resp.next_token().map(|s| s.to_string());
            if next_token.is_none() {
                break;
            }
        }

        let linux_ids: Vec<String> = instances
            .iter()
            .filter(|(_, _, platform, _)| !platform.to_lowercase().contains("windows"))
            .map(|(id, ..)| id.clone())
            .collect();
        let windows_ids: Vec<String> = instances
            .iter()
            .filter(|(_, _, platform, _)| platform.to_lowercase().contains("windows"))
            .map(|(id, ..)| id.clone())
            .collect();

        let mut command_results = self
            .run_and_collect("AWS-RunShellScript", "chronyc sources -v", &linux_ids)
            .await?;
        command_results.extend(
            self.run_and_collect(
                "AWS-RunPowerShellScript",
                "w32tm /query /peers",
                &windows_ids,
            )
            .await?,
        );

        let mut rows = Vec::new();
        for (instance_id, computer_name, platform, ping_status) in instances {
            let (cmd_status, cmd_output) = command_results
                .get(&instance_id)
                .cloned()
                .unwrap_or_else(|| ("Not Run".to_string(), String::new()));
            rows.push(vec![
                instance_id,
                computer_name,
                platform,
                ping_status,
                cmd_status,
                cmd_output,
            ]);
        }

        Ok(rows)
    }
}

// ══════════════════════════════════════════════════════════════════════════════
// 4. SSM Instance Associations Status
// ══════════════════════════════════════════════════════════════════════════════

pub struct SsmInstanceAssociationsStatusCollector {
    client: SsmClient,
}

impl SsmInstanceAssociationsStatusCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self {
            client: SsmClient::new(config),
        }
    }
}

#[async_trait]
impl CsvCollector for SsmInstanceAssociationsStatusCollector {
    fn name(&self) -> &str {
        "SSM Instance Associations Status"
    }
    fn filename_prefix(&self) -> &str {
        "SSM_Instance_Associations_Status"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Instance ID",
            "Association ID",
            "Association Name",
            "Status",
            "Error Code",
            "Executed Date",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let mut rows = Vec::new();

        // Gather managed instance IDs first (same pattern as TimeSyncConfigCollector).
        let mut instance_ids: Vec<String> = Vec::new();
        let mut inst_next: Option<String> = None;
        loop {
            let mut req = self.client.describe_instance_information();
            if let Some(ref t) = inst_next {
                req = req.next_token(t);
            }
            let resp = match req.send().await {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("  WARN: SSM describe_instance_information: {e:#}");
                    break;
                }
            };
            instance_ids.extend(
                resp.instance_information_list()
                    .iter()
                    .filter_map(|i| i.instance_id().map(|s| s.to_string())),
            );
            inst_next = resp.next_token().map(|s| s.to_string());
            if inst_next.is_none() {
                break;
            }
        }

        for instance_id in &instance_ids {
            let mut assoc_next: Option<String> = None;
            loop {
                let mut req = self
                    .client
                    .describe_instance_associations_status()
                    .instance_id(instance_id);
                if let Some(ref t) = assoc_next {
                    req = req.next_token(t);
                }
                let resp = match req.send().await {
                    Ok(r) => r,
                    Err(e) => {
                        eprintln!(
                            "  WARN: SSM describe_instance_associations_status {instance_id}: {e:#}"
                        );
                        break;
                    }
                };
                for assoc in resp.instance_association_status_infos() {
                    rows.push(vec![
                        instance_id.clone(),
                        assoc.association_id().unwrap_or("").to_string(),
                        assoc.association_name().unwrap_or("").to_string(),
                        assoc.status().unwrap_or("").to_string(),
                        assoc.error_code().unwrap_or("").to_string(),
                        assoc.execution_date().map(fmt_ssm_dt).unwrap_or_default(),
                    ]);
                }
                assoc_next = resp.next_token().map(|s| s.to_string());
                if assoc_next.is_none() {
                    break;
                }
            }
        }

        Ok(rows)
    }
}
