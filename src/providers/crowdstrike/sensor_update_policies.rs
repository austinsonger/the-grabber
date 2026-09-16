use anyhow::Result;
use async_trait::async_trait;
use crowdstrike_rs::CrowdStrikeClient;
use serde_json::Value;

use crate::evidence::CsvCollector;

pub struct CrowdStrikeSensorUpdatePoliciesCollector {
    client: CrowdStrikeClient,
}

impl CrowdStrikeSensorUpdatePoliciesCollector {
    pub fn new(client: CrowdStrikeClient) -> Self {
        Self { client }
    }
}

#[async_trait]
impl CsvCollector for CrowdStrikeSensorUpdatePoliciesCollector {
    fn name(&self) -> &str {
        "CrowdStrike Sensor Update Policies"
    }
    fn filename_prefix(&self) -> &str {
        "CrowdStrike_Sensor_Update_Policies"
    }

    fn headers(&self) -> &'static [&'static str] {
        &[
            "Policy ID",
            "Name",
            "Platform",
            "Enabled",
            "Build",
            "Scheduler Enabled",
            "Uninstall Protection",
            "Created",
            "Modified",
            "Created By",
            "Modified By",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let policies = match self.client.sensor_update_policies().list_all().await {
            Ok(p) => p,
            Err(crowdstrike_rs::CrowdStrikeError::Api { status: 404, .. }) => return Ok(vec![]),
            Err(e) => return Err(e.into()),
        };
        let rows = policies
            .into_iter()
            .map(|p| {
                let build = p
                    .settings
                    .get("build")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string();
                let scheduler_enabled = p
                    .settings
                    .get("scheduler")
                    .and_then(|s| s.get("enabled"))
                    .and_then(Value::as_bool)
                    .map(|b| if b { "YES" } else { "NO" })
                    .unwrap_or_default()
                    .to_string();
                let uninstall_protection = p
                    .settings
                    .get("uninstall_protection")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string();
                vec![
                    p.id,
                    p.name.unwrap_or_default(),
                    p.platform_name.unwrap_or_default(),
                    p.enabled
                        .map(|b| if b { "YES" } else { "NO" })
                        .unwrap_or_default()
                        .to_string(),
                    build,
                    scheduler_enabled,
                    uninstall_protection,
                    p.created_timestamp.unwrap_or_default(),
                    p.modified_timestamp.unwrap_or_default(),
                    p.created_by.unwrap_or_default(),
                    p.modified_by.unwrap_or_default(),
                ]
            })
            .collect();
        Ok(rows)
    }
}
