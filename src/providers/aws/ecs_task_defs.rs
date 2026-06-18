use anyhow::Result;
use async_trait::async_trait;
use aws_sdk_ecs::types::TaskDefinitionFamilyStatus;
use aws_sdk_ecs::Client as EcsClient;

use crate::evidence::CsvCollector;

pub struct EcsTaskDefsCollector {
    client: EcsClient,
}

impl EcsTaskDefsCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self {
            client: EcsClient::new(config),
        }
    }
}

#[async_trait]
impl CsvCollector for EcsTaskDefsCollector {
    fn name(&self) -> &str {
        "ECS Task Definitions"
    }
    fn filename_prefix(&self) -> &str {
        "ECS_TaskDefinitions"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Family",
            "Revision",
            "Network Mode",
            "Container Name",
            "Privileged",
            "Run As User",
            "Readonly Root FS",
            "Added Capabilities",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let mut rows = Vec::new();

        // list_task_definition_families paginated (ACTIVE only).
        let mut families: Vec<String> = Vec::new();
        let mut next_token: Option<String> = None;
        loop {
            let mut req = self
                .client
                .list_task_definition_families()
                .status(TaskDefinitionFamilyStatus::Active);
            if let Some(ref t) = next_token {
                req = req.next_token(t);
            }
            let resp = match req.send().await {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("  WARN: ECS list_task_definition_families: {e:#}");
                    return Ok(rows);
                }
            };
            families.extend(resp.families().iter().map(|s| s.to_string()));
            next_token = resp.next_token().map(|s| s.to_string());
            if next_token.is_none() {
                break;
            }
        }

        for family in &families {
            let resp = match self
                .client
                .describe_task_definition()
                .task_definition(family)
                .send()
                .await
            {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("  WARN: ECS describe_task_definition family={family}: {e:#}");
                    continue;
                }
            };

            let td = match resp.task_definition() {
                Some(t) => t,
                None => continue,
            };

            let family_name = td.family().unwrap_or(family).to_string();
            let revision = td.revision().to_string();
            let network_mode = td
                .network_mode()
                .map(|n| n.as_str().to_string())
                .unwrap_or_default();

            for c in td.container_definitions() {
                let cname = c.name().unwrap_or("").to_string();
                let privileged = c.privileged().map(|b| b.to_string()).unwrap_or_default();
                let user = c.user().unwrap_or("").to_string();
                let readonly = c
                    .readonly_root_filesystem()
                    .map(|b| b.to_string())
                    .unwrap_or_default();
                let added_caps = c
                    .linux_parameters()
                    .and_then(|lp| lp.capabilities())
                    .map(|kc| kc.add().join(","))
                    .unwrap_or_default();

                rows.push(vec![
                    family_name.clone(),
                    revision.clone(),
                    network_mode.clone(),
                    cname,
                    privileged,
                    user,
                    readonly,
                    added_caps,
                ]);
            }
        }

        Ok(rows)
    }
}
