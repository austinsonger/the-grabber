use anyhow::Result;
use async_trait::async_trait;
use aws_sdk_ssm::Client as SsmClient;

use crate::evidence::CsvCollector;

pub struct SsmPatchDetailCollector {
    client: SsmClient,
}

impl SsmPatchDetailCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self {
            client: SsmClient::new(config),
        }
    }
}

#[async_trait]
impl CsvCollector for SsmPatchDetailCollector {
    fn name(&self) -> &str {
        "SSM Patch Compliance (Detailed)"
    }
    fn filename_prefix(&self) -> &str {
        "SSM_Patch_Compliance_Detail"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Instance ID",
            "Patch ID",
            "Title",
            "Severity",
            "State",
            "Installed Time",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
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
            if next_token.is_none() {
                break;
            }
        }

        // Per instance: get individual patch data (first page only to bound output)
        for instance_id in &instance_ids {
            let resp = match self
                .client
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
                let kb_id = patch.kb_id().to_string();
                let title = patch.title().to_string();
                let severity = patch.severity().to_string();
                let state = patch.state().as_str().to_string();
                let installed_time = super::epoch_to_rfc3339(patch.installed_time().secs());

                rows.push(vec![
                    instance_id.clone(),
                    kb_id,
                    title,
                    severity,
                    state,
                    installed_time,
                ]);
            }
        }

        Ok(rows)
    }
}
