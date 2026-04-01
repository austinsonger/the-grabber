use anyhow::{Context, Result};
use async_trait::async_trait;
use aws_sdk_autoscaling::Client as AsgClient;

use crate::evidence::CsvCollector;

pub struct AutoScalingCollector {
    client: AsgClient,
}

impl AutoScalingCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self { client: AsgClient::new(config) }
    }
}

#[async_trait]
impl CsvCollector for AutoScalingCollector {
    fn name(&self) -> &str { "Auto Scaling Groups" }
    fn filename_prefix(&self) -> &str { "AutoScaling_Groups" }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Group Name", "Launch Template",
            "Desired Capacity", "Min", "Max",
            "Instances", "Region",
        ]
    }

    async fn collect_rows(&self, _account_id: &str, region: &str) -> Result<Vec<Vec<String>>> {
        let mut rows = Vec::new();
        let mut next_token: Option<String> = None;

        loop {
            let mut req = self.client.describe_auto_scaling_groups();
            if let Some(ref t) = next_token {
                req = req.next_token(t);
            }
            let resp = req.send().await.context("AutoScaling describe_auto_scaling_groups")?;

            for asg in resp.auto_scaling_groups() {
                let name = asg.auto_scaling_group_name().unwrap_or("").to_string();

                let launch_template = asg.launch_template()
                    .and_then(|lt| lt.launch_template_name())
                    .map(|s| s.to_string())
                    .or_else(|| asg.launch_configuration_name().map(|s| format!("LC:{s}")))
                    .unwrap_or_default();

                let desired  = asg.desired_capacity().map(|n| n.to_string()).unwrap_or_default();
                let min      = asg.min_size().map(|n| n.to_string()).unwrap_or_default();
                let max      = asg.max_size().map(|n| n.to_string()).unwrap_or_default();
                let instance_count = asg.instances().len().to_string();

                rows.push(vec![
                    name, launch_template, desired, min, max,
                    instance_count, region.to_string(),
                ]);
            }

            next_token = resp.next_token().map(|s| s.to_string());
            if next_token.is_none() { break; }
        }

        Ok(rows)
    }
}
