use anyhow::{Context, Result};
use async_trait::async_trait;
use aws_sdk_ec2::Client as Ec2Client;

use crate::evidence::CsvCollector;

pub struct LaunchTemplateCollector {
    client: Ec2Client,
}

impl LaunchTemplateCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self { client: Ec2Client::new(config) }
    }
}

#[async_trait]
impl CsvCollector for LaunchTemplateCollector {
    fn name(&self) -> &str { "EC2 Launch Templates" }
    fn filename_prefix(&self) -> &str { "Launch_Template_Config" }
    fn headers(&self) -> &'static [&'static str] {
        &["Template ID", "Template Name", "Version", "Image ID", "Instance Type", "Security Group IDs", "IAM Instance Profile"]
    }

    async fn collect_rows(&self, _account_id: &str, _region: &str) -> Result<Vec<Vec<String>>> {
        let mut rows = Vec::new();
        let mut next_token: Option<String> = None;

        // Collect template IDs + names
        let mut templates: Vec<(String, String)> = Vec::new();
        loop {
            let mut req = self.client.describe_launch_templates();
            if let Some(ref t) = next_token {
                req = req.next_token(t);
            }
            let resp = req.send().await.context("EC2 describe_launch_templates")?;
            for lt in resp.launch_templates() {
                templates.push((
                    lt.launch_template_id().unwrap_or("").to_string(),
                    lt.launch_template_name().unwrap_or("").to_string(),
                ));
            }
            next_token = resp.next_token().map(|s| s.to_string());
            if next_token.is_none() { break; }
        }

        // Describe the latest version of each template
        for (lt_id, lt_name) in &templates {
            let resp = match self.client
                .describe_launch_template_versions()
                .launch_template_id(lt_id)
                .versions("$Latest")
                .send()
                .await
            {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("  WARN: EC2 describe_launch_template_versions {lt_id}: {e:#}");
                    continue;
                }
            };

            for ver in resp.launch_template_versions() {
                let version = ver.version_number().map(|n| n.to_string()).unwrap_or_default();
                let data = match ver.launch_template_data() {
                    Some(d) => d,
                    None => continue,
                };

                let image_id     = data.image_id().unwrap_or("").to_string();
                let inst_type    = data.instance_type()
                    .map(|t| t.as_str().to_string())
                    .unwrap_or_default();
                let sg_ids: Vec<String> = data.security_group_ids()
                    .iter()
                    .map(|s| s.to_string())
                    .collect();
                let iam_profile  = data.iam_instance_profile()
                    .and_then(|p| p.arn().or(p.name()))
                    .unwrap_or("")
                    .to_string();

                rows.push(vec![
                    lt_id.clone(),
                    lt_name.clone(),
                    version,
                    image_id,
                    inst_type,
                    sg_ids.join(", "),
                    iam_profile,
                ]);
            }
        }

        Ok(rows)
    }
}
