use anyhow::{Context, Result};
use async_trait::async_trait;
use aws_sdk_resourcegroupstagging::Client as TagClient;

use crate::evidence::CsvCollector;

pub struct ResourceTaggingCollector {
    client: TagClient,
}

impl ResourceTaggingCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self { client: TagClient::new(config) }
    }
}

#[async_trait]
impl CsvCollector for ResourceTaggingCollector {
    fn name(&self) -> &str { "Resource Tagging Configuration" }
    fn filename_prefix(&self) -> &str { "Resource_Tagging_Config" }
    fn headers(&self) -> &'static [&'static str] {
        &["Resource ARN", "Resource Type", "Owner", "Environment", "Data Classification", "All Tags"]
    }

    async fn collect_rows(&self, _account_id: &str, _region: &str, _dates: Option<(i64, i64)>) -> Result<Vec<Vec<String>>> {
        let mut rows = Vec::new();
        let mut pagination_token: Option<String> = None;

        loop {
            let mut req = self.client
                .get_resources()
                .resources_per_page(100);
            if let Some(ref t) = pagination_token {
                req = req.pagination_token(t);
            }
            let resp = req.send().await.context("ResourceGroupsTaggingAPI get_resources")?;

            for resource in resp.resource_tag_mapping_list() {
                let arn = resource.resource_arn().unwrap_or("").to_string();

                // Extract resource type from ARN (e.g. arn:aws:ec2:...:instance/...)
                let res_type = {
                    let parts: Vec<&str> = arn.splitn(6, ':').collect();
                    if parts.len() >= 6 {
                        let service = parts.get(2).copied().unwrap_or("");
                        let resource = parts.get(5).copied().unwrap_or("");
                        let res_subtype = resource.split('/').next().unwrap_or(resource);
                        format!("{service}:{res_subtype}")
                    } else {
                        String::new()
                    }
                };

                let tags: std::collections::HashMap<&str, &str> = resource.tags()
                    .iter()
                    .map(|t| (t.key(), t.value()))
                    .collect();

                let owner      = tags.get("Owner").copied().unwrap_or("").to_string();
                let env        = tags.get("Environment").or_else(|| tags.get("Env")).copied().unwrap_or("").to_string();
                let data_class = tags.get("DataClassification")
                    .or_else(|| tags.get("Classification"))
                    .copied()
                    .unwrap_or("")
                    .to_string();

                let all_tags: Vec<String> = resource.tags()
                    .iter()
                    .map(|t| format!("{}={}", t.key(), t.value()))
                    .collect();

                rows.push(vec![arn, res_type, owner, env, data_class, all_tags.join("; ")]);
            }

            let token = resp.pagination_token().map(|s| s.to_string());
            // Empty string means no more pages
            if token.as_deref().map(|s| s.is_empty()).unwrap_or(true) {
                break;
            }
            pagination_token = token;
        }

        Ok(rows)
    }
}
