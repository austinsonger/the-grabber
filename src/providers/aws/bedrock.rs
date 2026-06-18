use anyhow::Result;
use async_trait::async_trait;
use aws_sdk_bedrock::Client as BedrockClient;

use crate::evidence::CsvCollector;

// ══════════════════════════════════════════════════════════════════════════════
// Bedrock Posture Collector — guardrails + model-invocation logging.
// ══════════════════════════════════════════════════════════════════════════════

pub struct BedrockCollector {
    client: BedrockClient,
}

impl BedrockCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self {
            client: BedrockClient::new(config),
        }
    }
}

fn is_benign(err: &str) -> bool {
    err.contains("AccessDenied")
        || err.contains("AccessDeniedException")
        || err.contains("ResourceNotFoundException")
        || err.contains("UnauthorizedOperation")
        || err.contains("not available")
        || err.contains("UnknownEndpoint")
        || err.contains("dispatch failure")
        || err.contains("InvalidAction")
        || err.contains("OptInRequired")
}

#[async_trait]
impl CsvCollector for BedrockCollector {
    fn name(&self) -> &str {
        "Bedrock Posture"
    }
    fn filename_prefix(&self) -> &str {
        "Bedrock_Posture"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Type",
            "ID / Name",
            "Status",
            "Content Filters / Log Destination",
            "KMS Key",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let mut rows: Vec<Vec<String>> = Vec::new();

        // Guardrails.
        let mut paginator = self.client.list_guardrails().into_paginator().send();
        while let Some(page) = paginator.next().await {
            let resp = match page {
                Ok(r) => r,
                Err(e) => {
                    let msg = format!("{e:#}");
                    if is_benign(&msg) {
                        return Ok(rows);
                    }
                    eprintln!("  WARN: Bedrock list_guardrails: {msg}");
                    break;
                }
            };
            for g in resp.guardrails() {
                let id = g.id().to_string();
                let name = g.name().to_string();
                let status = g.status().as_str().to_string();
                let version = g.version().to_string();
                if id.is_empty() {
                    continue;
                }
                let detail = match self
                    .client
                    .get_guardrail()
                    .guardrail_identifier(&id)
                    .guardrail_version(&version)
                    .send()
                    .await
                {
                    Ok(d) => d,
                    Err(e) => {
                        let msg = format!("{e:#}");
                        if is_benign(&msg) {
                            return Ok(rows);
                        }
                        eprintln!("  WARN: Bedrock get_guardrail: {msg}");
                        continue;
                    }
                };
                let content_filters = detail
                    .content_policy()
                    .map(|cp| cp.filters().len())
                    .unwrap_or(0);
                let topics = detail
                    .topic_policy()
                    .map(|tp| tp.topics().len())
                    .unwrap_or(0);
                let word_lists = detail
                    .word_policy()
                    .map(|wp| wp.managed_word_lists().len())
                    .unwrap_or(0);
                let kms = detail.kms_key_arn().unwrap_or("").to_string();
                let combo = format!(
                    "filters={content_filters} / topics={topics} / word_lists={word_lists}"
                );
                let id_name = format!("{id} / {name}");
                rows.push(vec!["Guardrail".to_string(), id_name, status, combo, kms]);
            }
        }

        // Model invocation logging.
        match self
            .client
            .get_model_invocation_logging_configuration()
            .send()
            .await
        {
            Ok(resp) => {
                if let Some(cfg) = resp.logging_config() {
                    let log_group = cfg
                        .cloud_watch_config()
                        .map(|c| c.log_group_name().to_string())
                        .unwrap_or_default();
                    let bucket = cfg
                        .s3_config()
                        .map(|s| s.bucket_name().to_string())
                        .unwrap_or_default();
                    let img = cfg
                        .image_data_delivery_enabled()
                        .map(|b| b.to_string())
                        .unwrap_or_default();
                    let txt = cfg
                        .text_data_delivery_enabled()
                        .map(|b| b.to_string())
                        .unwrap_or_default();
                    let dest = format!("log_group={log_group} / s3_bucket={bucket}");
                    let status = format!("image={img} / text={txt}");
                    rows.push(vec![
                        "Logging".to_string(),
                        "model-invocation".to_string(),
                        status,
                        dest,
                        String::new(),
                    ]);
                }
            }
            Err(e) => {
                let msg = format!("{e:#}");
                if !is_benign(&msg) {
                    eprintln!("  WARN: Bedrock get_model_invocation_logging: {msg}");
                }
            }
        }

        Ok(rows)
    }
}
