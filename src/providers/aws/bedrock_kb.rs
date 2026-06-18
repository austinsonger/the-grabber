use anyhow::Result;
use async_trait::async_trait;
use aws_sdk_bedrockagent::Client as BedrockAgentClient;

use crate::evidence::CsvCollector;

// ══════════════════════════════════════════════════════════════════════════════
// Bedrock Knowledge Bases — KB inventory with embedding model + storage type.
// ══════════════════════════════════════════════════════════════════════════════

pub struct BedrockKbCollector {
    client: BedrockAgentClient,
}

impl BedrockKbCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self {
            client: BedrockAgentClient::new(config),
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
impl CsvCollector for BedrockKbCollector {
    fn name(&self) -> &str {
        "Bedrock Knowledge Bases"
    }
    fn filename_prefix(&self) -> &str {
        "Bedrock_KnowledgeBases"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "KB ID",
            "Name",
            "Status",
            "Embedding Model",
            "Storage Type",
            "Role ARN",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let mut rows: Vec<Vec<String>> = Vec::new();

        let mut paginator = self.client.list_knowledge_bases().into_paginator().send();
        while let Some(page) = paginator.next().await {
            let resp = match page {
                Ok(r) => r,
                Err(e) => {
                    let msg = format!("{e:#}");
                    if is_benign(&msg) {
                        return Ok(rows);
                    }
                    eprintln!("  WARN: Bedrock list_knowledge_bases: {msg}");
                    break;
                }
            };
            for kb in resp.knowledge_base_summaries() {
                let id = kb.knowledge_base_id().to_string();
                let name = kb.name().to_string();
                let status = kb.status().as_str().to_string();

                let detail = match self
                    .client
                    .get_knowledge_base()
                    .knowledge_base_id(&id)
                    .send()
                    .await
                {
                    Ok(d) => d,
                    Err(e) => {
                        let msg = format!("{e:#}");
                        if is_benign(&msg) {
                            continue;
                        }
                        eprintln!("  WARN: Bedrock get_knowledge_base({id}): {msg}");
                        rows.push(vec![
                            id,
                            name,
                            status,
                            String::new(),
                            String::new(),
                            String::new(),
                        ]);
                        continue;
                    }
                };

                let (role_arn, embedding_model, storage_type) = match detail.knowledge_base() {
                    Some(kbd) => {
                        let role = kbd.role_arn().to_string();
                        let emb = kbd
                            .knowledge_base_configuration()
                            .and_then(|c| c.vector_knowledge_base_configuration())
                            .map(|v| v.embedding_model_arn().to_string())
                            .unwrap_or_default();
                        let stor = kbd
                            .storage_configuration()
                            .map(|s| s.r#type().as_str().to_string())
                            .unwrap_or_default();
                        (role, emb, stor)
                    }
                    None => (String::new(), String::new(), String::new()),
                };

                rows.push(vec![
                    id,
                    name,
                    status,
                    embedding_model,
                    storage_type,
                    role_arn,
                ]);
            }
        }

        Ok(rows)
    }
}
