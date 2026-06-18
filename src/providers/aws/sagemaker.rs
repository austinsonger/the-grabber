use anyhow::Result;
use async_trait::async_trait;
use aws_sdk_sagemaker::Client as SageMakerClient;

use crate::evidence::CsvCollector;

// ══════════════════════════════════════════════════════════════════════════════
// SageMaker Posture Collector — notebook IMDS/KMS/VPC, endpoint KMS, model VPC.
// ══════════════════════════════════════════════════════════════════════════════

pub struct SageMakerPostureCollector {
    client: SageMakerClient,
}

impl SageMakerPostureCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self {
            client: SageMakerClient::new(config),
        }
    }
}

fn is_benign(err: &str) -> bool {
    err.contains("AccessDenied")
        || err.contains("AccessDeniedException")
        || err.contains("ValidationException")
        || err.contains("UnauthorizedOperation")
        || err.contains("not available")
        || err.contains("UnknownEndpoint")
        || err.contains("dispatch failure")
        || err.contains("InvalidAction")
        || err.contains("OptInRequired")
}

#[async_trait]
impl CsvCollector for SageMakerPostureCollector {
    fn name(&self) -> &str {
        "SageMaker Posture"
    }
    fn filename_prefix(&self) -> &str {
        "SageMaker_Posture"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Type",
            "Resource Name",
            "IMDS / KMS / VPC",
            "Root Access / Direct Internet",
            "Detail",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let mut rows: Vec<Vec<String>> = Vec::new();

        // Notebook Instances.
        let mut paginator = self
            .client
            .list_notebook_instances()
            .into_paginator()
            .send();
        while let Some(page) = paginator.next().await {
            let resp = match page {
                Ok(r) => r,
                Err(e) => {
                    let msg = format!("{e:#}");
                    if is_benign(&msg) {
                        return Ok(rows);
                    }
                    eprintln!("  WARN: SageMaker list_notebook_instances: {msg}");
                    break;
                }
            };
            for nb in resp.notebook_instances() {
                let Some(name) = nb.notebook_instance_name() else {
                    continue;
                };
                let desc = match self
                    .client
                    .describe_notebook_instance()
                    .notebook_instance_name(name)
                    .send()
                    .await
                {
                    Ok(d) => d,
                    Err(e) => {
                        let msg = format!("{e:#}");
                        if is_benign(&msg) {
                            return Ok(rows);
                        }
                        eprintln!("  WARN: SageMaker describe_notebook_instance: {msg}");
                        continue;
                    }
                };
                let imds = desc
                    .instance_metadata_service_configuration()
                    .and_then(|c| c.minimum_instance_metadata_service_version())
                    .unwrap_or("")
                    .to_string();
                let kms = desc.kms_key_id().unwrap_or("").to_string();
                let subnet = desc.subnet_id().unwrap_or("").to_string();
                let root = desc
                    .root_access()
                    .map(|r| r.as_str().to_string())
                    .unwrap_or_default();
                let dia = desc
                    .direct_internet_access()
                    .map(|r| r.as_str().to_string())
                    .unwrap_or_default();
                let combo = format!("imds={imds} / kms={kms} / subnet={subnet}");
                let access = format!("root={root} / direct_internet={dia}");
                rows.push(vec![
                    "Notebook".to_string(),
                    name.to_string(),
                    combo,
                    access,
                    String::new(),
                ]);
            }
        }

        // Endpoints.
        let mut paginator = self.client.list_endpoints().into_paginator().send();
        while let Some(page) = paginator.next().await {
            let resp = match page {
                Ok(r) => r,
                Err(e) => {
                    let msg = format!("{e:#}");
                    if is_benign(&msg) {
                        return Ok(rows);
                    }
                    eprintln!("  WARN: SageMaker list_endpoints: {msg}");
                    break;
                }
            };
            for ep in resp.endpoints() {
                let Some(ep_name) = ep.endpoint_name() else {
                    continue;
                };
                // describe_endpoint to get endpoint_config_name
                let desc_ep = match self
                    .client
                    .describe_endpoint()
                    .endpoint_name(ep_name)
                    .send()
                    .await
                {
                    Ok(d) => d,
                    Err(e) => {
                        let msg = format!("{e:#}");
                        if is_benign(&msg) {
                            return Ok(rows);
                        }
                        eprintln!("  WARN: SageMaker describe_endpoint: {msg}");
                        continue;
                    }
                };
                let cfg_name = desc_ep.endpoint_config_name().unwrap_or("").to_string();
                let kms = if !cfg_name.is_empty() {
                    match self
                        .client
                        .describe_endpoint_config()
                        .endpoint_config_name(&cfg_name)
                        .send()
                        .await
                    {
                        Ok(cfg) => cfg.kms_key_id().unwrap_or("").to_string(),
                        Err(e) => {
                            let msg = format!("{e:#}");
                            if is_benign(&msg) {
                                return Ok(rows);
                            }
                            eprintln!("  WARN: SageMaker describe_endpoint_config: {msg}");
                            String::new()
                        }
                    }
                } else {
                    String::new()
                };
                rows.push(vec![
                    "Endpoint".to_string(),
                    ep_name.to_string(),
                    format!("kms={kms}"),
                    String::new(),
                    format!("config={cfg_name}"),
                ]);
            }
        }

        // Models.
        let mut paginator = self.client.list_models().into_paginator().send();
        while let Some(page) = paginator.next().await {
            let resp = match page {
                Ok(r) => r,
                Err(e) => {
                    let msg = format!("{e:#}");
                    if is_benign(&msg) {
                        return Ok(rows);
                    }
                    eprintln!("  WARN: SageMaker list_models: {msg}");
                    break;
                }
            };
            for m in resp.models() {
                let Some(mname) = m.model_name() else {
                    continue;
                };
                let desc = match self.client.describe_model().model_name(mname).send().await {
                    Ok(d) => d,
                    Err(e) => {
                        let msg = format!("{e:#}");
                        if is_benign(&msg) {
                            return Ok(rows);
                        }
                        eprintln!("  WARN: SageMaker describe_model: {msg}");
                        continue;
                    }
                };
                let vpc = if desc.vpc_config().is_some() {
                    "present"
                } else {
                    "absent"
                };
                rows.push(vec![
                    "Model".to_string(),
                    mname.to_string(),
                    format!("vpc={vpc}"),
                    String::new(),
                    String::new(),
                ]);
            }
        }

        Ok(rows)
    }
}
