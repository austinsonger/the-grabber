use anyhow::{Context, Result};
use async_trait::async_trait;
use aws_sdk_ecr::Client as EcrClient;
use aws_sdk_ecr::types::{ImageIdentifier, ListImagesFilter, FindingSeverity, TagStatus};

use crate::evidence::CsvCollector;

pub struct EcrScanCollector {
    client: EcrClient,
}

impl EcrScanCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self { client: EcrClient::new(config) }
    }
}

#[async_trait]
impl CsvCollector for EcrScanCollector {
    fn name(&self) -> &str { "ECR Image Scan Findings" }
    fn filename_prefix(&self) -> &str { "ECR_ScanFindings" }
    fn headers(&self) -> &'static [&'static str] {
        &["Repository", "Image Tag", "Scan Status", "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"]
    }

    async fn collect_rows(&self, _account_id: &str, _region: &str) -> Result<Vec<Vec<String>>> {
        let mut rows = Vec::new();
        let mut next_token: Option<String> = None;

        loop {
            let mut req = self.client.describe_repositories();
            if let Some(ref t) = next_token {
                req = req.next_token(t);
            }
            let resp = req.send().await.context("ECR describe_repositories")?;

            for repo in resp.repositories() {
                let repo_name = repo.repository_name().unwrap_or("").to_string();

                // List tagged images, cap at 10
                let images_resp = match self.client
                    .list_images()
                    .repository_name(&repo_name)
                    .filter(
                        ListImagesFilter::builder()
                            .tag_status(TagStatus::Tagged)
                            .build()
                    )
                    .send()
                    .await
                {
                    Ok(r) => r,
                    Err(e) => {
                        eprintln!("  WARN: ECR list_images for {repo_name}: {e:#}");
                        continue;
                    }
                };

                for image_id in images_resp.image_ids().iter().take(10) {
                    let tag = image_id.image_tag().unwrap_or("").to_string();
                    let digest = image_id.image_digest().map(|s| s.to_string());

                    if tag.is_empty() { continue; }

                    let mut img_id_builder = ImageIdentifier::builder().image_tag(&tag);
                    if let Some(ref d) = digest {
                        img_id_builder = img_id_builder.image_digest(d);
                    }
                    let img_id = img_id_builder.build();

                    let scan_resp = match self.client
                        .describe_image_scan_findings()
                        .repository_name(&repo_name)
                        .image_id(img_id)
                        .send()
                        .await
                    {
                        Ok(r) => r,
                        Err(e) => {
                            let msg = format!("{e}");
                            if msg.contains("ScanNotFoundException") || msg.contains("ImageNotFoundException") {
                                rows.push(vec![
                                    repo_name.clone(),
                                    tag,
                                    "NOT_SCANNED".to_string(),
                                    String::new(), String::new(), String::new(), String::new(), String::new(),
                                ]);
                            } else {
                                eprintln!("  WARN: ECR describe_image_scan_findings {repo_name}:{tag}: {e:#}");
                            }
                            continue;
                        }
                    };

                    let scan_status = scan_resp.image_scan_status()
                        .and_then(|s| s.status())
                        .map(|s| s.as_str().to_string())
                        .unwrap_or_default();

                    let counts = scan_resp.image_scan_findings()
                        .and_then(|f| f.finding_severity_counts());

                    let get_count = |sev: &FindingSeverity| -> String {
                        counts.and_then(|c| c.get(sev))
                            .map(|n| n.to_string())
                            .unwrap_or_else(|| "0".to_string())
                    };

                    rows.push(vec![
                        repo_name.clone(),
                        tag,
                        scan_status,
                        get_count(&FindingSeverity::Critical),
                        get_count(&FindingSeverity::High),
                        get_count(&FindingSeverity::Medium),
                        get_count(&FindingSeverity::Low),
                        get_count(&FindingSeverity::Informational),
                    ]);
                }
            }

            next_token = resp.next_token().map(|s| s.to_string());
            if next_token.is_none() { break; }
        }

        Ok(rows)
    }
}
