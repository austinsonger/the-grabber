use anyhow::Result;
use async_trait::async_trait;
use aws_sdk_ecr::Client as EcrClient;

use crate::evidence::CsvCollector;

pub struct EcrSignaturesCollector {
    client: EcrClient,
}

impl EcrSignaturesCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self {
            client: EcrClient::new(config),
        }
    }
}

const COSIGN_MEDIA: &str = "application/vnd.dev.cosign.simplesigning.v1+json";
const NOTARY_MEDIA: &str = "application/vnd.cncf.notary.signature.v2+jws";

fn signature_info(tags: &[String], media_type: &str) -> (bool, String) {
    if media_type == COSIGN_MEDIA {
        return (true, "Cosign".to_string());
    }
    if media_type == NOTARY_MEDIA {
        return (true, "Notary".to_string());
    }
    for t in tags {
        if t.ends_with(".sig") {
            return (true, "Cosign".to_string());
        }
    }
    (false, String::new())
}

#[async_trait]
impl CsvCollector for EcrSignaturesCollector {
    fn name(&self) -> &str {
        "ECR Image Signatures & Scanning"
    }
    fn filename_prefix(&self) -> &str {
        "ECR_Signatures_ScanConfig"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Repository",
            "Registry Scan Type",
            "Enhanced Filters",
            "Image Digest",
            "Image Tags",
            "Signature Present",
            "Signature Type",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let mut rows = Vec::new();

        // Registry scanning configuration.
        let (scan_type, enhanced_filters) = match self
            .client
            .get_registry_scanning_configuration()
            .send()
            .await
        {
            Ok(r) => {
                let cfg = r.scanning_configuration();
                let st = cfg
                    .and_then(|c| c.scan_type())
                    .map(|s| s.as_str().to_string())
                    .unwrap_or_else(|| "BASIC".to_string());
                let filters: Vec<String> = cfg
                    .map(|c| c.rules())
                    .unwrap_or(&[])
                    .iter()
                    .flat_map(|r| r.repository_filters())
                    .map(|f| f.filter().to_string())
                    .collect();
                (st, filters.join(";"))
            }
            Err(e) => {
                let msg = format!("{e}");
                if msg.contains("AccessDenied") || msg.contains("not supported") {
                    ("BASIC".to_string(), String::new())
                } else {
                    eprintln!("  WARN: ECR get_registry_scanning_configuration: {e:#}");
                    ("UNKNOWN".to_string(), String::new())
                }
            }
        };

        // Repositories.
        let mut next_token: Option<String> = None;
        loop {
            let mut req = self.client.describe_repositories();
            if let Some(t) = next_token.as_ref() {
                req = req.next_token(t);
            }
            let resp = match req.send().await {
                Ok(r) => r,
                Err(e) => {
                    let msg = format!("{e}");
                    if msg.contains("RepositoryNotFoundException")
                        || msg.contains("AccessDenied")
                        || msg.contains("not supported")
                    {
                        return Ok(rows);
                    }
                    eprintln!("  WARN: ECR describe_repositories: {e:#}");
                    return Ok(rows);
                }
            };

            for repo in resp.repositories() {
                let repo_name = repo.repository_name().unwrap_or("").to_string();

                let mut img_token: Option<String> = None;
                loop {
                    let mut ireq = self.client.describe_images().repository_name(&repo_name);
                    if let Some(t) = img_token.as_ref() {
                        ireq = ireq.next_token(t);
                    }
                    let iresp = match ireq.send().await {
                        Ok(r) => r,
                        Err(e) => {
                            let msg = format!("{e}");
                            if !msg.contains("ImageNotFoundException") {
                                eprintln!("  WARN: ECR describe_images({repo_name}): {e:#}");
                            }
                            break;
                        }
                    };
                    for img in iresp.image_details() {
                        let digest = img.image_digest().unwrap_or("").to_string();
                        let tags: Vec<String> =
                            img.image_tags().iter().map(|s| s.to_string()).collect();
                        let media = img.image_manifest_media_type().unwrap_or("");
                        let (present, sig_type) = signature_info(&tags, media);
                        rows.push(vec![
                            repo_name.clone(),
                            scan_type.clone(),
                            enhanced_filters.clone(),
                            digest,
                            tags.join(";"),
                            if present { "Yes" } else { "No" }.to_string(),
                            sig_type,
                        ]);
                    }
                    img_token = iresp.next_token().map(|s| s.to_string());
                    if img_token.is_none() {
                        break;
                    }
                }
            }

            next_token = resp.next_token().map(|s| s.to_string());
            if next_token.is_none() {
                break;
            }
        }

        Ok(rows)
    }
}
