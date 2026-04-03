use anyhow::Result;
use async_trait::async_trait;
use aws_sdk_ecr::Client as EcrClient;
use aws_sdk_ecr::types::FindingSeverity;

use crate::evidence::CsvCollector;

fn secs_to_rfc3339(secs: i64) -> String {
    chrono::DateTime::<chrono::Utc>::from_timestamp(secs, 0)
        .map(|c| c.to_rfc3339())
        .unwrap_or_default()
}

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
    fn name(&self) -> &str { "ECR Image Details" }
    fn filename_prefix(&self) -> &str { "ECR_ScanFindings" }
    fn headers(&self) -> &'static [&'static str] {
        &[
            // Image identity
            "Registry ID",
            "Repository Name",
            "Image Digest",
            "Image Tags",
            // Image metadata
            "Image Size (bytes)",
            "Image Pushed At",
            "Image Manifest Media Type",
            "Artifact Media Type",
            "Last Recorded Pull Time",
            // Scan status
            "Scan Status",
            "Scan Status Description",
            // Scan findings summary
            "Scan Completed At",
            "Vuln Source Updated At",
            "CRITICAL",
            "HIGH",
            "MEDIUM",
            "LOW",
            "INFORMATIONAL",
            "UNDEFINED",
        ]
    }

    async fn collect_rows(&self, _account_id: &str, _region: &str, _dates: Option<(i64, i64)>) -> Result<Vec<Vec<String>>> {
        let mut rows = Vec::new();

        // Paginate through all repositories
        let mut repo_token: Option<String> = None;
        loop {
            let mut req = self.client.describe_repositories();
            if let Some(ref t) = repo_token {
                req = req.next_token(t);
            }
            let resp = match req.send().await {
                Ok(r) => r,
                Err(e) => {
                    let msg = format!("{e:#}");
                    if msg.contains("AccessDeniedException") {
                        eprintln!("  WARN: ECR describe_repositories (access denied): {msg}");
                        return Ok(rows);
                    }
                    eprintln!("  WARN: ECR describe_repositories: {msg}");
                    break;
                }
            };

            for repo in resp.repositories() {
                let repo_name = repo.repository_name().unwrap_or("").to_string();

                // Use describe_images (not describe_image_scan_findings) so we get scan
                // summaries even when Inspector2 enhanced scanning is enabled on the account.
                // describe_image_scan_findings returns nothing / errors under enhanced scanning.
                let mut img_token: Option<String> = None;
                loop {
                    let mut img_req = self.client
                        .describe_images()
                        .repository_name(&repo_name);
                    if let Some(ref t) = img_token {
                        img_req = img_req.next_token(t);
                    }
                    let img_resp = match img_req.send().await {
                        Ok(r) => r,
                        Err(e) => {
                            eprintln!("  WARN: ECR describe_images for {repo_name}: {e:#}");
                            break;
                        }
                    };

                    for img in img_resp.image_details() {
                        // ── Image identity ──────────────────────────────────────
                        let registry_id  = img.registry_id().unwrap_or("").to_string();
                        let image_digest = img.image_digest().unwrap_or("").to_string();
                        let image_tags   = img.image_tags().join("; ");

                        // ── Image metadata ──────────────────────────────────────
                        let image_size   = img.image_size_in_bytes()
                            .map(|n| n.to_string())
                            .unwrap_or_default();
                        let pushed_at    = img.image_pushed_at()
                            .map(|d| secs_to_rfc3339(d.secs()))
                            .unwrap_or_default();
                        let manifest_type = img.image_manifest_media_type().unwrap_or("").to_string();
                        let artifact_type = img.artifact_media_type().unwrap_or("").to_string();
                        let last_pull    = img.last_recorded_pull_time()
                            .map(|d| secs_to_rfc3339(d.secs()))
                            .unwrap_or_default();

                        // ── Scan status ─────────────────────────────────────────
                        let (scan_status, scan_desc) = img.image_scan_status()
                            .map(|s| (
                                s.status().map(|x| x.as_str().to_string()).unwrap_or_default(),
                                s.description().unwrap_or("").to_string(),
                            ))
                            .unwrap_or_default();

                        // ── Scan findings summary ───────────────────────────────
                        let (
                            scan_completed_at, vuln_updated_at,
                            cnt_critical, cnt_high, cnt_medium,
                            cnt_low, cnt_info, cnt_undefined,
                        ) = img.image_scan_findings_summary()
                            .map(|s| {
                                let completed = s.image_scan_completed_at()
                                    .map(|d| secs_to_rfc3339(d.secs()))
                                    .unwrap_or_default();
                                let vuln_upd = s.vulnerability_source_updated_at()
                                    .map(|d| secs_to_rfc3339(d.secs()))
                                    .unwrap_or_default();
                                let counts = s.finding_severity_counts();
                                let get = |sev: &FindingSeverity| -> String {
                                    counts.and_then(|c| c.get(sev))
                                        .map(|n| n.to_string())
                                        .unwrap_or_else(|| "0".to_string())
                                };
                                (
                                    completed, vuln_upd,
                                    get(&FindingSeverity::Critical),
                                    get(&FindingSeverity::High),
                                    get(&FindingSeverity::Medium),
                                    get(&FindingSeverity::Low),
                                    get(&FindingSeverity::Informational),
                                    get(&FindingSeverity::Undefined),
                                )
                            })
                            .unwrap_or_else(|| (
                                String::new(), String::new(),
                                "0".to_string(), "0".to_string(), "0".to_string(),
                                "0".to_string(), "0".to_string(), "0".to_string(),
                            ));

                        rows.push(vec![
                            registry_id, repo_name.clone(), image_digest, image_tags,
                            image_size, pushed_at, manifest_type, artifact_type, last_pull,
                            scan_status, scan_desc,
                            scan_completed_at, vuln_updated_at,
                            cnt_critical, cnt_high, cnt_medium, cnt_low, cnt_info, cnt_undefined,
                        ]);
                    }

                    img_token = img_resp.next_token().map(|s| s.to_string());
                    if img_token.is_none() { break; }
                }
            }

            repo_token = resp.next_token().map(|s| s.to_string());
            if repo_token.is_none() { break; }
        }

        Ok(rows)
    }
}
