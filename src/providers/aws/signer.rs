use anyhow::Result;
use async_trait::async_trait;
use aws_sdk_signer::Client as SignerClient;

use crate::evidence::CsvCollector;

pub struct SignerCollector {
    client: SignerClient,
}

impl SignerCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self {
            client: SignerClient::new(config),
        }
    }
}

fn unsupported(msg: &str) -> bool {
    msg.contains("ResourceNotFoundException")
        || msg.contains("UnrecognizedClientException")
        || msg.contains("InvalidAction")
        || msg.contains("not supported")
        || msg.contains("AccessDenied")
        || msg.contains("OperationNotPermitted")
}

#[async_trait]
impl CsvCollector for SignerCollector {
    fn name(&self) -> &str {
        "AWS Signer Profiles & Jobs"
    }
    fn filename_prefix(&self) -> &str {
        "Signer_Profiles_Jobs"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Type",
            "Profile Name",
            "Profile Version",
            "Platform ID",
            "Status",
            "Job ID",
            "Source S3",
            "Signed At",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let mut rows = Vec::new();

        // Signing profiles.
        let mut next_token: Option<String> = None;
        loop {
            let mut req = self.client.list_signing_profiles();
            if let Some(t) = next_token.as_ref() {
                req = req.next_token(t);
            }
            let resp = match req.send().await {
                Ok(r) => r,
                Err(e) => {
                    let msg = format!("{e}");
                    if unsupported(&msg) {
                        break;
                    }
                    eprintln!("  WARN: Signer list_signing_profiles: {e:#}");
                    break;
                }
            };
            for p in resp.profiles() {
                let name = p.profile_name().unwrap_or("").to_string();
                let version = p.profile_version().unwrap_or("").to_string();
                let platform = p.platform_id().unwrap_or("").to_string();
                let status = p
                    .status()
                    .map(|s| s.as_str().to_string())
                    .unwrap_or_default();
                rows.push(vec![
                    "Profile".to_string(),
                    name,
                    version,
                    platform,
                    status,
                    String::new(),
                    String::new(),
                    String::new(),
                ]);
            }
            next_token = resp.next_token().map(|s| s.to_string());
            if next_token.is_none() {
                break;
            }
        }

        // Signing jobs.
        let mut next_token: Option<String> = None;
        loop {
            let mut req = self.client.list_signing_jobs();
            if let Some(t) = next_token.as_ref() {
                req = req.next_token(t);
            }
            let resp = match req.send().await {
                Ok(r) => r,
                Err(e) => {
                    let msg = format!("{e}");
                    if unsupported(&msg) {
                        break;
                    }
                    eprintln!("  WARN: Signer list_signing_jobs: {e:#}");
                    break;
                }
            };
            for j in resp.jobs() {
                let job_id = j.job_id().unwrap_or("").to_string();
                let profile_name = j.profile_name().unwrap_or("").to_string();
                let profile_version = j.profile_version().unwrap_or("").to_string();
                let platform = j.platform_id().unwrap_or("").to_string();
                let status = j
                    .status()
                    .map(|s| s.as_str().to_string())
                    .unwrap_or_default();
                let source_s3 = j
                    .source()
                    .and_then(|s| s.s3())
                    .map(|s| s.bucket_name().to_string())
                    .unwrap_or_default();
                let signed_at = j.created_at().map(|d| d.to_string()).unwrap_or_default();
                rows.push(vec![
                    "Job".to_string(),
                    profile_name,
                    profile_version,
                    platform,
                    status,
                    job_id,
                    source_s3,
                    signed_at,
                ]);
            }
            next_token = resp.next_token().map(|s| s.to_string());
            if next_token.is_none() {
                break;
            }
        }

        Ok(rows)
    }
}
