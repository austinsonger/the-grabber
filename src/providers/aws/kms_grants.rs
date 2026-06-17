use anyhow::{Context, Result};
use async_trait::async_trait;
use aws_sdk_kms::types::KeyManagerType;
use aws_sdk_kms::Client as KmsClient;

use crate::evidence::CsvCollector;

pub struct KmsGrantsCollector {
    client: KmsClient,
}

impl KmsGrantsCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self {
            client: KmsClient::new(config),
        }
    }
}

fn dt_to_rfc3339(d: Option<&aws_sdk_kms::primitives::DateTime>) -> String {
    d.and_then(|d| {
        chrono::DateTime::<chrono::Utc>::from_timestamp(d.secs(), d.subsec_nanos())
            .map(|c| c.to_rfc3339())
    })
    .unwrap_or_default()
}

#[async_trait]
impl CsvCollector for KmsGrantsCollector {
    fn name(&self) -> &str {
        "KMS Grants & Rotation"
    }
    fn filename_prefix(&self) -> &str {
        "KMS_Grants_Rotation"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Key ID",
            "Key ARN",
            "Creation Date",
            "Rotation Enabled",
            "Grant ID",
            "Grantee Principal",
            "Operations",
            "Grant Created",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let mut rows = Vec::new();
        let mut next_marker: Option<String> = None;

        loop {
            let mut req = self.client.list_keys();
            if let Some(ref m) = next_marker {
                req = req.marker(m);
            }
            let resp = req.send().await.context("KMS list_keys")?;

            for key_entry in resp.keys() {
                let key_id = key_entry.key_id().unwrap_or("").to_string();
                let key_arn = key_entry.key_arn().unwrap_or("").to_string();

                // Describe key for metadata; skip AWS-managed.
                let metadata = match self.client.describe_key().key_id(&key_id).send().await {
                    Ok(r) => r.key_metadata().cloned(),
                    Err(e) => {
                        eprintln!("  WARN: KMS describe_key({key_id}): {e:#}");
                        continue;
                    }
                };
                let Some(meta) = metadata else { continue };
                if meta.key_manager() == Some(&KeyManagerType::Aws) {
                    continue;
                }

                let creation_date = dt_to_rfc3339(meta.creation_date());

                let rotation_enabled = match self
                    .client
                    .get_key_rotation_status()
                    .key_id(&key_id)
                    .send()
                    .await
                {
                    Ok(r) => if r.key_rotation_enabled() {
                        "Yes"
                    } else {
                        "No"
                    }
                    .to_string(),
                    Err(_) => String::new(),
                };

                // Collect grants (paginated).
                let mut grants: Vec<(String, String, String, String)> = Vec::new();
                let mut grant_marker: Option<String> = None;
                loop {
                    let mut g_req = self.client.list_grants().key_id(&key_id);
                    if let Some(ref m) = grant_marker {
                        g_req = g_req.marker(m);
                    }
                    let g_resp = match g_req.send().await {
                        Ok(r) => r,
                        Err(e) => {
                            eprintln!("  WARN: KMS list_grants({key_id}): {e:#}");
                            break;
                        }
                    };
                    for g in g_resp.grants() {
                        let grant_id = g.grant_id().unwrap_or("").to_string();
                        let grantee = g.grantee_principal().unwrap_or("").to_string();
                        let ops = g
                            .operations()
                            .iter()
                            .map(|o| o.as_str().to_string())
                            .collect::<Vec<_>>()
                            .join(", ");
                        let g_created = dt_to_rfc3339(g.creation_date());
                        grants.push((grant_id, grantee, ops, g_created));
                    }
                    grant_marker = if g_resp.truncated() {
                        g_resp.next_marker().map(|s| s.to_string())
                    } else {
                        None
                    };
                    if grant_marker.is_none() {
                        break;
                    }
                }

                if grants.is_empty() {
                    rows.push(vec![
                        key_id.clone(),
                        key_arn.clone(),
                        creation_date.clone(),
                        rotation_enabled.clone(),
                        String::new(),
                        String::new(),
                        String::new(),
                        String::new(),
                    ]);
                } else {
                    for (grant_id, grantee, ops, g_created) in grants {
                        rows.push(vec![
                            key_id.clone(),
                            key_arn.clone(),
                            creation_date.clone(),
                            rotation_enabled.clone(),
                            grant_id,
                            grantee,
                            ops,
                            g_created,
                        ]);
                    }
                }
            }

            next_marker = if resp.truncated() {
                resp.next_marker().map(|s| s.to_string())
            } else {
                None
            };
            if next_marker.is_none() {
                break;
            }
        }

        Ok(rows)
    }
}
