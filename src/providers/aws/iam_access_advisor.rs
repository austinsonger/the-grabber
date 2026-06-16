use anyhow::{Context, Result};
use async_trait::async_trait;
use aws_sdk_iam::types::JobStatusType;
use aws_sdk_iam::Client as IamClient;
use std::time::Duration;

use crate::evidence::CsvCollector;

const MAX_PRINCIPALS: usize = 200;
const POLL_INTERVAL_SECS: u64 = 5;
const POLL_MAX_ITER: usize = 12; // 12 * 5s = 60s
const THROTTLE_MAX_RETRIES: usize = 3;
const THROTTLE_BACKOFF_SECS: u64 = 2;

pub struct IamAccessAdvisorCollector {
    client: IamClient,
}

impl IamAccessAdvisorCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self {
            client: IamClient::new(config),
        }
    }
}

fn fmt_dt(dt: &aws_sdk_iam::primitives::DateTime) -> String {
    chrono::DateTime::<chrono::Utc>::from_timestamp(dt.secs(), dt.subsec_nanos())
        .map(|c| c.to_rfc3339())
        .unwrap_or_default()
}

fn is_throttling_err<E: std::fmt::Debug>(err: &E) -> bool {
    let s = format!("{:?}", err);
    s.contains("Throttling") || s.contains("ThrottlingException") || s.contains("TooManyRequests")
}

#[async_trait]
impl CsvCollector for IamAccessAdvisorCollector {
    fn name(&self) -> &str {
        "IAM Access Advisor"
    }
    fn filename_prefix(&self) -> &str {
        "IAM_Access_Advisor"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Principal ARN",
            "Principal Type",
            "Service Name",
            "Service Namespace",
            "Last Authenticated",
            "Last Authenticated Entity",
            "Last Authenticated Region",
            "Total Authenticated Entities",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        // 1. Gather all principal ARNs (users + roles).
        let mut principals: Vec<(String, &'static str)> = Vec::new();

        let mut marker: Option<String> = None;
        loop {
            let mut req = self.client.list_users();
            if let Some(ref m) = marker {
                req = req.marker(m);
            }
            let resp = req
                .send()
                .await
                .context("IAM list_users (access advisor)")?;
            for u in resp.users() {
                principals.push((u.arn().to_string(), "User"));
            }
            if resp.is_truncated() {
                marker = resp.marker().map(|s| s.to_string());
                if marker.is_none() {
                    break;
                }
            } else {
                break;
            }
        }

        let mut marker: Option<String> = None;
        loop {
            let mut req = self.client.list_roles();
            if let Some(ref m) = marker {
                req = req.marker(m);
            }
            let resp = req
                .send()
                .await
                .context("IAM list_roles (access advisor)")?;
            for r in resp.roles() {
                principals.push((r.arn().to_string(), "Role"));
            }
            if resp.is_truncated() {
                marker = resp.marker().map(|s| s.to_string());
                if marker.is_none() {
                    break;
                }
            } else {
                break;
            }
        }

        let total_principals = principals.len();
        let truncated = total_principals > MAX_PRINCIPALS;
        if truncated {
            principals.truncate(MAX_PRINCIPALS);
        }

        let mut rows: Vec<Vec<String>> = Vec::new();

        if truncated {
            rows.push(vec![
                format!(
                    "# capped at first {} principals out of {}",
                    MAX_PRINCIPALS, total_principals
                ),
                String::new(),
                String::new(),
                String::new(),
                String::new(),
                String::new(),
                String::new(),
                String::new(),
            ]);
        }

        // 2. For each principal: generate -> poll -> collect.
        for (arn, ptype) in &principals {
            // Generate job (with throttling retry).
            let mut job_id_opt: Option<String> = None;
            let mut attempt = 0;
            let mut skip = false;
            loop {
                match self
                    .client
                    .generate_service_last_accessed_details()
                    .arn(arn)
                    .send()
                    .await
                {
                    Ok(out) => {
                        job_id_opt = out.job_id().map(|s| s.to_string());
                        break;
                    }
                    Err(e) => {
                        if is_throttling_err(&e) && attempt < THROTTLE_MAX_RETRIES {
                            attempt += 1;
                            tokio::time::sleep(Duration::from_secs(THROTTLE_BACKOFF_SECS)).await;
                            continue;
                        }
                        rows.push(vec![
                            arn.clone(),
                            (*ptype).to_string(),
                            format!("# generate failed: {}", e),
                            String::new(),
                            String::new(),
                            String::new(),
                            String::new(),
                            String::new(),
                        ]);
                        skip = true;
                        break;
                    }
                }
            }
            if skip {
                continue;
            }
            let job_id = match job_id_opt {
                Some(j) => j,
                None => {
                    rows.push(vec![
                        arn.clone(),
                        (*ptype).to_string(),
                        "# generate returned no job_id".to_string(),
                        String::new(),
                        String::new(),
                        String::new(),
                        String::new(),
                        String::new(),
                    ]);
                    continue;
                }
            };

            // Poll until COMPLETED or timeout.
            let mut completed = false;
            let mut last_resp = None;
            for i in 0..POLL_MAX_ITER {
                tokio::time::sleep(Duration::from_secs(POLL_INTERVAL_SECS)).await;
                let mut throttle_attempt = 0;
                let resp_res = loop {
                    match self
                        .client
                        .get_service_last_accessed_details()
                        .job_id(&job_id)
                        .send()
                        .await
                    {
                        Ok(r) => break Ok(r),
                        Err(e) => {
                            if is_throttling_err(&e) && throttle_attempt < THROTTLE_MAX_RETRIES {
                                throttle_attempt += 1;
                                tokio::time::sleep(Duration::from_secs(THROTTLE_BACKOFF_SECS))
                                    .await;
                                continue;
                            }
                            break Err(e);
                        }
                    }
                };
                let resp = match resp_res {
                    Ok(r) => r,
                    Err(e) => {
                        rows.push(vec![
                            arn.clone(),
                            (*ptype).to_string(),
                            format!("# get failed: {}", e),
                            String::new(),
                            String::new(),
                            String::new(),
                            String::new(),
                            String::new(),
                        ]);
                        break;
                    }
                };
                if matches!(resp.job_status(), JobStatusType::Completed) {
                    last_resp = Some(resp);
                    completed = true;
                    break;
                }
                if i == POLL_MAX_ITER - 1 {
                    rows.push(vec![
                        arn.clone(),
                        (*ptype).to_string(),
                        "# polling timeout (60s)".to_string(),
                        String::new(),
                        String::new(),
                        String::new(),
                        String::new(),
                        String::new(),
                    ]);
                }
            }

            if !completed {
                continue;
            }

            let resp = match last_resp {
                Some(r) => r,
                None => continue,
            };

            for svc in resp.services_last_accessed() {
                let last_auth = svc.last_authenticated().map(fmt_dt).unwrap_or_default();
                let last_entity = svc.last_authenticated_entity().unwrap_or("").to_string();
                let last_region = svc.last_authenticated_region().unwrap_or("").to_string();
                let total = svc
                    .total_authenticated_entities()
                    .map(|n| n.to_string())
                    .unwrap_or_default();
                rows.push(vec![
                    arn.clone(),
                    (*ptype).to_string(),
                    svc.service_name().to_string(),
                    svc.service_namespace().to_string(),
                    last_auth,
                    last_entity,
                    last_region,
                    total,
                ]);
            }
        }

        Ok(rows)
    }
}
