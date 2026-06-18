use anyhow::Result;
use async_trait::async_trait;
use aws_sdk_iot::Client as IotClient;

use crate::evidence::CsvCollector;

// ══════════════════════════════════════════════════════════════════════════════
// IoT Things & Policies — thing groups, IoT policies (with document excerpts),
// and device certificates.
// ══════════════════════════════════════════════════════════════════════════════

pub struct IotThingsCollector {
    client: IotClient,
}

impl IotThingsCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self {
            client: IotClient::new(config),
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
        || err.contains("not enabled")
        || err.contains("NotFoundException")
}

fn secs_to_rfc3339(secs: i64) -> String {
    chrono::DateTime::<chrono::Utc>::from_timestamp(secs, 0)
        .map(|c| c.to_rfc3339())
        .unwrap_or_default()
}

fn truncate(s: &str, n: usize) -> String {
    if s.len() <= n {
        s.to_string()
    } else {
        let mut end = n;
        while !s.is_char_boundary(end) && end > 0 {
            end -= 1;
        }
        format!("{}…", &s[..end])
    }
}

#[async_trait]
impl CsvCollector for IotThingsCollector {
    fn name(&self) -> &str {
        "IoT Things & Policies"
    }
    fn filename_prefix(&self) -> &str {
        "IoT_Things_Policies"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Type",
            "Name / ID",
            "ARN",
            "Status / Created",
            "Policy Excerpt",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let mut rows: Vec<Vec<String>> = Vec::new();

        // Thing groups.
        let mut groups = self.client.list_thing_groups().into_paginator().send();
        while let Some(page) = groups.next().await {
            let resp = match page {
                Ok(r) => r,
                Err(e) => {
                    let msg = format!("{e:#}");
                    if is_benign(&msg) {
                        return Ok(rows);
                    }
                    eprintln!("  WARN: IoT list_thing_groups: {msg}");
                    break;
                }
            };
            for g in resp.thing_groups() {
                let name = g.group_name().unwrap_or("").to_string();
                let arn = g.group_arn().unwrap_or("").to_string();
                if name.is_empty() && arn.is_empty() {
                    continue;
                }
                rows.push(vec![
                    "Group".to_string(),
                    name,
                    arn,
                    String::new(),
                    String::new(),
                ]);
            }
        }

        // IoT policies.
        let mut pols = self.client.list_policies().into_paginator().send();
        while let Some(page) = pols.next().await {
            let resp = match page {
                Ok(r) => r,
                Err(e) => {
                    let msg = format!("{e:#}");
                    if is_benign(&msg) {
                        break;
                    }
                    eprintln!("  WARN: IoT list_policies: {msg}");
                    break;
                }
            };
            for p in resp.policies() {
                let name = p.policy_name().unwrap_or("").to_string();
                let arn = p.policy_arn().unwrap_or("").to_string();
                if name.is_empty() {
                    continue;
                }
                let doc = match self.client.get_policy().policy_name(&name).send().await {
                    Ok(d) => d
                        .policy_document()
                        .map(|s| truncate(s, 1000))
                        .unwrap_or_default(),
                    Err(e) => {
                        let msg = format!("{e:#}");
                        if !is_benign(&msg) {
                            eprintln!("  WARN: IoT get_policy({name}): {msg}");
                        }
                        String::new()
                    }
                };
                rows.push(vec!["Policy".to_string(), name, arn, String::new(), doc]);
            }
        }

        // Certificates.
        let mut certs = self.client.list_certificates().into_paginator().send();
        while let Some(page) = certs.next().await {
            let resp = match page {
                Ok(r) => r,
                Err(e) => {
                    let msg = format!("{e:#}");
                    if is_benign(&msg) {
                        break;
                    }
                    eprintln!("  WARN: IoT list_certificates: {msg}");
                    break;
                }
            };
            for c in resp.certificates() {
                let id = c.certificate_id().unwrap_or("").to_string();
                let arn = c.certificate_arn().unwrap_or("").to_string();
                let status = c
                    .status()
                    .map(|s| s.as_str().to_string())
                    .unwrap_or_default();
                let created = c
                    .creation_date()
                    .map(|d| secs_to_rfc3339(d.secs()))
                    .unwrap_or_default();
                if id.is_empty() {
                    continue;
                }
                let status_created = format!("{status} / {created}");
                rows.push(vec![
                    "Certificate".to_string(),
                    id,
                    arn,
                    status_created,
                    String::new(),
                ]);
            }
        }

        Ok(rows)
    }
}
