use anyhow::Result;
use async_trait::async_trait;
use aws_sdk_config::types::ResourceType;
use aws_sdk_config::Client as ConfigClient;

use crate::evidence::CsvCollector;

fn fmt_config_dt(dt: &aws_sdk_config::primitives::DateTime) -> (String, i64) {
    let secs = dt.secs();
    let s = chrono::DateTime::<chrono::Utc>::from_timestamp(secs, 0)
        .map(|c| c.to_rfc3339())
        .unwrap_or_default();
    (s, secs)
}

fn is_benign(err: &str) -> bool {
    err.contains("AccessDenied")
        || err.contains("ResourceNotFoundException")
        || err.contains("ValidationException")
        || err.contains("not enabled")
        || err.contains("not subscribed")
        || err.contains("UnknownService")
        || err.contains("dispatch failure")
        || err.contains("could not be found")
        || err.contains("NoSuchConfigurationRecorder")
        || err.contains("NoAvailableConfigurationRecorder")
}

pub struct ResourceDriftCollector {
    client: ConfigClient,
}

impl ResourceDriftCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self {
            client: ConfigClient::new(config),
        }
    }
}

#[async_trait]
impl CsvCollector for ResourceDriftCollector {
    fn name(&self) -> &str {
        "Resource Drift Detection"
    }
    fn filename_prefix(&self) -> &str {
        "Resource_Drift"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Resource ARN",
            "Resource Type",
            "Last Captured",
            "Days Since Capture",
            "Status",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let mut rows: Vec<Vec<String>> = Vec::new();

        let resource_types = &[
            "AWS::EC2::Instance",
            "AWS::S3::Bucket",
            "AWS::IAM::Role",
            "AWS::RDS::DBInstance",
            "AWS::Lambda::Function",
        ];

        let cap_total: usize = 1000;
        let now_secs = chrono::Utc::now().timestamp();
        let mut count_total: usize = 0;

        'outer: for rt_str in resource_types {
            if count_total >= cap_total {
                break;
            }
            let rt = ResourceType::from(*rt_str);

            let mut next_token: Option<String> = None;
            loop {
                let mut req = self
                    .client
                    .list_discovered_resources()
                    .resource_type(rt.clone())
                    .limit(100);
                if let Some(t) = next_token.as_ref() {
                    req = req.next_token(t);
                }
                let resp = match req.send().await {
                    Ok(r) => r,
                    Err(e) => {
                        let msg = format!("{e:#}");
                        if is_benign(&msg) {
                            eprintln!(
                                "  WARN: Config not enabled or accessible for {rt_str}: {msg}"
                            );
                            // Skip this RT but continue others (Config may be partial).
                            break;
                        }
                        eprintln!("  WARN: Config list_discovered_resources {rt_str}: {e:#}");
                        break;
                    }
                };

                for resource in resp.resource_identifiers() {
                    if count_total >= cap_total {
                        break 'outer;
                    }
                    let resource_id = resource.resource_id().unwrap_or("").to_string();
                    if resource_id.is_empty() {
                        continue;
                    }
                    count_total += 1;

                    let hist = match self
                        .client
                        .get_resource_config_history()
                        .resource_type(rt.clone())
                        .resource_id(&resource_id)
                        .limit(1)
                        .send()
                        .await
                    {
                        Ok(r) => r,
                        Err(e) => {
                            let msg = format!("{e:#}");
                            if !is_benign(&msg) {
                                eprintln!(
                                    "  WARN: Config get_resource_config_history {resource_id}: {e:#}"
                                );
                            }
                            continue;
                        }
                    };

                    let item = match hist.configuration_items().first() {
                        Some(i) => i,
                        None => continue,
                    };

                    let arn = item.arn().unwrap_or(&resource_id).to_string();
                    let item_rt = item
                        .resource_type()
                        .map(|t| t.as_str().to_string())
                        .unwrap_or_else(|| rt_str.to_string());
                    let status = item
                        .configuration_item_status()
                        .map(|s| s.as_str().to_string())
                        .unwrap_or_default();

                    let (capture_str, capture_secs) = match item.configuration_item_capture_time() {
                        Some(d) => fmt_config_dt(d),
                        None => continue,
                    };
                    let days_since = (now_secs - capture_secs) / 86_400;
                    if days_since <= 90 {
                        continue;
                    }

                    rows.push(vec![
                        arn,
                        item_rt,
                        capture_str,
                        days_since.to_string(),
                        status,
                    ]);
                }

                next_token = resp.next_token().map(|s| s.to_string());
                if next_token.is_none() {
                    break;
                }
            }
        }

        Ok(rows)
    }
}
