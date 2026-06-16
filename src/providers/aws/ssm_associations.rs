use anyhow::Result;
use async_trait::async_trait;
use aws_sdk_ssm::Client as SsmClient;

use crate::evidence::CsvCollector;

fn fmt_ssm_dt(dt: &aws_sdk_ssm::primitives::DateTime) -> String {
    chrono::DateTime::<chrono::Utc>::from_timestamp(dt.secs(), 0)
        .map(|c| c.to_rfc3339())
        .unwrap_or_default()
}

pub struct SsmAssociationsCollector {
    client: SsmClient,
}

impl SsmAssociationsCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self {
            client: SsmClient::new(config),
        }
    }
}

#[async_trait]
impl CsvCollector for SsmAssociationsCollector {
    fn name(&self) -> &str {
        "SSM Associations"
    }
    fn filename_prefix(&self) -> &str {
        "SSM_Association_Compliance"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Association ID",
            "Document Name",
            "Targets",
            "Schedule Expression",
            "Last Execution Status",
            "Last Execution Time",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let mut rows = Vec::new();
        let mut next_token: Option<String> = None;

        loop {
            let mut req = self.client.list_associations();
            if let Some(ref t) = next_token {
                req = req.next_token(t);
            }
            let resp = match req.send().await {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("  WARN: SSM list_associations: {e:#}");
                    break;
                }
            };

            for assoc in resp.associations() {
                let association_id = assoc.association_id().unwrap_or("").to_string();
                let document_name = assoc.name().unwrap_or("").to_string();
                let targets: String = assoc
                    .targets()
                    .iter()
                    .map(|t| {
                        let key = t.key().unwrap_or("");
                        let values = t.values().join(",");
                        format!("{key}={values}")
                    })
                    .collect::<Vec<_>>()
                    .join(";");
                let schedule = assoc.schedule_expression().unwrap_or("").to_string();
                let last_status = assoc
                    .overview()
                    .and_then(|o| o.status())
                    .unwrap_or("")
                    .to_string();
                let last_exec = assoc
                    .last_execution_date()
                    .map(fmt_ssm_dt)
                    .unwrap_or_default();

                rows.push(vec![
                    association_id,
                    document_name,
                    targets,
                    schedule,
                    last_status,
                    last_exec,
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
