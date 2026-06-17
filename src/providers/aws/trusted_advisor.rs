use anyhow::Result;
use async_trait::async_trait;
use aws_sdk_support::Client as SupportClient;

use crate::evidence::CsvCollector;

pub struct TrustedAdvisorCollector {
    client: SupportClient,
}

impl TrustedAdvisorCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self {
            client: SupportClient::new(config),
        }
    }
}

#[async_trait]
impl CsvCollector for TrustedAdvisorCollector {
    fn name(&self) -> &str {
        "Trusted Advisor Checks"
    }
    fn filename_prefix(&self) -> &str {
        "TrustedAdvisor_Checks"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Check ID",
            "Name",
            "Category",
            "Status",
            "Resources Flagged",
            "Timestamp",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let mut rows = Vec::new();

        let checks_resp = match self
            .client
            .describe_trusted_advisor_checks()
            .language("en")
            .send()
            .await
        {
            Ok(r) => r,
            Err(e) => {
                let msg = format!("{e:#}");
                if msg.contains("SubscriptionRequiredException") {
                    rows.push(vec![
                        String::new(),
                        "Support tier insufficient".to_string(),
                        String::new(),
                        String::new(),
                        String::new(),
                        String::new(),
                    ]);
                    return Ok(rows);
                }
                eprintln!("  WARN: TrustedAdvisor describe_trusted_advisor_checks: {e:#}");
                return Ok(rows);
            }
        };

        let checks: Vec<(String, String, String)> = checks_resp
            .checks()
            .iter()
            .map(|c| {
                (
                    c.id().to_string(),
                    c.name().to_string(),
                    c.category().to_string(),
                )
            })
            .collect();

        for (id, name, category) in checks {
            let result_resp = match self
                .client
                .describe_trusted_advisor_check_result()
                .check_id(&id)
                .language("en")
                .send()
                .await
            {
                Ok(r) => r,
                Err(e) => {
                    let msg = format!("{e:#}");
                    if msg.contains("SubscriptionRequiredException") {
                        rows.push(vec![
                            String::new(),
                            "Support tier insufficient".to_string(),
                            String::new(),
                            String::new(),
                            String::new(),
                            String::new(),
                        ]);
                        return Ok(rows);
                    }
                    eprintln!(
                        "  WARN: TrustedAdvisor describe_trusted_advisor_check_result({id}): {e:#}"
                    );
                    rows.push(vec![
                        id,
                        name,
                        category,
                        String::new(),
                        String::new(),
                        String::new(),
                    ]);
                    continue;
                }
            };

            let (status, timestamp, flagged) = match result_resp.result() {
                Some(r) => {
                    let status = r.status().to_string();
                    let timestamp = r.timestamp().to_string();
                    let flagged = r
                        .resources_summary()
                        .map(|s| s.resources_flagged().to_string())
                        .unwrap_or_default();
                    (status, timestamp, flagged)
                }
                None => (String::new(), String::new(), String::new()),
            };

            rows.push(vec![id, name, category, status, flagged, timestamp]);
        }

        Ok(rows)
    }
}
