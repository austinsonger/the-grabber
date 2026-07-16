use anyhow::Result;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use okta_rs::OktaClient;

use crate::evidence::CsvCollector;

pub struct OktaOffboardingSlaCollector {
    client: OktaClient,
}

impl OktaOffboardingSlaCollector {
    pub fn new(client: OktaClient) -> Self {
        Self { client }
    }
}

#[async_trait]
impl CsvCollector for OktaOffboardingSlaCollector {
    fn name(&self) -> &str {
        "Okta Offboarding SLA"
    }
    fn filename_prefix(&self) -> &str {
        "Okta_Offboarding_SLA"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Event ID",
            "Published",
            "Login",
            "Actor Name",
            "Hours Since Termination",
            "SLA Met (24hr)",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let since_iso = dates
            .map(|(s, _)| DateTime::<Utc>::from_timestamp(s, 0).unwrap_or_else(Utc::now))
            .unwrap_or_else(|| Utc::now() - chrono::Duration::days(90))
            .to_rfc3339();

        let events = match self
            .client
            .lifecycle()
            .events_all("user.lifecycle.deactivate", &since_iso)
            .await
        {
            Ok(e) => e,
            Err(okta_rs::OktaError::Api { status: 404, .. }) => return Ok(vec![]),
            Err(e) => return Err(e.into()),
        };

        let rows = events
            .into_iter()
            .map(|e| {
                let target_arr = e.target.as_array();
                let login = target_arr
                    .and_then(|a| a.first())
                    .and_then(|t| t.get("alternateId"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();

                let actor_name = e
                    .actor
                    .as_ref()
                    .and_then(|a| a.display_name.clone())
                    .unwrap_or_default();

                // TODO: join to HRIS termination date via --hris-term-source flag once available
                vec![
                    e.uuid,
                    e.published,
                    login,
                    actor_name,
                    String::new(),
                    "UNKNOWN".to_string(),
                ]
            })
            .collect();

        Ok(rows)
    }
}
