use anyhow::Result;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use okta_rs::OktaClient;

use crate::evidence::CsvCollector;

const CONTRACTOR_TOKENS: &[&str] = &["contractor", "ctr-", "-ext", "external"];

pub struct OktaContractorDeprovisioningCollector {
    client: OktaClient,
}

impl OktaContractorDeprovisioningCollector {
    pub fn new(client: OktaClient) -> Self {
        Self { client }
    }
}

#[async_trait]
impl CsvCollector for OktaContractorDeprovisioningCollector {
    fn name(&self) -> &str {
        "Okta Contractor Deprovisioning"
    }
    fn filename_prefix(&self) -> &str {
        "Okta_Contractor_Deprovisioning"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Event ID",
            "Published",
            "Contractor Login",
            "Actor Name",
            "Days Since Contract End",
            "Outcome",
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
            .filter_map(|e| {
                let target_arr = e.target.as_array();
                let login = target_arr
                    .and_then(|a| a.first())
                    .and_then(|t| t.get("alternateId"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();

                let login_lower = login.to_lowercase();
                let is_contractor = CONTRACTOR_TOKENS
                    .iter()
                    .any(|tok| login_lower.contains(tok));
                if !is_contractor {
                    return None;
                }

                let actor_name = e
                    .actor
                    .as_ref()
                    .and_then(|a| a.display_name.clone())
                    .unwrap_or_default();
                let outcome = e
                    .outcome
                    .as_ref()
                    .map(|o| o.result.clone())
                    .unwrap_or_default();

                // Days Since Contract End requires an HRIS join; left empty.
                Some(vec![
                    e.uuid,
                    e.published,
                    login,
                    actor_name,
                    String::new(),
                    outcome,
                ])
            })
            .collect();

        Ok(rows)
    }
}
