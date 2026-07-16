use anyhow::Result;
use async_trait::async_trait;
use okta_rs::OktaClient;
use serde_json::Value;

use crate::evidence::CsvCollector;

pub struct OktaAccessCertificationCampaignsCollector {
    client: OktaClient,
}

impl OktaAccessCertificationCampaignsCollector {
    pub fn new(client: OktaClient) -> Self {
        Self { client }
    }
}

fn str_field(v: &Value, key: &str) -> String {
    v.get(key)
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .to_string()
}

#[async_trait]
impl CsvCollector for OktaAccessCertificationCampaignsCollector {
    fn name(&self) -> &str {
        "Okta Access Certification Campaigns"
    }
    fn filename_prefix(&self) -> &str {
        "Okta_Access_Certification_Campaigns"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Campaign ID",
            "Name",
            "Status",
            "Created",
            "Started",
            "Ended",
            "Owner",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let campaigns = match self.client.access_reviews().campaigns().await {
            Ok(v) => v,
            Err(okta_rs::OktaError::Api { status, .. }) if [401, 403, 404].contains(&status) => {
                return Ok(vec![])
            }
            Err(e) => return Err(e.into()),
        };

        let arr = match campaigns.as_array() {
            Some(a) => a,
            None => return Ok(vec![]),
        };

        let rows = arr
            .iter()
            .map(|c| {
                let owner = c
                    .get("principalReviewerId")
                    .and_then(|v| v.as_str())
                    .or_else(|| c.get("owner").and_then(|v| v.as_str()))
                    .unwrap_or("")
                    .to_string();

                vec![
                    str_field(c, "id"),
                    str_field(c, "name"),
                    str_field(c, "status"),
                    str_field(c, "created"),
                    str_field(c, "startDate"),
                    str_field(c, "endDate"),
                    owner,
                ]
            })
            .collect();

        Ok(rows)
    }
}
