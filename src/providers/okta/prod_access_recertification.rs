use anyhow::Result;
use async_trait::async_trait;
use okta_rs::OktaClient;
use serde_json::Value;

use crate::evidence::CsvCollector;

const PROD_KEYWORDS: &[&str] = &["prod", "production"];

pub struct OktaProdAccessRecertificationCollector {
    client: OktaClient,
}

impl OktaProdAccessRecertificationCollector {
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

fn matches_prod(v: &Value) -> bool {
    let name = str_field(v, "name").to_lowercase();
    let description = str_field(v, "description").to_lowercase();
    PROD_KEYWORDS
        .iter()
        .any(|kw| name.contains(kw) || description.contains(kw))
}

#[async_trait]
impl CsvCollector for OktaProdAccessRecertificationCollector {
    fn name(&self) -> &str {
        "Okta Production Access Recertification"
    }
    fn filename_prefix(&self) -> &str {
        "Okta_Prod_Access_Recertification"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Campaign ID",
            "Name",
            "Status",
            "Target Group / Resource",
            "Reviewer",
            "Ended",
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
            .filter(|c| matches_prod(c))
            .map(|c| {
                let target = c
                    .get("resourceReferences")
                    .and_then(|v| v.as_array())
                    .and_then(|a| a.first())
                    .and_then(|r| r.get("resourceType"))
                    .and_then(|v| v.as_str())
                    .or_else(|| {
                        c.get("targetResources")
                            .and_then(|v| v.as_array())
                            .and_then(|a| a.first())
                            .and_then(|r| r.get("name"))
                            .and_then(|v| v.as_str())
                    })
                    .unwrap_or("")
                    .to_string();

                vec![
                    str_field(c, "id"),
                    str_field(c, "name"),
                    str_field(c, "status"),
                    target,
                    str_field(c, "principalReviewerId"),
                    str_field(c, "endDate"),
                ]
            })
            .collect();

        Ok(rows)
    }
}
