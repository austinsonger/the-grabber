use anyhow::Result;
use async_trait::async_trait;
use crowdstrike_rs::CrowdStrikeClient;

use crate::evidence::CsvCollector;

pub struct CrowdStrikePreventionPoliciesCollector {
    client: CrowdStrikeClient,
}

impl CrowdStrikePreventionPoliciesCollector {
    pub fn new(client: CrowdStrikeClient) -> Self {
        Self { client }
    }
}

#[async_trait]
impl CsvCollector for CrowdStrikePreventionPoliciesCollector {
    fn name(&self) -> &str {
        "CrowdStrike Prevention Policies"
    }
    fn filename_prefix(&self) -> &str {
        "CrowdStrike_Prevention_Policies"
    }

    fn headers(&self) -> &'static [&'static str] {
        &[
            "Policy ID",
            "Name",
            "Platform",
            "Enabled",
            "Description",
            "Precedence",
            "Created",
            "Modified",
            "Created By",
            "Modified By",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let policies = match self.client.prevention_policies().list_all().await {
            Ok(p) => p,
            Err(crowdstrike_rs::CrowdStrikeError::Api { status: 404, .. }) => return Ok(vec![]),
            Err(e) => return Err(e.into()),
        };
        let rows = policies
            .into_iter()
            .map(|p| {
                vec![
                    p.id,
                    p.name.unwrap_or_default(),
                    p.platform_name.unwrap_or_default(),
                    p.enabled
                        .map(|b| if b { "YES" } else { "NO" })
                        .unwrap_or_default()
                        .to_string(),
                    p.description.unwrap_or_default(),
                    p.precedence.map(|n| n.to_string()).unwrap_or_default(),
                    p.created_timestamp.unwrap_or_default(),
                    p.modified_timestamp.unwrap_or_default(),
                    p.created_by.unwrap_or_default(),
                    p.modified_by.unwrap_or_default(),
                ]
            })
            .collect();
        Ok(rows)
    }
}
