use anyhow::Result;
use async_trait::async_trait;
use jamf_rs::JamfClient;

use crate::evidence::CsvCollector;

fn criteria_summary(criteria: &[jamf_rs::api::groups::Criterion]) -> String {
    if criteria.is_empty() {
        return "static".to_string();
    }
    criteria
        .iter()
        .map(|c| format!("{} {} {}", c.name, c.operator, c.value))
        .collect::<Vec<_>>()
        .join(" AND ")
}

pub struct JamfMobileDeviceGroupsCollector {
    client: JamfClient,
}

impl JamfMobileDeviceGroupsCollector {
    pub fn new(client: JamfClient) -> Self {
        Self { client }
    }
}

#[async_trait]
impl CsvCollector for JamfMobileDeviceGroupsCollector {
    fn name(&self) -> &str {
        "Jamf Mobile Device Groups"
    }
    fn filename_prefix(&self) -> &str {
        "Jamf_Mobile_Device_Groups"
    }

    fn headers(&self) -> &'static [&'static str] {
        &["Group ID", "Name", "Type", "Criteria", "Member Count"]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let groups = match self.client.mobile_device_groups().list_all().await {
            Ok(g) => g,
            Err(jamf_rs::JamfError::Api { status: 404, .. }) => return Ok(vec![]),
            Err(e) => return Err(e.into()),
        };
        let rows = groups
            .into_iter()
            .map(|g| {
                vec![
                    g.id.to_string(),
                    g.name,
                    if g.is_smart { "Smart".to_string() } else { "Static".to_string() },
                    criteria_summary(&g.criteria),
                    g.member_count.to_string(),
                ]
            })
            .collect();
        Ok(rows)
    }
}
