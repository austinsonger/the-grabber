use anyhow::Result;
use async_trait::async_trait;
use jamf_rs::JamfClient;

use crate::evidence::CsvCollector;

fn scope_summary(scope: &jamf_rs::api::config_profiles::ProfileScope) -> String {
    if scope.all_computers || scope.all_mobile_devices {
        return "All".to_string();
    }
    let groups: Vec<&str> = scope
        .computer_groups
        .iter()
        .chain(scope.mobile_device_groups.iter())
        .map(|g| g.name.as_str())
        .collect();
    if groups.is_empty() {
        "None".to_string()
    } else {
        groups.join("; ")
    }
}

pub struct JamfMobileConfigProfilesCollector {
    client: JamfClient,
}

impl JamfMobileConfigProfilesCollector {
    pub fn new(client: JamfClient) -> Self {
        Self { client }
    }
}

#[async_trait]
impl CsvCollector for JamfMobileConfigProfilesCollector {
    fn name(&self) -> &str {
        "Jamf Mobile Configuration Profiles"
    }
    fn filename_prefix(&self) -> &str {
        "Jamf_Mobile_Config_Profiles"
    }

    fn headers(&self) -> &'static [&'static str] {
        &[
            "Profile ID",
            "Name",
            "Category",
            "Distribution Method",
            "Scope",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let profiles = match self.client.mobile_config_profiles().list_all().await {
            Ok(p) => p,
            Err(jamf_rs::JamfError::Api { status: 404, .. }) => return Ok(vec![]),
            Err(e) => return Err(e.into()),
        };
        let rows = profiles
            .into_iter()
            .map(|p| {
                vec![
                    p.id.to_string(),
                    p.name,
                    p.category.name,
                    p.distribution_method,
                    scope_summary(&p.scope),
                ]
            })
            .collect();
        Ok(rows)
    }
}
