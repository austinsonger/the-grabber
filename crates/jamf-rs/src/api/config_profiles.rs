use serde::Deserialize;

use crate::client::JamfClient;
use crate::error::JamfError;

#[derive(Debug, Clone, Deserialize, Default)]
pub struct ConfigProfile {
    pub id: i64,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub category: NamedRef,
    #[serde(default, rename = "distribution_method")]
    pub distribution_method: String,
    #[serde(default)]
    pub scope: ProfileScope,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct NamedRef {
    #[serde(default)]
    pub name: String,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct ProfileScope {
    #[serde(default)]
    pub all_computers: bool,
    #[serde(default)]
    pub all_mobile_devices: bool,
    #[serde(default)]
    pub computer_groups: Vec<NamedRef>,
    #[serde(default)]
    pub mobile_device_groups: Vec<NamedRef>,
}

#[derive(Debug, Deserialize)]
struct ListEnvelope<T> {
    #[serde(
        alias = "os_x_configuration_profiles",
        alias = "mobile_device_configuration_profiles"
    )]
    items: Vec<T>,
}

#[derive(Debug, Deserialize)]
struct ListItem {
    id: i64,
}

#[derive(Debug, Deserialize)]
struct DetailEnvelope {
    #[serde(
        alias = "os_x_configuration_profile",
        alias = "mobile_device_configuration_profile"
    )]
    general: DetailGeneral,
}

#[derive(Debug, Deserialize)]
struct DetailGeneral {
    general: ProfileGeneralFields,
    #[serde(default)]
    scope: ProfileScope,
}

#[derive(Debug, Deserialize, Default)]
struct ProfileGeneralFields {
    #[serde(default)]
    name: String,
    #[serde(default)]
    category: NamedRef,
    #[serde(default)]
    distribution_method: String,
}

async fn list_and_fetch(
    client: &JamfClient,
    list_path: &str,
    detail_path_prefix: &str,
) -> Result<Vec<ConfigProfile>, JamfError> {
    let resp = client.get(list_path).await?;
    if !resp.status().is_success() {
        let status = resp.status().as_u16();
        let message = resp.text().await.unwrap_or_default();
        return Err(JamfError::Api { status, message });
    }
    let list: ListEnvelope<ListItem> = resp.json().await?;

    let mut out = Vec::with_capacity(list.items.len());
    for item in list.items {
        let detail_resp = client
            .get(&format!("{detail_path_prefix}/id/{}", item.id))
            .await?;
        if !detail_resp.status().is_success() {
            continue;
        }
        let detail: DetailEnvelope = detail_resp.json().await?;
        out.push(ConfigProfile {
            id: item.id,
            name: detail.general.general.name,
            category: detail.general.general.category,
            distribution_method: detail.general.general.distribution_method,
            scope: detail.general.scope,
        });
    }
    Ok(out)
}

pub struct ComputerConfigProfilesApi<'c>(pub(crate) &'c JamfClient);

impl<'c> ComputerConfigProfilesApi<'c> {
    pub async fn list_all(&self) -> Result<Vec<ConfigProfile>, JamfError> {
        list_and_fetch(
            self.0,
            "/JSSResource/osxconfigurationprofiles",
            "/JSSResource/osxconfigurationprofiles",
        )
        .await
    }
}

pub struct MobileConfigProfilesApi<'c>(pub(crate) &'c JamfClient);

impl<'c> MobileConfigProfilesApi<'c> {
    pub async fn list_all(&self) -> Result<Vec<ConfigProfile>, JamfError> {
        list_and_fetch(
            self.0,
            "/JSSResource/mobiledeviceconfigurationprofiles",
            "/JSSResource/mobiledeviceconfigurationprofiles",
        )
        .await
    }
}
