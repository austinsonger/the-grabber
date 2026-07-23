use serde::Deserialize;

use crate::client::JamfClient;
use crate::error::JamfError;

#[derive(Debug, Clone, Deserialize, Default)]
pub struct DeviceGroup {
    pub id: i64,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub is_smart: bool,
    #[serde(default)]
    pub criteria: Vec<Criterion>,
    #[serde(default)]
    pub member_count: usize,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct Criterion {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub operator: String,
    #[serde(default)]
    pub value: String,
}

#[derive(Debug, Deserialize)]
struct ListEnvelope {
    #[serde(alias = "computer_groups", alias = "mobile_device_groups")]
    items: Vec<ListItem>,
}

#[derive(Debug, Deserialize)]
struct ListItem {
    id: i64,
}

#[derive(Debug, Deserialize)]
struct DetailEnvelope {
    #[serde(alias = "computer_group", alias = "mobile_device_group")]
    detail: GroupDetail,
}

#[derive(Debug, Deserialize, Default)]
struct GroupDetail {
    #[serde(default)]
    name: String,
    #[serde(default)]
    is_smart: bool,
    #[serde(default)]
    criteria: CriteriaEnvelope,
    #[serde(default, alias = "computers", alias = "mobile_devices")]
    members: MembersEnvelope,
}

#[derive(Debug, Deserialize, Default)]
struct CriteriaEnvelope {
    #[serde(default)]
    criterion: Vec<Criterion>,
}

#[derive(Debug, Deserialize, Default)]
struct MembersEnvelope {
    #[serde(default, alias = "computer", alias = "mobile_device")]
    member: Vec<serde_json::Value>,
}

async fn list_and_fetch(
    client: &JamfClient,
    list_path: &str,
    detail_path_prefix: &str,
) -> Result<Vec<DeviceGroup>, JamfError> {
    let resp = client.get(list_path).await?;
    if !resp.status().is_success() {
        let status = resp.status().as_u16();
        let message = resp.text().await.unwrap_or_default();
        return Err(JamfError::Api { status, message });
    }
    let list: ListEnvelope = resp.json().await?;

    let mut out = Vec::with_capacity(list.items.len());
    for item in list.items {
        let detail_resp = client
            .get(&format!("{detail_path_prefix}/id/{}", item.id))
            .await?;
        if !detail_resp.status().is_success() {
            continue;
        }
        let detail: DetailEnvelope = detail_resp.json().await?;
        out.push(DeviceGroup {
            id: item.id,
            name: detail.detail.name,
            is_smart: detail.detail.is_smart,
            criteria: detail.detail.criteria.criterion,
            member_count: detail.detail.members.member.len(),
        });
    }
    Ok(out)
}

pub struct ComputerGroupsApi<'c>(pub(crate) &'c JamfClient);

impl<'c> ComputerGroupsApi<'c> {
    pub async fn list_all(&self) -> Result<Vec<DeviceGroup>, JamfError> {
        list_and_fetch(
            self.0,
            "/JSSResource/computergroups",
            "/JSSResource/computergroups",
        )
        .await
    }
}

pub struct MobileDeviceGroupsApi<'c>(pub(crate) &'c JamfClient);

impl<'c> MobileDeviceGroupsApi<'c> {
    pub async fn list_all(&self) -> Result<Vec<DeviceGroup>, JamfError> {
        list_and_fetch(
            self.0,
            "/JSSResource/mobiledevicegroups",
            "/JSSResource/mobiledevicegroups",
        )
        .await
    }
}
