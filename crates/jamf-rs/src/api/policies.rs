use serde::{Deserialize, Serialize};

use crate::client::JamfClient;
use crate::error::JamfError;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Policy {
    pub id: i64,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub category: String,
    #[serde(default)]
    pub frequency: String,
    #[serde(default)]
    pub scope: String,
}

#[derive(Debug, Deserialize)]
struct ListEnvelope {
    policies: Vec<ListItem>,
}

#[derive(Debug, Deserialize)]
struct ListItem {
    id: i64,
}

#[derive(Debug, Deserialize)]
struct DetailEnvelope {
    policy: PolicyDetail,
}

#[derive(Debug, Deserialize, Default)]
struct PolicyDetail {
    #[serde(default)]
    general: PolicyGeneral,
    #[serde(default)]
    scope: PolicyScopeDetail,
}

#[derive(Debug, Deserialize, Default)]
struct PolicyGeneral {
    #[serde(default)]
    name: String,
    #[serde(default)]
    category: NamedRef,
    #[serde(default)]
    frequency: String,
}

#[derive(Debug, Deserialize, Default)]
struct NamedRef {
    #[serde(default)]
    name: String,
}

#[derive(Debug, Deserialize, Default)]
struct PolicyScopeDetail {
    #[serde(default)]
    all_computers: bool,
    #[serde(default)]
    computer_groups: Vec<NamedRef>,
}

pub struct PoliciesApi<'c>(pub(crate) &'c JamfClient);

impl<'c> PoliciesApi<'c> {
    /// GET /JSSResource/policies (list) + /JSSResource/policies/id/{id} (detail per policy) —
    /// the Classic API's list endpoint only returns id+name, so full policy detail requires
    /// one detail fetch per policy.
    pub async fn list_all(&self) -> Result<Vec<Policy>, JamfError> {
        let resp = self.0.get("/JSSResource/policies").await?;
        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let message = resp.text().await.unwrap_or_default();
            return Err(JamfError::Api { status, message });
        }
        let list: ListEnvelope = resp.json().await?;

        let mut out = Vec::with_capacity(list.policies.len());
        for item in list.policies {
            let detail_resp = self
                .0
                .get(&format!("/JSSResource/policies/id/{}", item.id))
                .await?;
            if !detail_resp.status().is_success() {
                continue;
            }
            let detail: DetailEnvelope = detail_resp.json().await?;
            let scope = if detail.policy.scope.all_computers {
                "All".to_string()
            } else {
                let names: Vec<&str> = detail
                    .policy
                    .scope
                    .computer_groups
                    .iter()
                    .map(|g| g.name.as_str())
                    .collect();
                if names.is_empty() {
                    "None".to_string()
                } else {
                    names.join("; ")
                }
            };
            out.push(Policy {
                id: item.id,
                name: detail.policy.general.name,
                category: detail.policy.general.category.name,
                frequency: detail.policy.general.frequency,
                scope,
            });
        }
        Ok(out)
    }
}
