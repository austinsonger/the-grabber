use serde::Deserialize;

use crate::client::JamfClient;
use crate::error::JamfError;

#[derive(Debug, Clone, Deserialize)]
pub struct PatchTitle {
    pub id: String,
    #[serde(rename = "displayName")]
    pub display_name: String,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct PatchSummary {
    #[serde(default, rename = "latestVersion")]
    pub latest_version: String,
    #[serde(default)]
    pub versions: Vec<PatchVersionCount>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct PatchVersionCount {
    #[serde(default)]
    pub version: String,
    #[serde(default, rename = "hostIds")]
    pub host_ids: Vec<String>,
}

impl PatchSummary {
    /// Devices currently on `latest_version`.
    pub fn compliant_count(&self) -> usize {
        self.versions
            .iter()
            .find(|v| v.version == self.latest_version)
            .map(|v| v.host_ids.len())
            .unwrap_or(0)
    }

    /// Devices on any other reported version.
    pub fn out_of_date_count(&self) -> usize {
        self.versions
            .iter()
            .filter(|v| v.version != self.latest_version)
            .map(|v| v.host_ids.len())
            .sum()
    }
}

pub struct PatchApi<'c>(pub(crate) &'c JamfClient);

impl<'c> PatchApi<'c> {
    /// GET /api/v2/patch-software-title-configurations — configured patch titles.
    /// Org-scale title counts are small (tens, not thousands), so this call is
    /// not paginated.
    pub async fn list_titles(&self) -> Result<Vec<PatchTitle>, JamfError> {
        let resp = self
            .0
            .get("/api/v2/patch-software-title-configurations")
            .await?;
        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let message = resp.text().await.unwrap_or_default();
            return Err(JamfError::Api { status, message });
        }
        Ok(resp.json().await?)
    }

    /// GET /api/v2/patch-software-title-configurations/{id}/patch-summary
    pub async fn summary(&self, title_id: &str) -> Result<PatchSummary, JamfError> {
        let resp = self
            .0
            .get(&format!(
                "/api/v2/patch-software-title-configurations/{title_id}/patch-summary"
            ))
            .await?;
        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let message = resp.text().await.unwrap_or_default();
            return Err(JamfError::Api { status, message });
        }
        Ok(resp.json().await?)
    }
}
