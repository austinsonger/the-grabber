use crate::client::JumpCloudClient;
use crate::error::JumpCloudError;
use crate::types::organization::Organization;

pub struct OrganizationsApi<'a>(pub(crate) &'a JumpCloudClient);

impl<'a> OrganizationsApi<'a> {
    pub async fn list_all(&self) -> Result<Vec<Organization>, JumpCloudError> {
        self.0.list_v1("/api/organizations").await
    }

    /// GET /api/organizations/{id} — returns the org record including
    /// the `settings` block used by password/session-policy collectors.
    pub async fn get(&self, org_id: &str) -> Result<Organization, JumpCloudError> {
        let path = format!("/api/organizations/{org_id}");
        let url = self.0.url(&path);
        let resp = self.0.http.get(&url).send().await?;
        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let message = resp.text().await.unwrap_or_default();
            return Err(JumpCloudError::Api { status, message });
        }
        let org: Organization = resp.json().await?;
        Ok(org)
    }
}
