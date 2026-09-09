use crate::client::JumpCloudClient;
use crate::error::JumpCloudError;
use crate::types::administrator::Administrator;

pub struct AdministratorsApi<'a>(pub(crate) &'a JumpCloudClient);

impl<'a> AdministratorsApi<'a> {
    /// List org administrators. Requires the caller's API key to belong to
    /// the same org. If `org_id` is empty, the header-scoped org is used.
    pub async fn list_all(&self, org_id: &str) -> Result<Vec<Administrator>, JumpCloudError> {
        let path = if org_id.is_empty() {
            "/api/organizations/administrators".to_string()
        } else {
            format!("/api/organizations/{org_id}/administrators")
        };
        self.0.list_v1(&path).await
    }
}
