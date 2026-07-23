use crate::client::JumpCloudClient;
use crate::error::JumpCloudError;
use crate::types::policy::Policy;

pub struct PoliciesApi<'a>(pub(crate) &'a JumpCloudClient);

impl<'a> PoliciesApi<'a> {
    pub async fn list_all(&self) -> Result<Vec<Policy>, JumpCloudError> {
        self.0.list_v2_cursor("/api/v2/policies").await
    }
}
