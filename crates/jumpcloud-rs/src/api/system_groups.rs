use crate::client::JumpCloudClient;
use crate::error::JumpCloudError;
use crate::types::system_group::{SystemGroup, SystemGroupMember};

pub struct SystemGroupsApi<'a>(pub(crate) &'a JumpCloudClient);

impl<'a> SystemGroupsApi<'a> {
    pub async fn list_all(&self) -> Result<Vec<SystemGroup>, JumpCloudError> {
        self.0.list_v2_cursor("/api/v2/systemgroups").await
    }

    pub async fn list_members(
        &self,
        group_id: &str,
    ) -> Result<Vec<SystemGroupMember>, JumpCloudError> {
        let path = format!("/api/v2/systemgroups/{group_id}/members");
        self.0.list_v2_cursor(&path).await
    }
}
