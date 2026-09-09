use crate::client::JumpCloudClient;
use crate::error::JumpCloudError;
use crate::types::user_group::{UserGroup, UserGroupMember};

pub struct UserGroupsApi<'a>(pub(crate) &'a JumpCloudClient);

impl<'a> UserGroupsApi<'a> {
    pub async fn list_all(&self) -> Result<Vec<UserGroup>, JumpCloudError> {
        self.0.list_v2_cursor("/api/v2/usergroups").await
    }

    pub async fn list_members(
        &self,
        group_id: &str,
    ) -> Result<Vec<UserGroupMember>, JumpCloudError> {
        let path = format!("/api/v2/usergroups/{group_id}/members");
        self.0.list_v2_cursor(&path).await
    }
}
