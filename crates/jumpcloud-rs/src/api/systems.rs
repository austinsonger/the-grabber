use crate::client::JumpCloudClient;
use crate::error::JumpCloudError;
use crate::types::association::AssociationRef;
use crate::types::system::System;

pub struct SystemsApi<'a>(pub(crate) &'a JumpCloudClient);

impl<'a> SystemsApi<'a> {
    pub async fn list_all(&self) -> Result<Vec<System>, JumpCloudError> {
        self.0.list_v1("/api/systems").await
    }

    pub async fn list_users(&self, system_id: &str) -> Result<Vec<AssociationRef>, JumpCloudError> {
        let path = format!("/api/v2/systems/{system_id}/users");
        self.0.list_v2_cursor(&path).await
    }
}
