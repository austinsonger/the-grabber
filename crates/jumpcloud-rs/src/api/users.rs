use crate::client::JumpCloudClient;
use crate::error::JumpCloudError;
use crate::types::user::SystemUser;

pub struct UsersApi<'a>(pub(crate) &'a JumpCloudClient);

impl<'a> UsersApi<'a> {
    pub async fn list_all(&self) -> Result<Vec<SystemUser>, JumpCloudError> {
        self.0.list_v1("/api/systemusers").await
    }
}
