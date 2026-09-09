use crate::client::JumpCloudClient;
use crate::error::JumpCloudError;
use crate::types::application::Application;

pub struct ApplicationsApi<'a>(pub(crate) &'a JumpCloudClient);

impl<'a> ApplicationsApi<'a> {
    pub async fn list_all(&self) -> Result<Vec<Application>, JumpCloudError> {
        self.0.list_v1("/api/applications").await
    }
}
