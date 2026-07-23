use crate::error::JumpCloudError;

#[derive(Clone)]
pub struct JumpCloudClient;

impl JumpCloudClient {
    pub fn new(_base_url: &str, _api_key: &str, _org_id: Option<&str>) -> Result<Self, JumpCloudError> {
        Ok(Self)
    }
}
