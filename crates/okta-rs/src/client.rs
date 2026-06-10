use crate::error::OktaError;
#[derive(Clone)]
pub struct OktaClient;
impl OktaClient {
    pub fn new(_base_url: &str, _token: &str) -> Result<Self, OktaError> {
        Ok(Self)
    }
}
