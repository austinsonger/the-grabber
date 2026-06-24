use crate::client::OktaClient;
use crate::error::OktaError;
use crate::types::policy::OktaPolicy;

pub struct PoliciesApi<'c>(pub(crate) &'c OktaClient);

impl<'c> PoliciesApi<'c> {
    /// GET /api/v1/policies?type={policy_type}
    /// Supported types include: OKTA_SIGN_ON, PASSWORD, MFA_ENROLL, IDP_DISCOVERY,
    /// ACCESS_POLICY, PROFILE_ENROLLMENT.
    pub async fn list_by_type(&self, policy_type: &str) -> Result<Vec<OktaPolicy>, OktaError> {
        let path = format!("/api/v1/policies?type={}", policy_type);
        let resp = self.0.get(&path).await?;
        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let message = resp.text().await.unwrap_or_default();
            return Err(OktaError::Api { status, message });
        }
        Ok(resp.json().await?)
    }
}
