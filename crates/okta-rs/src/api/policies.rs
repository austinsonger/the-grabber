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

    /// GET /api/v1/policies/{policy_id}/rules
    ///
    /// Rule `actions`/`conditions` shape varies drastically per policy type
    /// (`signon` session actions vs. `appSignOn` verification-method
    /// constraints vs. `enroll` factor requirements), so rules are returned
    /// as raw JSON rather than a single typed struct.
    pub async fn list_rules(&self, policy_id: &str) -> Result<Vec<serde_json::Value>, OktaError> {
        let path = format!("/api/v1/policies/{policy_id}/rules");
        let resp = self.0.get(&path).await?;
        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let message = resp.text().await.unwrap_or_default();
            return Err(OktaError::Api { status, message });
        }
        Ok(resp.json().await?)
    }

    /// PUT /api/v1/policies/{policy_id}
    ///
    /// `body` must be the full policy object (fetch via `list_by_type`,
    /// mutate the field(s) you need, then pass the whole thing back —
    /// Okta's Policy API replaces the resource, it does not merge-patch).
    pub async fn update_policy(
        &self,
        policy_id: &str,
        body: &serde_json::Value,
    ) -> Result<serde_json::Value, OktaError> {
        let path = format!("/api/v1/policies/{policy_id}");
        let resp = self.0.put_json(&path, body).await?;
        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let message = resp.text().await.unwrap_or_default();
            return Err(OktaError::Api { status, message });
        }
        Ok(resp.json().await?)
    }

    /// PUT /api/v1/policies/{policy_id}/rules/{rule_id}
    ///
    /// `body` must be the full rule object (fetch via `list_rules`, mutate,
    /// then pass the whole thing back — same full-replace semantics as
    /// `update_policy`).
    pub async fn update_rule(
        &self,
        policy_id: &str,
        rule_id: &str,
        body: &serde_json::Value,
    ) -> Result<serde_json::Value, OktaError> {
        let path = format!("/api/v1/policies/{policy_id}/rules/{rule_id}");
        let resp = self.0.put_json(&path, body).await?;
        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let message = resp.text().await.unwrap_or_default();
            return Err(OktaError::Api { status, message });
        }
        Ok(resp.json().await?)
    }
}
