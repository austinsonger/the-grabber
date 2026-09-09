use anyhow::Result;
use async_trait::async_trait;
use jumpcloud_rs::JumpCloudClient;

use crate::evidence::CsvCollector;

pub struct JumpCloudMfaFactorsCollector {
    client: JumpCloudClient,
}

impl JumpCloudMfaFactorsCollector {
    pub fn new(client: JumpCloudClient) -> Self {
        Self { client }
    }
}

fn has_factor(factors: &[String], needle: &str) -> bool {
    factors.iter().any(|f| f.eq_ignore_ascii_case(needle))
}

#[async_trait]
impl CsvCollector for JumpCloudMfaFactorsCollector {
    fn name(&self) -> &str {
        "JumpCloud MFA Factors"
    }
    fn filename_prefix(&self) -> &str {
        "JumpCloud_MfaFactors"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "User ID",
            "Username",
            "Email",
            "MFA Configured",
            "MFA Exclusion",
            "Exclusion Days",
            "TOTP",
            "WebAuthn",
            "Push",
            "Duo",
            "All Configured Factors",
        ]
    }
    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let users = match self.client.users().list_all().await {
            Ok(u) => u,
            Err(jumpcloud_rs::JumpCloudError::Api { status: 404, .. }) => return Ok(vec![]),
            Err(e) => return Err(e.into()),
        };
        let rows = users
            .into_iter()
            .map(|u| {
                let factors = &u.mfa.configured_factors;
                vec![
                    u.id,
                    u.username,
                    u.email,
                    u.mfa.configured.to_string(),
                    u.mfa.exclusion.to_string(),
                    u.mfa
                        .exclusion_days
                        .map(|d| d.to_string())
                        .unwrap_or_default(),
                    has_factor(factors, "totp").to_string(),
                    has_factor(factors, "webauthn").to_string(),
                    has_factor(factors, "push").to_string(),
                    has_factor(factors, "duo").to_string(),
                    factors.join(";"),
                ]
            })
            .collect();
        Ok(rows)
    }
}
