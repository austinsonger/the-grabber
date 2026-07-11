use anyhow::Result;
use async_trait::async_trait;
use okta_rs::OktaClient;

use crate::evidence::CsvCollector;

pub struct OktaFactorsCollector {
    client: OktaClient,
}
impl OktaFactorsCollector {
    pub fn new(client: OktaClient) -> Self {
        Self { client }
    }
}

#[async_trait]
impl CsvCollector for OktaFactorsCollector {
    fn name(&self) -> &str {
        "Okta MFA Factors"
    }
    fn filename_prefix(&self) -> &str {
        "Okta_MFA_Factors"
    }

    fn headers(&self) -> &'static [&'static str] {
        &[
            "User ID",
            "User Login",
            "Factor ID",
            "Factor Type",
            "Provider",
            "Vendor",
            "Status",
            "Created",
            "Last Updated",
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
            Err(okta_rs::OktaError::Api { status: 404, .. }) => return Ok(vec![]),
            Err(e) => return Err(e.into()),
        };

        let mut rows = Vec::new();
        for u in users {
            let factors = match self.client.users().list_factors(&u.id).await {
                Ok(f) => f,
                // User may have been deactivated mid-collection or have no factors.
                Err(okta_rs::OktaError::Api { status, .. }) if status == 404 || status == 403 => {
                    continue;
                }
                Err(e) => return Err(e.into()),
            };
            if factors.is_empty() {
                rows.push(vec![
                    u.id.clone(),
                    u.profile.login.clone(),
                    String::new(),
                    "NONE".to_string(),
                    String::new(),
                    String::new(),
                    "NOT_ENROLLED".to_string(),
                    String::new(),
                    String::new(),
                ]);
                continue;
            }
            for f in factors {
                rows.push(vec![
                    u.id.clone(),
                    u.profile.login.clone(),
                    f.id,
                    f.factor_type,
                    f.provider.unwrap_or_default(),
                    f.vendor_name.unwrap_or_default(),
                    f.status.unwrap_or_default(),
                    f.created.unwrap_or_default(),
                    f.last_updated.unwrap_or_default(),
                ]);
            }
        }
        Ok(rows)
    }
}
