use anyhow::Result;
use async_trait::async_trait;
use okta_rs::OktaClient;

use crate::evidence::CsvCollector;

fn is_broker_mode(sign_on_mode: &str) -> bool {
    let upper = sign_on_mode.to_uppercase();
    upper == "SECURE_PASSWORD_STORE" || upper == "AUTO_LOGIN" || upper.contains("SWA")
}

pub struct OktaSharedAccountBrokerConfigCollector {
    client: OktaClient,
}

impl OktaSharedAccountBrokerConfigCollector {
    pub fn new(client: OktaClient) -> Self {
        Self { client }
    }
}

#[async_trait]
impl CsvCollector for OktaSharedAccountBrokerConfigCollector {
    fn name(&self) -> &str {
        "Okta Shared Account Broker Config"
    }
    fn filename_prefix(&self) -> &str {
        "Okta_Shared_Account_Broker_Config"
    }
    fn headers(&self) -> &'static [&'static str] {
        &["App ID", "Label", "Sign-On Mode", "Status", "Users Assigned"]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let apps = match self.client.apps().list_all().await {
            Ok(a) => a,
            Err(okta_rs::OktaError::Api { status: 404, .. }) => return Ok(vec![]),
            Err(e) => return Err(e.into()),
        };

        let rows = apps
            .into_iter()
            .filter(|a| {
                a.sign_on_mode
                    .as_deref()
                    .map(is_broker_mode)
                    .unwrap_or(false)
            })
            .map(|a| {
                vec![
                    a.id,
                    a.label,
                    a.sign_on_mode.unwrap_or_default(),
                    a.status,
                    String::new(),
                ]
            })
            .collect();

        Ok(rows)
    }
}
