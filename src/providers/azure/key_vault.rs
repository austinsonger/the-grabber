//! Azure Key Vault collector.
//!
//! Maps to AWS KMS + SecretsManager.  Uses `azure_mgmt_keyvault` to enumerate
//! all vaults in the subscription.

use std::sync::Arc;

use anyhow::{Context, Result};
use async_trait::async_trait;
use azure_mgmt_keyvault::Client as KeyVaultClient;
use futures::StreamExt;
use serde_json::{json, Value};

use crate::evidence::JsonCollector;

pub struct KeyVaultCollector {
    client:          KeyVaultClient,
    subscription_id: String,
}

impl KeyVaultCollector {
    pub fn new(
        credential: Arc<dyn azure_core::auth::TokenCredential>,
        subscription_id: String,
    ) -> Self {
        Self {
            client: KeyVaultClient::builder(credential).build(),
            subscription_id,
        }
    }
}

#[async_trait]
impl JsonCollector for KeyVaultCollector {
    fn name(&self) -> &str { "Azure Key Vault" }
    fn filename_prefix(&self) -> &str { "Azure_Key_Vaults" }

    async fn collect_records(
        &self,
        _account_id: &str,
        _region: &str,
    ) -> Result<Vec<Value>> {
        let mut records = Vec::new();

        let mut stream = self.client
            .vaults_client()
            .list_by_subscription(&self.subscription_id)
            .into_stream();

        while let Some(page) = stream.next().await {
            let page = page.context("Key Vault: list page failed")?;
            for vault in page.value {
                let vault_val = serde_json::to_value(&vault).unwrap_or(Value::Null);
                records.push(json!({ "vault": vault_val }));
            }
        }

        Ok(records)
    }
}
