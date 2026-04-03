use anyhow::Result;
use async_trait::async_trait;
use aws_sdk_account::Client as AccountClient;
use aws_sdk_account::types::AlternateContactType;
use aws_sdk_iam::Client as IamClient;


use crate::evidence::CsvCollector;

// ══════════════════════════════════════════════════════════════════════════════
// 1. Account Alternate Contacts
// ══════════════════════════════════════════════════════════════════════════════

pub struct AccountContactsCollector {
    client: AccountClient,
}

impl AccountContactsCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self { client: AccountClient::new(config) }
    }
}

#[async_trait]
impl CsvCollector for AccountContactsCollector {
    fn name(&self) -> &str { "Account Alternate Contacts" }
    fn filename_prefix(&self) -> &str { "Account_Contacts_Config" }
    fn headers(&self) -> &'static [&'static str] {
        &["Contact Type", "Name", "Email", "Phone", "Title"]
    }

    async fn collect_rows(&self, _account_id: &str, _region: &str, _dates: Option<(i64, i64)>) -> Result<Vec<Vec<String>>> {
        let mut rows = Vec::new();
        let types = [
            AlternateContactType::Security,
            AlternateContactType::Operations,
            AlternateContactType::Billing,
        ];

        for contact_type in &types {
            let type_str = contact_type.as_str().to_string();
            match self.client
                .get_alternate_contact()
                .alternate_contact_type(contact_type.clone())
                .send()
                .await
            {
                Ok(r) => {
                    if let Some(contact) = r.alternate_contact() {
                        rows.push(vec![
                            type_str,
                            contact.name().unwrap_or("").to_string(),
                            contact.email_address().unwrap_or("").to_string(),
                            contact.phone_number().unwrap_or("").to_string(),
                            contact.title().unwrap_or("").to_string(),
                        ]);
                    } else {
                        rows.push(vec![type_str, "Not Set".to_string(),
                            String::new(), String::new(), String::new()]);
                    }
                }
                Err(e) => {
                    let msg = format!("{e}");
                    if msg.contains("ResourceNotFoundException") {
                        rows.push(vec![type_str, "Not Configured".to_string(),
                            String::new(), String::new(), String::new()]);
                    } else {
                        eprintln!("  WARN: Account get_alternate_contact {type_str}: {e:#}");
                    }
                }
            }
        }

        Ok(rows)
    }
}

// ══════════════════════════════════════════════════════════════════════════════
// 2. SAML / Identity Provider Config
// ══════════════════════════════════════════════════════════════════════════════

pub struct SamlProviderCollector {
    client: IamClient,
}

impl SamlProviderCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self { client: IamClient::new(config) }
    }
}

#[async_trait]
impl CsvCollector for SamlProviderCollector {
    fn name(&self) -> &str { "IAM SAML Identity Providers" }
    fn filename_prefix(&self) -> &str { "IAM_Identity_Provider_Config" }
    fn headers(&self) -> &'static [&'static str] {
        &["Provider ARN", "Provider Name", "Created Date", "Valid Until", "Metadata Length (bytes)"]
    }

    async fn collect_rows(&self, _account_id: &str, _region: &str, _dates: Option<(i64, i64)>) -> Result<Vec<Vec<String>>> {
        let mut rows = Vec::new();

        let list_resp = match self.client.list_saml_providers().send().await {
            Ok(r) => r,
            Err(e) => {
                eprintln!("  WARN: IAM list_saml_providers: {e:#}");
                return Ok(rows);
            }
        };

        for provider in list_resp.saml_provider_list() {
            let arn = provider.arn().unwrap_or("").to_string();
            let name = arn.split('/').last().unwrap_or("").to_string();

            let (created, valid_until, meta_len) = match self.client
                .get_saml_provider()
                .saml_provider_arn(&arn)
                .send()
                .await
            {
                Ok(r) => {
                    let created = r.create_date()
                        .map(|d| {
                            chrono::DateTime::<chrono::Utc>::from_timestamp(d.secs(), 0)
                                .map(|c| c.to_rfc3339())
                                .unwrap_or_default()
                        })
                        .unwrap_or_default();
                    let valid = r.valid_until()
                        .map(|d| {
                            chrono::DateTime::<chrono::Utc>::from_timestamp(d.secs(), 0)
                                .map(|c| c.to_rfc3339())
                                .unwrap_or_default()
                        })
                        .unwrap_or_default();
                    let meta_len = r.saml_metadata_document()
                        .map(|m| m.len().to_string())
                        .unwrap_or_default();
                    (created, valid, meta_len)
                }
                Err(e) => {
                    eprintln!("  WARN: IAM get_saml_provider {arn}: {e:#}");
                    (String::new(), String::new(), String::new())
                }
            };

            rows.push(vec![arn, name, created, valid_until, meta_len]);
        }

        Ok(rows)
    }
}

// ══════════════════════════════════════════════════════════════════════════════
// 3. IAM Account Summary
// ══════════════════════════════════════════════════════════════════════════════

pub struct IamAccountSummaryCollector {
    client: IamClient,
}

impl IamAccountSummaryCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self { client: IamClient::new(config) }
    }
}

#[async_trait]
impl CsvCollector for IamAccountSummaryCollector {
    fn name(&self) -> &str { "IAM Account Summary" }
    fn filename_prefix(&self) -> &str { "IAM_Account_Summary" }
    fn headers(&self) -> &'static [&'static str] {
        &["Key", "Value"]
    }

    async fn collect_rows(&self, _account_id: &str, _region: &str, _dates: Option<(i64, i64)>) -> Result<Vec<Vec<String>>> {
        let resp = match self.client.get_account_summary().send().await {
            Ok(r) => r,
            Err(e) => {
                eprintln!("  WARN: IAM get_account_summary: {e:#}");
                return Ok(vec![]);
            }
        };

        let mut rows: Vec<Vec<String>> = resp.summary_map()
            .map(|m| {
                let mut pairs: Vec<Vec<String>> = m.iter()
                    .map(|(k, v)| vec![k.as_str().to_string(), v.to_string()])
                    .collect();
                pairs.sort_by(|a, b| a[0].cmp(&b[0]));
                pairs
            })
            .unwrap_or_default();

        if rows.is_empty() {
            rows.push(vec!["NoData".to_string(), "0".to_string()]);
        }

        Ok(rows)
    }
}
