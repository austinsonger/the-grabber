use anyhow::Result;
use async_trait::async_trait;
use aws_sdk_organizations::Client as OrgClient;

use crate::evidence::CsvCollector;

pub struct OrgConfigCollector {
    client: OrgClient,
}

impl OrgConfigCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self { client: OrgClient::new(config) }
    }
}

#[async_trait]
impl CsvCollector for OrgConfigCollector {
    fn name(&self) -> &str { "AWS Organizations Configuration" }
    fn filename_prefix(&self) -> &str { "AWS_Organizations_Config" }
    fn headers(&self) -> &'static [&'static str] {
        &["Org ID", "Master Account ID", "Master Account Email", "Feature Set",
          "Total Accounts", "Root ID", "SCPs Enabled"]
    }

    async fn collect_rows(&self, _account_id: &str, _region: &str) -> Result<Vec<Vec<String>>> {
        let org = match self.client.describe_organization().send().await {
            Ok(r) => r,
            Err(e) => {
                eprintln!("  WARN: Organizations describe_organization (not org master?): {e:#}");
                return Ok(vec![]);
            }
        };

        let org_info = match org.organization() {
            Some(o) => o,
            None => return Ok(vec![]),
        };

        let org_id        = org_info.id().unwrap_or("").to_string();
        let master_acct   = org_info.master_account_id().unwrap_or("").to_string();
        let master_email  = org_info.master_account_email().unwrap_or("").to_string();
        let feature_set   = org_info.feature_set()
            .map(|f| f.as_str().to_string())
            .unwrap_or_default();
        let scps_enabled  = org_info.available_policy_types()
            .iter()
            .any(|pt| pt.r#type().map(|t| t.as_str() == "SERVICE_CONTROL_POLICY").unwrap_or(false))
            .to_string();

        // Count accounts
        let mut account_count = 0usize;
        let mut next_token: Option<String> = None;
        loop {
            let mut req = self.client.list_accounts();
            if let Some(ref t) = next_token {
                req = req.next_token(t);
            }
            let resp = match req.send().await {
                Ok(r) => r,
                Err(_) => break,
            };
            account_count += resp.accounts().len();
            next_token = resp.next_token().map(|s| s.to_string());
            if next_token.is_none() { break; }
        }

        // Get root ID
        let root_id = match self.client.list_roots().send().await {
            Ok(r) => r.roots().first()
                .and_then(|root| root.id())
                .unwrap_or("")
                .to_string(),
            Err(_) => String::new(),
        };

        Ok(vec![vec![
            org_id,
            master_acct,
            master_email,
            feature_set,
            account_count.to_string(),
            root_id,
            scps_enabled,
        ]])
    }
}
