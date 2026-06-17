use anyhow::Result;
use async_trait::async_trait;
use aws_sdk_organizations::Client as OrgClient;

use crate::evidence::CsvCollector;

pub struct OrgDelegatedCollector {
    client: OrgClient,
}

impl OrgDelegatedCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self {
            client: OrgClient::new(config),
        }
    }
}

#[async_trait]
impl CsvCollector for OrgDelegatedCollector {
    fn name(&self) -> &str {
        "Organizations Delegated Admins & Services"
    }
    fn filename_prefix(&self) -> &str {
        "Organizations_Delegated_Services"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Type",
            "Service Principal",
            "Account ID",
            "Account Email",
            "Delegation Date",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let mut rows = Vec::new();

        // ── EnabledService: list_aws_service_access_for_organization ──────
        let mut next_token: Option<String> = None;
        loop {
            let mut req = self.client.list_aws_service_access_for_organization();
            if let Some(t) = next_token.as_ref() {
                req = req.next_token(t);
            }
            let resp = match req.send().await {
                Ok(r) => r,
                Err(e) => {
                    let msg = format!("{e:#}");
                    if msg.contains("AWSOrganizationsNotInUseException") {
                        return Ok(rows);
                    }
                    eprintln!(
                        "  WARN: Organizations list_aws_service_access_for_organization: {e:#}"
                    );
                    break;
                }
            };

            for svc in resp.enabled_service_principals() {
                let sp = svc.service_principal().unwrap_or("").to_string();
                let date = svc
                    .date_enabled()
                    .map(|t| t.to_string())
                    .unwrap_or_default();
                rows.push(vec![
                    "EnabledService".to_string(),
                    sp,
                    String::new(),
                    String::new(),
                    date,
                ]);
            }

            next_token = resp.next_token().map(|s| s.to_string());
            if next_token.is_none() {
                break;
            }
        }

        // ── DelegatedAdmin: list_delegated_administrators ─────────────────
        let mut admins: Vec<(String, String, String)> = Vec::new();
        let mut admin_token: Option<String> = None;
        loop {
            let mut req = self.client.list_delegated_administrators();
            if let Some(t) = admin_token.as_ref() {
                req = req.next_token(t);
            }
            let resp = match req.send().await {
                Ok(r) => r,
                Err(e) => {
                    let msg = format!("{e:#}");
                    if msg.contains("AWSOrganizationsNotInUseException") {
                        return Ok(rows);
                    }
                    eprintln!("  WARN: Organizations list_delegated_administrators: {e:#}");
                    break;
                }
            };

            for admin in resp.delegated_administrators() {
                let id = admin.id().unwrap_or("").to_string();
                let email = admin.email().unwrap_or("").to_string();
                let date = admin
                    .delegation_enabled_date()
                    .map(|t| t.to_string())
                    .unwrap_or_default();
                admins.push((id, email, date));
            }

            admin_token = resp.next_token().map(|s| s.to_string());
            if admin_token.is_none() {
                break;
            }
        }

        for (admin_id, admin_email, admin_date) in admins {
            // For each admin, list delegated services
            let mut svc_token: Option<String> = None;
            let mut had_services = false;
            loop {
                let mut req = self
                    .client
                    .list_delegated_services_for_account()
                    .account_id(&admin_id);
                if let Some(t) = svc_token.as_ref() {
                    req = req.next_token(t);
                }
                let resp = match req.send().await {
                    Ok(r) => r,
                    Err(e) => {
                        eprintln!(
                            "  WARN: Organizations list_delegated_services_for_account({admin_id}): {e:#}"
                        );
                        break;
                    }
                };

                for ds in resp.delegated_services() {
                    had_services = true;
                    let sp = ds.service_principal().unwrap_or("").to_string();
                    let date = ds
                        .delegation_enabled_date()
                        .map(|t| t.to_string())
                        .unwrap_or_else(|| admin_date.clone());
                    rows.push(vec![
                        "DelegatedAdmin".to_string(),
                        sp,
                        admin_id.clone(),
                        admin_email.clone(),
                        date,
                    ]);
                }

                svc_token = resp.next_token().map(|s| s.to_string());
                if svc_token.is_none() {
                    break;
                }
            }

            if !had_services {
                rows.push(vec![
                    "DelegatedAdmin".to_string(),
                    String::new(),
                    admin_id,
                    admin_email,
                    admin_date,
                ]);
            }
        }

        Ok(rows)
    }
}
