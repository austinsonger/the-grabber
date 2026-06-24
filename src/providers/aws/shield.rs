use anyhow::Result;
use async_trait::async_trait;
use aws_sdk_shield::Client as ShieldClient;

use crate::evidence::CsvCollector;

pub struct ShieldCollector {
    client: ShieldClient,
}

impl ShieldCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self {
            client: ShieldClient::new(config),
        }
    }
}

#[async_trait]
impl CsvCollector for ShieldCollector {
    fn name(&self) -> &str {
        "AWS Shield"
    }
    fn filename_prefix(&self) -> &str {
        "Shield_Config"
    }
    fn headers(&self) -> &'static [&'static str] {
        &["Record Type", "Identifier", "Detail Key", "Detail Value"]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let mut rows = Vec::new();

        match self.client.describe_subscription().send().await {
            Ok(s) => {
                if let Some(sub) = s.subscription() {
                    let start = sub.start_time().map(|d| d.to_string()).unwrap_or_default();
                    let end = sub.end_time().map(|d| d.to_string()).unwrap_or_default();
                    let auto_renew = sub
                        .auto_renew()
                        .map(|a| a.as_str().to_string())
                        .unwrap_or_default();
                    rows.push(vec![
                        "Subscription".into(),
                        String::new(),
                        "StartTime".into(),
                        start,
                    ]);
                    rows.push(vec![
                        "Subscription".into(),
                        String::new(),
                        "EndTime".into(),
                        end,
                    ]);
                    rows.push(vec![
                        "Subscription".into(),
                        String::new(),
                        "AutoRenew".into(),
                        auto_renew,
                    ]);
                } else {
                    rows.push(vec![
                        "Subscription".into(),
                        String::new(),
                        "Status".into(),
                        "Not Subscribed".into(),
                    ]);
                }
            }
            Err(e) => {
                eprintln!("  WARN: shield describe_subscription: {e:#}");
            }
        }

        match self
            .client
            .describe_emergency_contact_settings()
            .send()
            .await
        {
            Ok(c) => {
                for (i, contact) in c.emergency_contact_list().iter().enumerate() {
                    let email = contact.email_address().to_string();
                    let phone = contact.phone_number().unwrap_or("").to_string();
                    let notes = contact.contact_notes().unwrap_or("").to_string();
                    rows.push(vec![
                        "EmergencyContact".into(),
                        format!("contact-{i}"),
                        "Email".into(),
                        email,
                    ]);
                    rows.push(vec![
                        "EmergencyContact".into(),
                        format!("contact-{i}"),
                        "Phone".into(),
                        phone,
                    ]);
                    rows.push(vec![
                        "EmergencyContact".into(),
                        format!("contact-{i}"),
                        "Notes".into(),
                        notes,
                    ]);
                }
            }
            Err(e) => {
                eprintln!("  WARN: shield describe_emergency_contact_settings: {e:#}");
            }
        }

        let mut next_token: Option<String> = None;
        loop {
            let mut req = self.client.list_protections();
            if let Some(ref t) = next_token {
                req = req.next_token(t);
            }
            let resp = match req.send().await {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("  WARN: shield list_protections: {e:#}");
                    break;
                }
            };
            for prot in resp.protections() {
                let id = prot.id().unwrap_or("").to_string();
                let name = prot.name().unwrap_or("").to_string();
                let res_arn = prot.resource_arn().unwrap_or("").to_string();
                rows.push(vec!["Protection".into(), id.clone(), "Name".into(), name]);
                rows.push(vec!["Protection".into(), id, "ResourceArn".into(), res_arn]);
            }
            next_token = resp.next_token().map(|s| s.to_string());
            if next_token.is_none() {
                break;
            }
        }

        Ok(rows)
    }
}
