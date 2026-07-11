use anyhow::Result;
use async_trait::async_trait;
use okta_rs::OktaClient;

use crate::evidence::CsvCollector;

pub struct OktaUsersCollector {
    client: OktaClient,
}

impl OktaUsersCollector {
    pub fn new(client: OktaClient) -> Self {
        Self { client }
    }
}

#[async_trait]
impl CsvCollector for OktaUsersCollector {
    fn name(&self) -> &str {
        "Okta Users"
    }
    fn filename_prefix(&self) -> &str {
        "Okta_Users"
    }

    fn headers(&self) -> &'static [&'static str] {
        &[
            "User ID",
            "Login",
            "Email",
            "First Name",
            "Last Name",
            "Status",
            "Department",
            "Manager",
            "Created",
            "Activated",
            "Status Changed",
            "Last Login",
            "Last Updated",
            "Password Changed",
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
        let rows = users
            .into_iter()
            .map(|u| {
                vec![
                    u.id,
                    u.profile.login,
                    u.profile.email,
                    u.profile.first_name.unwrap_or_default(),
                    u.profile.last_name.unwrap_or_default(),
                    u.status,
                    u.profile.department.unwrap_or_default(),
                    u.profile.manager.unwrap_or_default(),
                    u.created.unwrap_or_default(),
                    u.activated.unwrap_or_default(),
                    u.status_changed.unwrap_or_default(),
                    u.last_login.unwrap_or_default(),
                    u.last_updated.unwrap_or_default(),
                    u.password_changed.unwrap_or_default(),
                ]
            })
            .collect();
        Ok(rows)
    }
}
