use anyhow::Result;
use async_trait::async_trait;
use jumpcloud_rs::JumpCloudClient;

use crate::evidence::CsvCollector;

pub struct JumpCloudUsersCollector {
    client: JumpCloudClient,
}

impl JumpCloudUsersCollector {
    pub fn new(client: JumpCloudClient) -> Self {
        Self { client }
    }
}

#[async_trait]
impl CsvCollector for JumpCloudUsersCollector {
    fn name(&self) -> &str {
        "JumpCloud Users"
    }
    fn filename_prefix(&self) -> &str {
        "JumpCloud_Users"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "User ID",
            "Username",
            "Email",
            "First Name",
            "Last Name",
            "Activated",
            "Suspended",
            "Account Locked",
            "MFA Configured",
            "MFA Exclusion",
            "Configured Factors",
            "Password Expired",
            "Password Expiration Date",
            "Created",
            "Department",
            "Job Title",
            "Manager",
            "Last Login Attempt",
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
                vec![
                    u.id,
                    u.username,
                    u.email,
                    u.firstname,
                    u.lastname,
                    u.activated.to_string(),
                    u.suspended.to_string(),
                    u.account_locked.to_string(),
                    u.mfa.configured.to_string(),
                    u.mfa.exclusion.to_string(),
                    u.mfa.configured_factors.join(";"),
                    u.password_expired.to_string(),
                    u.password_expiration_date.unwrap_or_default(),
                    u.created.unwrap_or_default(),
                    u.department.unwrap_or_default(),
                    u.job_title.unwrap_or_default(),
                    u.manager.unwrap_or_default(),
                    u.last_login_attempt.unwrap_or_default(),
                ]
            })
            .collect();
        Ok(rows)
    }
}
