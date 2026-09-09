use anyhow::Result;
use async_trait::async_trait;
use jumpcloud_rs::JumpCloudClient;

use crate::evidence::CsvCollector;

pub struct JumpCloudDisabledUsersCollector {
    client: JumpCloudClient,
}

impl JumpCloudDisabledUsersCollector {
    pub fn new(client: JumpCloudClient) -> Self {
        Self { client }
    }
}

fn disable_reason(suspended: bool, locked: bool, activated: bool) -> String {
    let mut reasons: Vec<&str> = Vec::new();
    if suspended {
        reasons.push("suspended");
    }
    if locked {
        reasons.push("account_locked");
    }
    if !activated {
        reasons.push("never_activated");
    }
    reasons.join(";")
}

#[async_trait]
impl CsvCollector for JumpCloudDisabledUsersCollector {
    fn name(&self) -> &str {
        "JumpCloud Disabled Users"
    }
    fn filename_prefix(&self) -> &str {
        "JumpCloud_DisabledUsers"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "User ID",
            "Username",
            "Email",
            "First Name",
            "Last Name",
            "Disable Reason",
            "Suspended",
            "Account Locked",
            "Activated",
            "Password Expired",
            "Password Expiration Date",
            "Last Login Attempt",
            "Created",
            "Department",
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
            .filter(|u| u.suspended || u.account_locked || !u.activated)
            .map(|u| {
                let reason = disable_reason(u.suspended, u.account_locked, u.activated);
                vec![
                    u.id,
                    u.username,
                    u.email,
                    u.firstname,
                    u.lastname,
                    reason,
                    u.suspended.to_string(),
                    u.account_locked.to_string(),
                    u.activated.to_string(),
                    u.password_expired.to_string(),
                    u.password_expiration_date.unwrap_or_default(),
                    u.last_login_attempt.unwrap_or_default(),
                    u.created.unwrap_or_default(),
                    u.department.unwrap_or_default(),
                ]
            })
            .collect();
        Ok(rows)
    }
}
