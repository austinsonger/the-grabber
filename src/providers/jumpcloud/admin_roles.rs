use anyhow::Result;
use async_trait::async_trait;
use jumpcloud_rs::JumpCloudClient;

use crate::evidence::CsvCollector;

pub struct JumpCloudAdminRolesCollector {
    client: JumpCloudClient,
    org_id: String,
}

impl JumpCloudAdminRolesCollector {
    pub fn new(client: JumpCloudClient, org_id: String) -> Self {
        Self { client, org_id }
    }
}

#[async_trait]
impl CsvCollector for JumpCloudAdminRolesCollector {
    fn name(&self) -> &str {
        "JumpCloud Admin Roles"
    }
    fn filename_prefix(&self) -> &str {
        "JumpCloud_AdminRoles"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Admin ID",
            "Email",
            "First Name",
            "Last Name",
            "Role",
            "Role Name",
            "MFA Enabled",
            "Created",
        ]
    }
    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let admins = match self.client.administrators().list_all(&self.org_id).await {
            Ok(a) => a,
            Err(jumpcloud_rs::JumpCloudError::Api { status: 404, .. }) => return Ok(vec![]),
            Err(e) => return Err(e.into()),
        };
        let rows = admins
            .into_iter()
            .map(|a| {
                vec![
                    a.id,
                    a.email,
                    a.firstname,
                    a.lastname,
                    a.role.unwrap_or_default(),
                    a.role_name.unwrap_or_default(),
                    a.enable_mfa.to_string(),
                    a.created.unwrap_or_default(),
                ]
            })
            .collect();
        Ok(rows)
    }
}
