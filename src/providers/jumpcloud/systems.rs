use anyhow::Result;
use async_trait::async_trait;
use jumpcloud_rs::JumpCloudClient;

use crate::evidence::CsvCollector;

pub struct JumpCloudSystemsCollector {
    client: JumpCloudClient,
}

impl JumpCloudSystemsCollector {
    pub fn new(client: JumpCloudClient) -> Self {
        Self { client }
    }
}

#[async_trait]
impl CsvCollector for JumpCloudSystemsCollector {
    fn name(&self) -> &str {
        "JumpCloud Systems"
    }
    fn filename_prefix(&self) -> &str {
        "JumpCloud_Systems"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "System ID",
            "Hostname",
            "Display Name",
            "OS",
            "OS Version",
            "Arch",
            "Agent Version",
            "Active",
            "Created",
            "Last Contact",
            "Remote IP",
            "FDE Active",
            "FDE Key Present",
            "SSH Password Auth",
            "SSH Root Login",
        ]
    }
    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let systems = match self.client.systems().list_all().await {
            Ok(s) => s,
            Err(jumpcloud_rs::JumpCloudError::Api { status: 404, .. }) => return Ok(vec![]),
            Err(e) => return Err(e.into()),
        };
        let rows = systems
            .into_iter()
            .map(|s| {
                let (fde_active, fde_key) = s
                    .fde
                    .as_ref()
                    .map(|f| (f.active.to_string(), f.key_present.to_string()))
                    .unwrap_or_else(|| ("".to_string(), "".to_string()));
                vec![
                    s.id,
                    s.hostname,
                    s.display_name.unwrap_or_default(),
                    s.os,
                    s.version.unwrap_or_default(),
                    s.arch.unwrap_or_default(),
                    s.agent_version.unwrap_or_default(),
                    s.active.to_string(),
                    s.created.unwrap_or_default(),
                    s.last_contact.unwrap_or_default(),
                    s.remote_ip.unwrap_or_default(),
                    fde_active,
                    fde_key,
                    s.allow_ssh_password_authentication.to_string(),
                    s.allow_ssh_root_login.to_string(),
                ]
            })
            .collect();
        Ok(rows)
    }
}
