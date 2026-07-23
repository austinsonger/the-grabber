use std::collections::HashMap;

use anyhow::Result;
use async_trait::async_trait;
use github_rs::{GithubClient, GithubError};

use crate::evidence::CsvCollector;

pub struct GithubMembersCollector {
    pub(crate) client: GithubClient,
}

impl GithubMembersCollector {
    pub fn new(client: GithubClient) -> Self {
        Self { client }
    }
}

#[async_trait]
impl CsvCollector for GithubMembersCollector {
    fn name(&self) -> &str {
        "GitHub Org Members"
    }
    fn filename_prefix(&self) -> &str {
        "Github_Org_Members"
    }
    fn headers(&self) -> &'static [&'static str] {
        &["Login", "User ID", "Role", "Site Admin", "2FA Disabled"]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let admins = self.client.members().list_by_role("admin").await?;
        let members = self.client.members().list_by_role("member").await?;

        let mut role_by_login: HashMap<String, &'static str> = HashMap::new();
        for u in &admins {
            role_by_login.insert(u.login.clone(), "admin");
        }
        for u in &members {
            role_by_login.entry(u.login.clone()).or_insert("member");
        }

        // 2FA-disabled requires an org-owner token — a 403 here means "we
        // can't tell", not "collection failed"; every row gets "unknown".
        let disabled_2fa: Option<std::collections::HashSet<String>> =
            match self.client.members().list_2fa_disabled().await {
                Ok(users) => Some(users.into_iter().map(|u| u.login).collect()),
                Err(GithubError::Api { status: 403, .. }) => None,
                Err(GithubError::Api { status: 404, .. }) => None,
                Err(e) => return Err(e.into()),
            };

        let mut merged: HashMap<String, (i64, bool)> = HashMap::new();
        for u in admins.into_iter().chain(members.into_iter()) {
            merged.entry(u.login).or_insert((u.id, u.site_admin));
        }

        let mut rows: Vec<Vec<String>> = merged
            .into_iter()
            .map(|(login, (id, site_admin))| {
                let role = role_by_login.get(&login).copied().unwrap_or("member");
                let two_fa = match &disabled_2fa {
                    Some(set) => {
                        if set.contains(&login) {
                            "true"
                        } else {
                            "false"
                        }
                    }
                    None => "unknown",
                };
                vec![
                    login,
                    id.to_string(),
                    role.to_string(),
                    site_admin.to_string(),
                    two_fa.to_string(),
                ]
            })
            .collect();
        rows.sort_by(|a, b| a[0].cmp(&b[0]));
        Ok(rows)
    }
}
