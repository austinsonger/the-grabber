use anyhow::Result;
use async_trait::async_trait;

use elastic_rs::ElasticClient;

use crate::evidence::CsvCollector;

pub struct ElasticUsersCollector {
    client: ElasticClient,
}

impl ElasticUsersCollector {
    pub fn new(client: ElasticClient) -> Self {
        Self { client }
    }
}

#[async_trait]
impl CsvCollector for ElasticUsersCollector {
    fn name(&self) -> &str {
        "Elastic Security Users"
    }

    fn filename_prefix(&self) -> &str {
        "Elastic_Security_Users"
    }

    fn headers(&self) -> &'static [&'static str] {
        &["Username", "Full Name", "Email", "Enabled", "Roles"]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let users = self.client.users().find_all().await?;

        let rows = users
            .into_iter()
            .map(|u| {
                vec![
                    u.username,
                    u.full_name.unwrap_or_default(),
                    u.email.unwrap_or_default(),
                    if u.enabled { "YES" } else { "NO" }.to_string(),
                    u.roles.join("; "),
                ]
            })
            .collect();

        Ok(rows)
    }
}
