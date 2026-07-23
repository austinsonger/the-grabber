use anyhow::Result;
use async_trait::async_trait;

use elastic_rs::ElasticClient;

use crate::evidence::CsvCollector;

pub struct ElasticRolesCollector {
    client: ElasticClient,
}

impl ElasticRolesCollector {
    pub fn new(client: ElasticClient) -> Self {
        Self { client }
    }
}

#[async_trait]
impl CsvCollector for ElasticRolesCollector {
    fn name(&self) -> &str {
        "Elastic Security Roles"
    }

    fn filename_prefix(&self) -> &str {
        "Elastic_Security_Roles"
    }

    fn headers(&self) -> &'static [&'static str] {
        &[
            "Role Name",
            "Cluster Privileges",
            "Index Patterns",
            "Index Privileges",
            "Application Privilege Count",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let roles = self.client.roles().find_all().await?;

        let rows = roles
            .into_iter()
            .map(|r| {
                vec![
                    r.name,
                    r.cluster_privileges.join("; "),
                    r.index_patterns.join("; "),
                    r.index_privileges.join("; "),
                    r.application_count.to_string(),
                ]
            })
            .collect();

        Ok(rows)
    }
}
