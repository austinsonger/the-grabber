use anyhow::Result;
use async_trait::async_trait;
use chrono::DateTime;

use elastic_rs::ElasticClient;

use crate::evidence::CsvCollector;

pub struct ElasticCasesCollector {
    client: ElasticClient,
}

impl ElasticCasesCollector {
    pub fn new(client: ElasticClient) -> Self {
        Self { client }
    }
}

#[async_trait]
impl CsvCollector for ElasticCasesCollector {
    fn name(&self) -> &str {
        "Elastic Security Cases"
    }

    fn filename_prefix(&self) -> &str {
        "Elastic_Security_Cases"
    }

    fn headers(&self) -> &'static [&'static str] {
        &[
            "Case ID",
            "Title",
            "Status",
            "Severity",
            "Tags",
            "Total Alerts",
            "Created At",
            "Created By",
            "Updated At",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let cases = self.client.cases().find_all().await?;

        let rows = cases
            .into_iter()
            .filter(|c| match dates {
                None => true,
                Some((start, end)) => DateTime::parse_from_rfc3339(&c.created_at)
                    .map(|ts| {
                        let secs = ts.timestamp();
                        secs >= start && secs <= end
                    })
                    .unwrap_or(true),
            })
            .map(|c| {
                let created_by = c
                    .created_by
                    .full_name
                    .or(c.created_by.username)
                    .unwrap_or_default();
                vec![
                    c.id,
                    c.title,
                    c.status,
                    c.severity,
                    c.tags.join("; "),
                    c.total_alerts.to_string(),
                    c.created_at,
                    created_by,
                    c.updated_at.unwrap_or_default(),
                ]
            })
            .collect();

        Ok(rows)
    }
}
