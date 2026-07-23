use anyhow::Result;
use async_trait::async_trait;

use elastic_rs::ElasticClient;

use crate::evidence::CsvCollector;

pub struct ElasticDetectionRulesCollector {
    client: ElasticClient,
}

impl ElasticDetectionRulesCollector {
    pub fn new(client: ElasticClient) -> Self {
        Self { client }
    }
}

#[async_trait]
impl CsvCollector for ElasticDetectionRulesCollector {
    fn name(&self) -> &str {
        "Elastic Detection Rules"
    }

    fn filename_prefix(&self) -> &str {
        "Elastic_Detection_Rules"
    }

    fn headers(&self) -> &'static [&'static str] {
        &[
            "Rule ID",
            "Rule UUID",
            "Rule Name",
            "Type",
            "Enabled",
            "Severity",
            "Risk Score",
            "Interval",
            "Index Patterns",
            "Tags",
            "Author",
            "Max Signals",
            "False Positives",
            "References",
            "Created At",
            "Updated At",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let rules = self.client.rules().find_all().await?;

        let rows = rules
            .into_iter()
            .map(|r| {
                vec![
                    r.rule_id,
                    r.id,
                    r.name,
                    r.rule_type,
                    if r.enabled { "YES" } else { "NO" }.to_string(),
                    r.severity,
                    r.risk_score.to_string(),
                    r.interval,
                    r.index.unwrap_or_default().join("; "),
                    r.tags.join("; "),
                    r.author.join("; "),
                    r.max_signals.map(|n| n.to_string()).unwrap_or_default(),
                    r.false_positives.join("; "),
                    r.references.join("; "),
                    r.created_at,
                    r.updated_at,
                ]
            })
            .collect();

        Ok(rows)
    }
}
