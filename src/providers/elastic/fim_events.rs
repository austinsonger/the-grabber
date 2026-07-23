use anyhow::Result;
use async_trait::async_trait;
use chrono::{DateTime, Utc};

use elastic_rs::ElasticClient;

use crate::evidence::CsvCollector;

pub struct ElasticFimEventsCollector {
    client: ElasticClient,
}

impl ElasticFimEventsCollector {
    pub fn new(client: ElasticClient) -> Self {
        Self { client }
    }
}

#[async_trait]
impl CsvCollector for ElasticFimEventsCollector {
    fn name(&self) -> &str {
        "Elastic File Integrity Monitoring Events"
    }

    fn filename_prefix(&self) -> &str {
        "Elastic_File_Integrity_Monitoring_Events"
    }

    fn headers(&self) -> &'static [&'static str] {
        &[
            "Event ID",
            "File Path",
            "Event Action",
            "File Hash SHA256",
            "Host Name",
            "User Name",
            "Timestamp",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        // Same fallback rationale as the alerts collector: non-AWS
        // Collectors runs always supply a date window in practice, but
        // default to the last 90 days if this is ever invoked without one.
        let (start_secs, end_secs) = dates.unwrap_or_else(|| {
            let now = Utc::now();
            (
                (now - chrono::Duration::days(90)).timestamp(),
                now.timestamp(),
            )
        });
        let start = DateTime::<Utc>::from_timestamp(start_secs, 0)
            .unwrap_or_else(Utc::now)
            .to_rfc3339();
        let end = DateTime::<Utc>::from_timestamp(end_secs, 0)
            .unwrap_or_else(Utc::now)
            .to_rfc3339();

        let events = self.client.fim().search_range(&start, &end).await?;

        let rows = events
            .into_iter()
            .map(|e| {
                vec![
                    e.id.clone(),
                    e.field_string("file.path"),
                    e.field_string("event.action"),
                    e.field_string("file.hash.sha256"),
                    e.field_string("host.name"),
                    e.field_string("user.name"),
                    e.field_string("@timestamp"),
                ]
            })
            .collect();

        Ok(rows)
    }
}
