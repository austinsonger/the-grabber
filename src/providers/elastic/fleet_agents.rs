use anyhow::Result;
use async_trait::async_trait;

use elastic_rs::ElasticClient;

use crate::evidence::CsvCollector;

pub struct ElasticFleetAgentsCollector {
    client: ElasticClient,
}

impl ElasticFleetAgentsCollector {
    pub fn new(client: ElasticClient) -> Self {
        Self { client }
    }
}

#[async_trait]
impl CsvCollector for ElasticFleetAgentsCollector {
    fn name(&self) -> &str {
        "Elastic Fleet Agents"
    }

    fn filename_prefix(&self) -> &str {
        "Elastic_Fleet_Agents"
    }

    fn headers(&self) -> &'static [&'static str] {
        &[
            "Agent ID",
            "Policy ID",
            "Policy Revision",
            "Active",
            "Status",
            "Last Checkin Status",
            "Agent Version",
            "Hostname",
            "Enrolled At",
            "Last Checkin",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let agents = self.client.agents().find_all().await?;

        let rows = agents
            .into_iter()
            .map(|a| {
                let hostname = a
                    .local_metadata
                    .as_ref()
                    .and_then(|m| m.get("host"))
                    .and_then(|h| h.get("hostname"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();

                vec![
                    a.id,
                    a.policy_id.unwrap_or_default(),
                    a.policy_revision.map(|n| n.to_string()).unwrap_or_default(),
                    if a.active { "YES" } else { "NO" }.to_string(),
                    a.status.unwrap_or_default(),
                    a.last_checkin_status.unwrap_or_default(),
                    a.agent.and_then(|v| v.version).unwrap_or_default(),
                    hostname,
                    a.enrolled_at.unwrap_or_default(),
                    a.last_checkin.unwrap_or_default(),
                ]
            })
            .collect();

        Ok(rows)
    }
}
