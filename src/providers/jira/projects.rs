use anyhow::Result;
use async_trait::async_trait;
use jira_rs::JiraClient;

use crate::evidence::CsvCollector;

pub struct JiraProjectsCollector {
    client: JiraClient,
}

impl JiraProjectsCollector {
    pub fn new(client: JiraClient) -> Self {
        Self { client }
    }
}

#[async_trait]
impl CsvCollector for JiraProjectsCollector {
    fn name(&self) -> &str {
        "Jira Projects"
    }
    fn filename_prefix(&self) -> &str {
        "Jira_Projects"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Project ID",
            "Key",
            "Name",
            "Type",
            "Style",
            "Lead Account ID",
            "Lead Name",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let projects = match self.client.projects().list_all().await {
            Ok(p) => p,
            Err(jira_rs::JiraError::Api { status: 404, .. }) => return Ok(vec![]),
            Err(e) => return Err(e.into()),
        };
        let rows = projects
            .into_iter()
            .map(|p| {
                let (lead_id, lead_name) = match p.lead {
                    Some(l) => (l.account_id, l.display_name),
                    None => (String::new(), String::new()),
                };
                vec![
                    p.id,
                    p.key,
                    p.name,
                    p.project_type_key,
                    p.style.unwrap_or_default(),
                    lead_id,
                    lead_name,
                ]
            })
            .collect();
        Ok(rows)
    }
}
