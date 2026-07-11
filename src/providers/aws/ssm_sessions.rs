use anyhow::Result;
use async_trait::async_trait;
use aws_sdk_ssm::types::SessionState;
use aws_sdk_ssm::Client as SsmClient;

use crate::evidence::CsvCollector;

pub struct SsmSessionsCollector {
    client: SsmClient,
}

impl SsmSessionsCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self {
            client: SsmClient::new(config),
        }
    }

    async fn pull(&self, state: SessionState, rows: &mut Vec<Vec<String>>) {
        let mut next_token: Option<String> = None;
        loop {
            let mut req = self.client.describe_sessions().state(state.clone());
            if let Some(ref t) = next_token {
                req = req.next_token(t);
            }
            let resp = match req.send().await {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("  WARN: ssm describe_sessions({state:?}): {e:#}");
                    break;
                }
            };
            for s in resp.sessions() {
                rows.push(vec![
                    s.session_id().unwrap_or("").to_string(),
                    s.target().unwrap_or("").to_string(),
                    s.owner().unwrap_or("").to_string(),
                    s.document_name().unwrap_or("").to_string(),
                    s.start_date().map(|d| d.to_string()).unwrap_or_default(),
                    s.end_date().map(|d| d.to_string()).unwrap_or_default(),
                    s.status()
                        .map(|st| st.as_str().to_string())
                        .unwrap_or_default(),
                    s.reason().unwrap_or("").to_string(),
                    s.details().unwrap_or("").to_string(),
                ]);
            }
            next_token = resp.next_token().map(|s| s.to_string());
            if next_token.is_none() {
                break;
            }
        }
    }
}

#[async_trait]
impl CsvCollector for SsmSessionsCollector {
    fn name(&self) -> &str {
        "SSM Session Manager Logs"
    }
    fn filename_prefix(&self) -> &str {
        "SSM_Sessions"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Session ID",
            "Target",
            "Owner",
            "Document",
            "Start",
            "End",
            "Status",
            "Reason",
            "Details",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let mut rows = Vec::new();
        self.pull(SessionState::History, &mut rows).await;
        self.pull(SessionState::Active, &mut rows).await;

        match self
            .client
            .describe_document()
            .name("SSM-SessionManagerRunShell")
            .send()
            .await
        {
            Ok(d) => {
                if let Some(doc) = d.document() {
                    rows.push(vec![
                        "DOCUMENT".into(),
                        doc.name().unwrap_or("").to_string(),
                        doc.owner().unwrap_or("").to_string(),
                        doc.document_version().unwrap_or("").to_string(),
                        doc.created_date()
                            .map(|d| d.to_string())
                            .unwrap_or_default(),
                        String::new(),
                        doc.status()
                            .map(|s| s.as_str().to_string())
                            .unwrap_or_default(),
                        String::new(),
                        doc.description().unwrap_or("").to_string(),
                    ]);
                }
            }
            Err(e) => {
                eprintln!("  WARN: ssm describe_document(SSM-SessionManagerRunShell): {e:#}");
            }
        }

        Ok(rows)
    }
}
