use anyhow::Result;
use async_trait::async_trait;
use aws_sdk_resourceexplorer2::Client as ReClient;

use crate::evidence::CsvCollector;

pub struct ResourceExplorerCollector {
    client: ReClient,
}

impl ResourceExplorerCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self {
            client: ReClient::new(config),
        }
    }
}

fn is_benign(err: &str) -> bool {
    err.contains("AccessDenied")
        || err.contains("ResourceNotFoundException")
        || err.contains("ValidationException")
        || err.contains("not enabled")
}

#[async_trait]
impl CsvCollector for ResourceExplorerCollector {
    fn name(&self) -> &str {
        "Resource Explorer Indexes & Views"
    }
    fn filename_prefix(&self) -> &str {
        "ResourceExplorer_Indexes"
    }
    fn headers(&self) -> &'static [&'static str] {
        &["Type", "ARN", "Index Type", "Region", "State", "Created At"]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let mut rows = Vec::new();

        // ── Indexes ───────────────────────────────────────────────────
        let mut idx_token: Option<String> = None;
        loop {
            let mut req = self.client.list_indexes();
            if let Some(t) = idx_token.as_ref() {
                req = req.next_token(t);
            }
            let resp = match req.send().await {
                Ok(r) => r,
                Err(e) => {
                    let msg = format!("{e:#}");
                    if is_benign(&msg) {
                        return Ok(rows);
                    }
                    eprintln!("  WARN: ResourceExplorer list_indexes: {e:#}");
                    break;
                }
            };

            for idx in resp.indexes() {
                let arn = idx.arn().map(|s| s.to_string()).unwrap_or_default();
                let region = idx.region().map(|s| s.to_string()).unwrap_or_default();
                let idx_type = idx
                    .r#type()
                    .map(|t| t.as_str().to_string())
                    .unwrap_or_default();

                let (state, created) = (String::new(), String::new());

                rows.push(vec![
                    "Index".to_string(),
                    arn,
                    idx_type,
                    region,
                    state,
                    created,
                ]);
            }

            idx_token = resp.next_token().map(|s| s.to_string());
            if idx_token.is_none() {
                break;
            }
        }

        // ── Views ─────────────────────────────────────────────────────
        let mut v_token: Option<String> = None;
        loop {
            let mut req = self.client.list_views();
            if let Some(t) = v_token.as_ref() {
                req = req.next_token(t);
            }
            let resp = match req.send().await {
                Ok(r) => r,
                Err(e) => {
                    let msg = format!("{e:#}");
                    if is_benign(&msg) {
                        return Ok(rows);
                    }
                    eprintln!("  WARN: ResourceExplorer list_views: {e:#}");
                    break;
                }
            };

            for view_arn in resp.views() {
                rows.push(vec![
                    "View".to_string(),
                    view_arn.to_string(),
                    String::new(),
                    String::new(),
                    String::new(),
                    String::new(),
                ]);
            }

            v_token = resp.next_token().map(|s| s.to_string());
            if v_token.is_none() {
                break;
            }
        }

        Ok(rows)
    }
}
