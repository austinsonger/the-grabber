//! GCP Cloud Run services — equivalent to AWS ECS/Fargate.

use anyhow::Result;
use async_trait::async_trait;

use crate::evidence::CsvCollector;
use crate::providers::gcp::client::GcpClient;

pub struct CloudRunCollector {
    client:     GcpClient,
    project_id: String,
}

impl CloudRunCollector {
    pub fn new(client: GcpClient, project_id: impl Into<String>) -> Self {
        Self { client, project_id: project_id.into() }
    }
}

#[async_trait]
impl CsvCollector for CloudRunCollector {
    fn name(&self) -> &str { "GCP Cloud Run" }
    fn filename_prefix(&self) -> &str { "GCP_Cloud_Run" }
    fn headers(&self) -> &'static [&'static str] {
        &["project_id", "name", "region", "ingress", "traffic_mode",
          "service_account", "min_instances", "max_instances",
          "create_time", "update_time", "uri"]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let url = format!(
            "https://run.googleapis.com/v2/projects/{}/locations/-/services?pageSize=1000",
            self.project_id
        );
        let services = self.client.paginate(&url, "services").await?;

        let rows = services.iter().map(|s| {
            let tmpl = s.get("template");
            let sa = tmpl
                .and_then(|t| t.get("serviceAccount"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_owned();
            let min_inst = tmpl
                .and_then(|t| t.get("scaling"))
                .and_then(|sc| sc.get("minInstanceCount"))
                .and_then(|v| v.as_i64())
                .map(|i| i.to_string())
                .unwrap_or_default();
            let max_inst = tmpl
                .and_then(|t| t.get("scaling"))
                .and_then(|sc| sc.get("maxInstanceCount"))
                .and_then(|v| v.as_i64())
                .map(|i| i.to_string())
                .unwrap_or_default();
            let name_full = s.get("name").and_then(|v| v.as_str()).unwrap_or("").to_owned();
            let name_short = name_full.split('/').last().unwrap_or("").to_owned();
            let region = name_full.split('/').nth(5).unwrap_or("").to_owned();
            vec![
                self.project_id.clone(),
                name_short,
                region,
                s.get("ingress").and_then(|v| v.as_str()).unwrap_or("").to_owned(),
                s.get("traffic")
                    .and_then(|v| v.as_array())
                    .map(|a| serde_json::to_string(a).unwrap_or_default())
                    .unwrap_or_default(),
                sa,
                min_inst,
                max_inst,
                s.get("createTime").and_then(|v| v.as_str()).unwrap_or("").to_owned(),
                s.get("updateTime").and_then(|v| v.as_str()).unwrap_or("").to_owned(),
                s.get("uri").and_then(|v| v.as_str()).unwrap_or("").to_owned(),
            ]
        }).collect();
        Ok(rows)
    }
}
