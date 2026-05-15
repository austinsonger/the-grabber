//! GCP Cloud DNS managed zones — equivalent to AWS Route 53.

use anyhow::Result;
use async_trait::async_trait;

use crate::evidence::CsvCollector;
use crate::providers::gcp::client::GcpClient;

pub struct CloudDnsCollector {
    client:     GcpClient,
    project_id: String,
}

impl CloudDnsCollector {
    pub fn new(client: GcpClient, project_id: impl Into<String>) -> Self {
        Self { client, project_id: project_id.into() }
    }
}

#[async_trait]
impl CsvCollector for CloudDnsCollector {
    fn name(&self) -> &str { "GCP Cloud DNS" }
    fn filename_prefix(&self) -> &str { "GCP_Cloud_DNS" }
    fn headers(&self) -> &'static [&'static str] {
        &["project_id", "name", "dns_name", "description", "visibility",
          "dnssec_enabled", "creation_time", "name_servers"]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let url = format!(
            "https://dns.googleapis.com/dns/v1/projects/{}/managedZones?maxResults=500",
            self.project_id
        );
        let zones = self.client.paginate(&url, "managedZones").await?;

        let rows = zones.iter().map(|z| {
            let dnssec = z
                .get("dnssecConfig")
                .and_then(|d| d.get("state"))
                .and_then(|v| v.as_str())
                .map(|s| (s == "on").to_string())
                .unwrap_or_else(|| "false".to_owned());
            let ns = z
                .get("nameServers")
                .and_then(|v| v.as_array())
                .map(|a| a.iter().filter_map(|s| s.as_str()).collect::<Vec<_>>().join(","))
                .unwrap_or_default();
            vec![
                self.project_id.clone(),
                z.get("name").and_then(|v| v.as_str()).unwrap_or("").to_owned(),
                z.get("dnsName").and_then(|v| v.as_str()).unwrap_or("").to_owned(),
                z.get("description").and_then(|v| v.as_str()).unwrap_or("").to_owned(),
                z.get("visibility").and_then(|v| v.as_str()).unwrap_or("").to_owned(),
                dnssec,
                z.get("creationTime").and_then(|v| v.as_str()).unwrap_or("").to_owned(),
                ns,
            ]
        }).collect();
        Ok(rows)
    }
}
