use anyhow::{Context, Result};
use async_trait::async_trait;
use aws_sdk_accessanalyzer::Client as AaClient;

use crate::evidence::CsvCollector;

pub struct AccessAnalyzerCollector {
    client: AaClient,
}

impl AccessAnalyzerCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self { client: AaClient::new(config) }
    }
}

#[async_trait]
impl CsvCollector for AccessAnalyzerCollector {
    fn name(&self) -> &str { "IAM Access Analyzer Findings" }
    fn filename_prefix(&self) -> &str { "AccessAnalyzer_Findings" }
    fn headers(&self) -> &'static [&'static str] {
        &["Analyzer Name", "Resource ARN", "Resource Type", "Finding Type", "Public Access", "Cross Account", "Status"]
    }

    async fn collect_rows(&self, account_id: &str, _region: &str) -> Result<Vec<Vec<String>>> {
        let mut rows = Vec::new();

        // List all analyzers
        let mut next_token: Option<String> = None;
        let mut analyzers: Vec<(String, String, String)> = Vec::new(); // (arn, name, type)

        loop {
            let mut req = self.client.list_analyzers();
            if let Some(ref t) = next_token {
                req = req.next_token(t);
            }
            let resp = req.send().await.context("AccessAnalyzer list_analyzers")?;

            for az in resp.analyzers() {
                let arn = az.arn().to_string();
                let name = az.name().to_string();
                let az_type = az.r#type().as_str().to_string();
                analyzers.push((arn, name, az_type));
            }

            next_token = resp.next_token().map(|s| s.to_string());
            if next_token.is_none() { break; }
        }

        if analyzers.is_empty() {
            eprintln!("  WARN: No Access Analyzers found in this region");
            return Ok(rows);
        }

        for (az_arn, az_name, az_type) in &analyzers {
            let mut findings_token: Option<String> = None;

            loop {
                let mut req = self.client
                    .list_findings()
                    .analyzer_arn(az_arn);
                if let Some(ref t) = findings_token {
                    req = req.next_token(t);
                }
                let resp = match req.send().await {
                    Ok(r) => r,
                    Err(e) => {
                        eprintln!("  WARN: AccessAnalyzer list_findings for {az_name}: {e:#}");
                        break;
                    }
                };

                for finding in resp.findings() {
                    let resource_arn = finding.resource().unwrap_or("").to_string();
                    let resource_type = finding.resource_type().as_str().to_string();

                    // Finding type derived from analyzer type
                    let finding_type = az_type.clone();

                    let is_public = if finding.is_public().unwrap_or(false) { "Yes" } else { "No" };

                    // Cross account: check principal map for ARNs with different account IDs
                    let cross_account = {
                        let mut cross = "No";
                        let principals = finding.principal();
                        for val in principals.map(|p| p.values()).into_iter().flatten() {
                            if val.starts_with("arn:aws") {
                                let parts: Vec<&str> = val.splitn(6, ':').collect();
                                if parts.len() >= 5 {
                                    let arn_account = parts[4];
                                    if !arn_account.is_empty() && arn_account != account_id {
                                        cross = "Yes";
                                    }
                                }
                            }
                        }
                        cross
                    };

                    let status = finding.status().as_str().to_string();

                    rows.push(vec![
                        az_name.clone(),
                        resource_arn,
                        resource_type,
                        finding_type,
                        is_public.to_string(),
                        cross_account.to_string(),
                        status,
                    ]);
                }

                findings_token = resp.next_token().map(|s| s.to_string());
                if findings_token.is_none() { break; }
            }
        }

        Ok(rows)
    }
}
