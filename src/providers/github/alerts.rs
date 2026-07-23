use anyhow::Result;
use async_trait::async_trait;
use chrono::DateTime;
use github_rs::{GithubClient, GithubError};

use crate::evidence::CsvCollector;

/// Parse an RFC 3339 `created_at` and check it against an optional
/// `(start_secs, end_secs)` Unix-timestamp range. Unparseable timestamps are
/// kept (fail open) rather than silently dropped.
fn in_range(created_at: &str, dates: Option<(i64, i64)>) -> bool {
    let Some((start, end)) = dates else {
        return true;
    };
    match DateTime::parse_from_rfc3339(created_at) {
        Ok(dt) => {
            let ts = dt.timestamp();
            ts >= start && ts <= end
        }
        Err(_) => true,
    }
}

pub struct GithubDependabotAlertsCollector {
    pub(crate) client: GithubClient,
}

impl GithubDependabotAlertsCollector {
    pub fn new(client: GithubClient) -> Self {
        Self { client }
    }
}

#[async_trait]
impl CsvCollector for GithubDependabotAlertsCollector {
    fn name(&self) -> &str {
        "GitHub Dependabot Alerts"
    }
    fn filename_prefix(&self) -> &str {
        "Github_Dependabot_Alerts"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Repository",
            "Alert Number",
            "State",
            "Package Ecosystem",
            "Package Name",
            "Severity",
            "GHSA ID",
            "CVE ID",
            "Summary",
            "Created At",
            "Updated At",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let alerts = match self.client.alerts().dependabot_alerts().await {
            Ok(a) => a,
            Err(GithubError::Api { status: 403, .. }) => return Ok(vec![]),
            Err(GithubError::Api { status: 404, .. }) => return Ok(vec![]),
            Err(e) => return Err(e.into()),
        };
        Ok(alerts
            .into_iter()
            .filter(|a| in_range(&a.created_at, dates))
            .map(|a| {
                let advisory = a.security_advisory;
                vec![
                    a.repository.full_name,
                    a.number.to_string(),
                    a.state,
                    a.dependency.package.ecosystem,
                    a.dependency.package.name,
                    advisory.as_ref().map(|s| s.severity.clone()).unwrap_or_default(),
                    advisory.as_ref().map(|s| s.ghsa_id.clone()).unwrap_or_default(),
                    advisory
                        .as_ref()
                        .and_then(|s| s.cve_id.clone())
                        .unwrap_or_default(),
                    advisory.as_ref().map(|s| s.summary.clone()).unwrap_or_default(),
                    a.created_at,
                    a.updated_at.unwrap_or_default(),
                ]
            })
            .collect())
    }
}

pub struct GithubSecretScanningAlertsCollector {
    pub(crate) client: GithubClient,
}

impl GithubSecretScanningAlertsCollector {
    pub fn new(client: GithubClient) -> Self {
        Self { client }
    }
}

#[async_trait]
impl CsvCollector for GithubSecretScanningAlertsCollector {
    fn name(&self) -> &str {
        "GitHub Secret Scanning Alerts"
    }
    fn filename_prefix(&self) -> &str {
        "Github_Secret_Scanning_Alerts"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Repository",
            "Alert Number",
            "State",
            "Secret Type",
            "Secret Type Display Name",
            "Resolution",
            "Push Protection Bypassed",
            "Created At",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let alerts = match self.client.alerts().secret_scanning_alerts().await {
            Ok(a) => a,
            Err(GithubError::Api { status: 403, .. }) => return Ok(vec![]),
            Err(GithubError::Api { status: 404, .. }) => return Ok(vec![]),
            Err(e) => return Err(e.into()),
        };
        Ok(alerts
            .into_iter()
            .filter(|a| in_range(&a.created_at, dates))
            .map(|a| {
                vec![
                    a.repository.full_name,
                    a.number.to_string(),
                    a.state,
                    a.secret_type,
                    a.secret_type_display_name.unwrap_or_default(),
                    a.resolution.unwrap_or_default(),
                    a.push_protection_bypassed.to_string(),
                    a.created_at,
                ]
            })
            .collect())
    }
}

pub struct GithubCodeScanningAlertsCollector {
    pub(crate) client: GithubClient,
}

impl GithubCodeScanningAlertsCollector {
    pub fn new(client: GithubClient) -> Self {
        Self { client }
    }
}

#[async_trait]
impl CsvCollector for GithubCodeScanningAlertsCollector {
    fn name(&self) -> &str {
        "GitHub Code Scanning Alerts"
    }
    fn filename_prefix(&self) -> &str {
        "Github_Code_Scanning_Alerts"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Repository",
            "Alert Number",
            "State",
            "Rule ID",
            "Severity",
            "Security Severity Level",
            "Description",
            "Created At",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let alerts = match self.client.alerts().code_scanning_alerts().await {
            Ok(a) => a,
            Err(GithubError::Api { status: 403, .. }) => return Ok(vec![]),
            Err(GithubError::Api { status: 404, .. }) => return Ok(vec![]),
            Err(e) => return Err(e.into()),
        };
        Ok(alerts
            .into_iter()
            .filter(|a| in_range(&a.created_at, dates))
            .map(|a| {
                vec![
                    a.repository.full_name,
                    a.number.to_string(),
                    a.state,
                    a.rule.id,
                    a.rule.severity.unwrap_or_default(),
                    a.rule.security_severity_level.unwrap_or_default(),
                    a.rule.description,
                    a.created_at,
                ]
            })
            .collect())
    }
}
