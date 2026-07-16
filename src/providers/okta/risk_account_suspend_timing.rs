use anyhow::Result;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use okta_rs::types::log_event::OktaLogEvent;
use okta_rs::OktaClient;

use crate::evidence::CsvCollector;

pub struct OktaRiskAccountSuspendTimingCollector {
    client: OktaClient,
}

impl OktaRiskAccountSuspendTimingCollector {
    pub fn new(client: OktaClient) -> Self {
        Self { client }
    }
}

fn target_login(event: &OktaLogEvent) -> String {
    // Prefer the actor's alternate ID (typically the login attempted during a
    // threat detection); fall back to the first target entry.
    if let Some(login) = event.actor.as_ref().and_then(|a| a.alternate_id.clone()) {
        if !login.is_empty() {
            return login;
        }
    }
    event
        .target
        .as_array()
        .and_then(|a| a.first())
        .and_then(|t| t.get("alternateId"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string()
}

fn latency_minutes(threat_published: &str, suspend_published: &str) -> Option<i64> {
    let threat_time = DateTime::parse_from_rfc3339(threat_published).ok()?;
    let suspend_time = DateTime::parse_from_rfc3339(suspend_published).ok()?;
    Some((suspend_time - threat_time).num_minutes())
}

#[async_trait]
impl CsvCollector for OktaRiskAccountSuspendTimingCollector {
    fn name(&self) -> &str {
        "Okta Risk Account Suspend Timing"
    }
    fn filename_prefix(&self) -> &str {
        "Okta_Risk_Account_Suspend_Timing"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Threat Event ID",
            "Threat Detected At",
            "Target Login",
            "Suspend Event ID",
            "Suspended At",
            "Latency Minutes",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let since_iso = dates
            .map(|(s, _)| DateTime::<Utc>::from_timestamp(s, 0).unwrap_or_else(Utc::now))
            .unwrap_or_else(|| Utc::now() - chrono::Duration::days(90))
            .to_rfc3339();

        let threats = match self.client.threat_insight().detections(&since_iso).await {
            Ok(e) => e,
            Err(okta_rs::OktaError::Api { status: 404, .. }) => vec![],
            Err(e) => return Err(e.into()),
        };

        let suspends = match self
            .client
            .lifecycle()
            .events_all("user.lifecycle.suspend", &since_iso)
            .await
        {
            Ok(e) => e,
            Err(okta_rs::OktaError::Api { status: 404, .. }) => vec![],
            Err(e) => return Err(e.into()),
        };

        let rows = threats
            .into_iter()
            .map(|threat| {
                let threat_login = target_login(&threat);
                let matched = suspends.iter().find(|s| target_login(s) == threat_login);

                match matched {
                    Some(suspend) => {
                        let latency = latency_minutes(&threat.published, &suspend.published)
                            .map(|m| m.to_string())
                            .unwrap_or_else(|| "NO_MATCH".to_string());
                        vec![
                            threat.uuid.clone(),
                            threat.published.clone(),
                            threat_login,
                            suspend.uuid.clone(),
                            suspend.published.clone(),
                            latency,
                        ]
                    }
                    None => vec![
                        threat.uuid.clone(),
                        threat.published.clone(),
                        threat_login,
                        String::new(),
                        String::new(),
                        "NO_MATCH".to_string(),
                    ],
                }
            })
            .collect();

        Ok(rows)
    }
}
