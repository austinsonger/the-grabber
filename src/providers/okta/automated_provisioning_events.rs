use anyhow::Result;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use okta_rs::types::log_event::OktaLogEvent;
use okta_rs::OktaClient;

use crate::evidence::CsvCollector;

pub struct OktaAutomatedProvisioningEventsCollector {
    client: OktaClient,
}

impl OktaAutomatedProvisioningEventsCollector {
    pub fn new(client: OktaClient) -> Self {
        Self { client }
    }
}

fn event_row(e: OktaLogEvent) -> Vec<String> {
    let target_arr = e.target.as_array();
    let first_target = target_arr.and_then(|a| a.first());
    let target_login = first_target
        .and_then(|t| t.get("alternateId"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    let actor = e.actor.as_ref();
    let actor_type = actor.and_then(|a| a.actor_type.clone()).unwrap_or_default();
    let is_system_principal = if actor_type == "SystemPrincipal" {
        "YES"
    } else {
        "NO"
    };

    vec![
        e.uuid,
        e.published,
        e.event_type,
        actor_type,
        target_login,
        is_system_principal.to_string(),
    ]
}

#[async_trait]
impl CsvCollector for OktaAutomatedProvisioningEventsCollector {
    fn name(&self) -> &str {
        "Okta Automated Provisioning Events"
    }
    fn filename_prefix(&self) -> &str {
        "Okta_Automated_Provisioning_Events"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Event ID",
            "Published",
            "Event Type",
            "Actor Type",
            "Target Login",
            "Is System Principal",
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

        let create_events = match self
            .client
            .lifecycle()
            .events_all("user.lifecycle.create", &since_iso)
            .await
        {
            Ok(e) => e,
            Err(okta_rs::OktaError::Api { status: 404, .. }) => vec![],
            Err(e) => return Err(e.into()),
        };

        let membership_events = match self
            .client
            .lifecycle()
            .events_all("application.user_membership.add", &since_iso)
            .await
        {
            Ok(e) => e,
            Err(okta_rs::OktaError::Api { status: 404, .. }) => vec![],
            Err(e) => return Err(e.into()),
        };

        let rows = create_events
            .into_iter()
            .chain(membership_events.into_iter())
            .map(event_row)
            .collect();

        Ok(rows)
    }
}
