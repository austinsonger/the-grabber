use anyhow::Result;
use async_trait::async_trait;
use chrono::SecondsFormat;
use okta_rs::OktaClient;

use crate::evidence::{CollectParams, EvidenceCollector, EvidenceRecord, EvidenceSource};

pub struct OktaSystemLogCollector {
    pub(crate) client: OktaClient,
}

impl OktaSystemLogCollector {
    pub fn new(client: OktaClient) -> Self {
        Self { client }
    }
}

#[async_trait]
impl EvidenceCollector for OktaSystemLogCollector {
    fn name(&self) -> &str {
        "Okta System Log"
    }

    fn filename_prefix(&self) -> &str {
        "Okta_System_Log_Events"
    }

    async fn collect(&self, params: &CollectParams) -> Result<Vec<EvidenceRecord>> {
        let since = params
            .start_time
            .to_rfc3339_opts(SecondsFormat::Millis, true);
        let until = params.end_time.to_rfc3339_opts(SecondsFormat::Millis, true);
        let filter = params.filter.as_deref();

        let events = match self
            .client
            .system_log()
            .events_all(&since, &until, filter)
            .await
        {
            Ok(e) => e,
            Err(okta_rs::OktaError::Api { status: 404, .. }) => return Ok(Vec::new()),
            Err(e) => return Err(e.into()),
        };

        let records = events
            .into_iter()
            .map(|e| {
                let actor_label = e
                    .actor
                    .as_ref()
                    .and_then(|a| a.alternate_id.clone().or_else(|| a.display_name.clone()))
                    .unwrap_or_default();
                let outcome_result = e
                    .outcome
                    .as_ref()
                    .map(|o| o.result.clone())
                    .filter(|s| !s.is_empty());
                let resource_arn = if actor_label.is_empty() {
                    None
                } else {
                    Some(actor_label)
                };
                let raw = if params.include_raw {
                    Some(serde_json::json!({
                        "uuid": e.uuid,
                        "published": e.published,
                        "eventType": e.event_type,
                        "displayMessage": e.display_message,
                        "severity": e.severity,
                        "outcome": e.outcome.as_ref().map(|o| serde_json::json!({
                            "result": o.result,
                            "reason": o.reason,
                        })),
                        "actor": e.actor.as_ref().map(|a| serde_json::json!({
                            "id": a.id,
                            "displayName": a.display_name,
                            "alternateId": a.alternate_id,
                            "type": a.actor_type,
                        })),
                        "client": e.client,
                        "target": e.target,
                    }))
                } else {
                    None
                };

                EvidenceRecord {
                    source: EvidenceSource::OktaSystemLog,
                    event_name: e.event_type,
                    timestamp: e.published,
                    job_id: Some(e.uuid),
                    plan_id: None,
                    resource_arn,
                    resource_type: e.severity,
                    status: outcome_result,
                    completion_timestamp: None,
                    raw,
                }
            })
            .collect();

        Ok(records)
    }
}
