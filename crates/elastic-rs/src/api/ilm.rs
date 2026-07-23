use std::collections::HashMap;

use crate::client::{check_response, ElasticClient};
use crate::error::ElasticError;
use crate::types::ilm::{IlmPolicy, IlmPolicyRaw};

pub struct IlmApi<'c>(pub(crate) &'c ElasticClient);

impl<'c> IlmApi<'c> {
    /// Fetch every Index Lifecycle Management policy via `GET /_ilm/policy`.
    /// A single, non-paginated call — Elasticsearch does not paginate this
    /// endpoint.
    pub async fn find_all(&self) -> Result<Vec<IlmPolicy>, ElasticError> {
        let resp = check_response(self.0.es_get("/_ilm/policy").await?).await?;
        let raw: HashMap<String, IlmPolicyRaw> = resp.json().await?;
        Ok(raw
            .into_iter()
            .map(|(name, p)| {
                let phases = &p.policy.phases;
                let delete_min_age = phases
                    .get("delete")
                    .and_then(|d| d.get("min_age"))
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                IlmPolicy {
                    name,
                    modified_date: p.modified_date,
                    has_hot_phase: phases.get("hot").is_some(),
                    has_warm_phase: phases.get("warm").is_some(),
                    has_cold_phase: phases.get("cold").is_some(),
                    has_frozen_phase: phases.get("frozen").is_some(),
                    has_delete_phase: phases.get("delete").is_some(),
                    delete_min_age,
                }
            })
            .collect())
    }
}
