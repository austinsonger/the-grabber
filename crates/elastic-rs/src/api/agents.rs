use crate::client::{check_response, ElasticClient};
use crate::error::ElasticError;
use crate::types::agent::{FleetAgent, FleetAgentsFindResponse};

const PAGE_SIZE: u32 = 100;

pub struct AgentsApi<'c>(pub(crate) &'c ElasticClient);

impl<'c> AgentsApi<'c> {
    /// Fetch every enrolled Fleet agent via `GET /api/fleet/agents`,
    /// paginating until exhausted.
    pub async fn find_all(&self) -> Result<Vec<FleetAgent>, ElasticError> {
        let mut page = 1u32;
        let mut all = Vec::new();
        loop {
            let path = format!("/api/fleet/agents?page={page}&perPage={PAGE_SIZE}");
            let resp = check_response(self.0.kibana_get(&path).await?).await?;
            let parsed: FleetAgentsFindResponse = resp.json().await?;
            let got = parsed.items.len();
            all.extend(parsed.items);
            if got == 0 || (all.len() as u64) >= parsed.total {
                break;
            }
            page += 1;
        }
        Ok(all)
    }
}
