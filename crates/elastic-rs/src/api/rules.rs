use crate::client::{check_response, ElasticClient};
use crate::error::ElasticError;
use crate::types::rule::{DetectionRule, RulesFindResponse};

const PAGE_SIZE: u32 = 100;

pub struct RulesApi<'c>(pub(crate) &'c ElasticClient);

impl<'c> RulesApi<'c> {
    /// Fetch every detection rule via `GET /api/detection_engine/rules/_find`,
    /// paginating until all pages are consumed.
    pub async fn find_all(&self) -> Result<Vec<DetectionRule>, ElasticError> {
        let mut page = 1u32;
        let mut all = Vec::new();
        loop {
            let path =
                format!("/api/detection_engine/rules/_find?page={page}&per_page={PAGE_SIZE}");
            let resp = check_response(self.0.kibana_get(&path).await?).await?;
            let parsed: RulesFindResponse = resp.json().await?;
            let got = parsed.data.len();
            all.extend(parsed.data);
            if got == 0 || (all.len() as u64) >= parsed.total {
                break;
            }
            page += 1;
        }
        Ok(all)
    }
}
