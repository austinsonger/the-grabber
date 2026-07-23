use crate::client::{check_response, ElasticClient};
use crate::error::ElasticError;
use crate::types::case::{Case, CasesFindResponse};

const PAGE_SIZE: u32 = 100;

pub struct CasesApi<'c>(pub(crate) &'c ElasticClient);

impl<'c> CasesApi<'c> {
    /// Fetch every Security Solution case via `GET /api/cases/_find`,
    /// paginating until exhausted. `owner=securitySolution` scopes results
    /// to Security cases (Observability/Stack cases are excluded).
    pub async fn find_all(&self) -> Result<Vec<Case>, ElasticError> {
        let mut page = 1u32;
        let mut all = Vec::new();
        loop {
            let path =
                format!("/api/cases/_find?owner=securitySolution&page={page}&perPage={PAGE_SIZE}");
            let resp = check_response(self.0.kibana_get(&path).await?).await?;
            let parsed: CasesFindResponse = resp.json().await?;
            let got = parsed.cases.len();
            all.extend(parsed.cases);
            if got == 0 || (all.len() as u64) >= parsed.total {
                break;
            }
            page += 1;
        }
        Ok(all)
    }
}
