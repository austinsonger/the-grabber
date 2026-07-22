use crate::client::{check_response, ElasticClient};
use crate::error::ElasticError;
use crate::types::exception::{
    ExceptionItemsFindResponse, ExceptionList, ExceptionListItem, ExceptionListsFindResponse,
};

const PAGE_SIZE: u32 = 100;

pub struct ExceptionsApi<'c>(pub(crate) &'c ElasticClient);

impl<'c> ExceptionsApi<'c> {
    /// Fetch every exception list via `GET /api/exception_lists/_find`,
    /// paginating until exhausted.
    pub async fn find_all_lists(&self) -> Result<Vec<ExceptionList>, ElasticError> {
        let mut page = 1u32;
        let mut all = Vec::new();
        loop {
            let path = format!("/api/exception_lists/_find?page={page}&per_page={PAGE_SIZE}");
            let resp = check_response(self.0.kibana_get(&path).await?).await?;
            let parsed: ExceptionListsFindResponse = resp.json().await?;
            let got = parsed.data.len();
            all.extend(parsed.data);
            if got == 0 || (all.len() as u64) >= parsed.total {
                break;
            }
            page += 1;
        }
        Ok(all)
    }

    /// Fetch every item across the given lists via
    /// `GET /api/exception_lists/items/_find`, paginating until exhausted.
    /// Returns an empty vec without a request when `lists` is empty (the
    /// endpoint requires at least one `list_id`).
    pub async fn find_all_items(
        &self,
        lists: &[ExceptionList],
    ) -> Result<Vec<ExceptionListItem>, ElasticError> {
        if lists.is_empty() {
            return Ok(Vec::new());
        }
        let list_ids = lists
            .iter()
            .map(|l| l.list_id.as_str())
            .collect::<Vec<_>>()
            .join(",");
        let namespaces = lists
            .iter()
            .map(|l| l.namespace_type.as_str())
            .collect::<Vec<_>>()
            .join(",");

        let mut page = 1u32;
        let mut all = Vec::new();
        loop {
            let path = format!(
                "/api/exception_lists/items/_find?list_id={list_ids}&namespace_type={namespaces}&page={page}&per_page={PAGE_SIZE}"
            );
            let resp = check_response(self.0.kibana_get(&path).await?).await?;
            let parsed: ExceptionItemsFindResponse = resp.json().await?;
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
