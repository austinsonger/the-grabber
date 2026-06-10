use crate::client::{next_link, OktaClient};
use crate::error::OktaError;
use crate::types::app::OktaApp;

pub struct AppsApi<'c>(pub(crate) &'c OktaClient);

impl<'c> AppsApi<'c> {
    pub async fn list_all(&self) -> Result<Vec<OktaApp>, OktaError> {
        let mut all = Vec::new();
        let mut next: Option<String> = Some(self.0.url("/api/v1/apps?limit=200"));
        while let Some(url) = next {
            let resp = self.0.get_absolute(&url).await?;
            if !resp.status().is_success() {
                let status = resp.status().as_u16();
                let message = resp.text().await.unwrap_or_default();
                return Err(OktaError::Api { status, message });
            }
            let link = next_link(&resp);
            let page: Vec<OktaApp> = resp.json().await?;
            all.extend(page);
            next = link;
        }
        Ok(all)
    }
}
