use crate::client::{next_link, OktaClient};
use crate::error::OktaError;
use crate::types::group::OktaGroup;
use crate::types::user::OktaUser;

pub struct GroupsApi<'c>(pub(crate) &'c OktaClient);

impl<'c> GroupsApi<'c> {
    pub async fn list_all(&self) -> Result<Vec<OktaGroup>, OktaError> {
        let mut all = Vec::new();
        let mut next: Option<String> = Some(self.0.url("/api/v1/groups?limit=200"));
        while let Some(url) = next {
            let resp = self.0.get_absolute(&url).await?;
            if !resp.status().is_success() {
                let status = resp.status().as_u16();
                let message = resp.text().await.unwrap_or_default();
                return Err(OktaError::Api { status, message });
            }
            let link = next_link(&resp);
            let page: Vec<OktaGroup> = resp.json().await?;
            all.extend(page);
            next = link;
        }
        Ok(all)
    }

    pub async fn list_members(&self, group_id: &str) -> Result<Vec<OktaUser>, OktaError> {
        let mut all = Vec::new();
        let mut next: Option<String> = Some(
            self.0
                .url(&format!("/api/v1/groups/{}/users?limit=200", group_id)),
        );
        while let Some(url) = next {
            let resp = self.0.get_absolute(&url).await?;
            if !resp.status().is_success() {
                let status = resp.status().as_u16();
                let message = resp.text().await.unwrap_or_default();
                return Err(OktaError::Api { status, message });
            }
            let link = next_link(&resp);
            let page: Vec<OktaUser> = resp.json().await?;
            all.extend(page);
            next = link;
        }
        Ok(all)
    }
}
