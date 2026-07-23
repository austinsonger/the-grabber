use std::collections::HashMap;

use crate::client::{check_response, ElasticClient};
use crate::error::ElasticError;
use crate::types::user::{SecurityUser, SecurityUserRaw};

pub struct UsersApi<'c>(pub(crate) &'c ElasticClient);

impl<'c> UsersApi<'c> {
    /// Fetch every Elasticsearch security user via `GET /_security/user`.
    /// A single, non-paginated call — Elasticsearch does not paginate this
    /// endpoint, and user counts are small enough that this isn't a concern.
    pub async fn find_all(&self) -> Result<Vec<SecurityUser>, ElasticError> {
        let resp = check_response(self.0.es_get("/_security/user").await?).await?;
        let raw: HashMap<String, SecurityUserRaw> = resp.json().await?;
        Ok(raw
            .into_iter()
            .map(|(username, u)| SecurityUser {
                username,
                roles: u.roles,
                full_name: u.full_name,
                email: u.email,
                enabled: u.enabled,
            })
            .collect())
    }
}
