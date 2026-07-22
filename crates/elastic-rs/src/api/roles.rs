use std::collections::HashMap;

use crate::client::{check_response, ElasticClient};
use crate::error::ElasticError;
use crate::types::role::{SecurityRole, SecurityRoleRaw};

pub struct RolesApi<'c>(pub(crate) &'c ElasticClient);

impl<'c> RolesApi<'c> {
    /// Fetch every Elasticsearch security role via `GET /_security/role`.
    /// A single, non-paginated call, matching the users endpoint.
    pub async fn find_all(&self) -> Result<Vec<SecurityRole>, ElasticError> {
        let resp = check_response(self.0.es_get("/_security/role").await?).await?;
        let raw: HashMap<String, SecurityRoleRaw> = resp.json().await?;
        Ok(raw
            .into_iter()
            .map(|(name, r)| {
                let index_patterns = r.indices.iter().flat_map(|i| i.names.clone()).collect();
                let index_privileges =
                    r.indices.iter().flat_map(|i| i.privileges.clone()).collect();
                SecurityRole {
                    name,
                    cluster_privileges: r.cluster,
                    index_patterns,
                    index_privileges,
                    application_count: r.applications.len(),
                }
            })
            .collect())
    }
}
