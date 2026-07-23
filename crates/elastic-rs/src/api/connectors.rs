use crate::client::{check_response, ElasticClient};
use crate::error::ElasticError;
use crate::types::connector::Connector;

pub struct ConnectorsApi<'c>(pub(crate) &'c ElasticClient);

impl<'c> ConnectorsApi<'c> {
    /// Fetch every configured Kibana alerting connector via
    /// `GET /api/actions/connectors`. This endpoint returns a plain JSON
    /// array (not paginated).
    pub async fn find_all(&self) -> Result<Vec<Connector>, ElasticError> {
        let resp = check_response(self.0.kibana_get("/api/actions/connectors").await?).await?;
        Ok(resp.json().await?)
    }
}
