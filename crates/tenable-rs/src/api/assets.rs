use crate::client::TenableClient;
use crate::error::TenableError;
use crate::export::ExportJob;
use crate::types::asset::AssetRecord;

/// Size of each downloaded chunk. Tenable requires 100–10 000.
const DEFAULT_CHUNK_SIZE: u32 = 1000;

pub struct AssetsApi<'c>(pub(crate) &'c TenableClient);

impl<'c> AssetsApi<'c> {
    /// Start an asset export.
    ///
    /// `chunk_size` controls how many assets Tenable puts in each downloadable
    /// chunk (100–10 000, default 1 000).  `filters` is an optional JSON object
    /// following the Tenable export filter schema.
    ///
    /// Note: the POST goes to `/assets/v2/export` but status/chunk downloads use
    /// the `/assets/export/{uuid}/…` paths (Tenable API inconsistency).
    pub async fn export(
        &self,
        chunk_size: Option<u32>,
        filters: Option<serde_json::Value>,
    ) -> Result<ExportJob<AssetRecord>, TenableError> {
        let body = build_body(chunk_size, filters);
        self.0
            .start_export("/assets/v2/export", "/assets/export", &body)
            .await
    }

    /// Convenience: export and collect all asset records in one call.
    pub async fn export_all(
        &self,
        chunk_size: Option<u32>,
        filters: Option<serde_json::Value>,
    ) -> Result<Vec<AssetRecord>, TenableError> {
        self.export(chunk_size, filters).await?.collect_all().await
    }
}

fn build_body(chunk_size: Option<u32>, filters: Option<serde_json::Value>) -> serde_json::Value {
    let size = chunk_size.unwrap_or(DEFAULT_CHUNK_SIZE);
    match filters {
        Some(f) => serde_json::json!({ "chunk_size": size, "filters": f }),
        None    => serde_json::json!({ "chunk_size": size }),
    }
}
