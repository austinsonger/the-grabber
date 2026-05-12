use std::marker::PhantomData;

use serde::de::DeserializeOwned;
use serde::Deserialize;
use tokio::time::{sleep, Duration};

use crate::client::TenableClient;
use crate::error::TenableError;

const MAX_POLL_ATTEMPTS: u32 = 120;
const POLL_INTERVAL_SECS: u64 = 5;

/// Shared async-export abstraction.
///
/// Tenable's bulk APIs (vulns, assets, compliance) all follow the same flow:
///   1. POST to start the export → receive an `export_uuid`
///   2. Poll GET `{resource_path}/status` until `"FINISHED"`
///   3. Download each chunk via GET `{resource_path}/chunks/{chunk_id}`
///
/// Call `collect_all()` to drive the full lifecycle, or `cancel()` to abort.
pub struct ExportJob<T> {
    client:        TenableClient,
    /// Base path for this specific export job, e.g. `/vulns/export/{uuid}`.
    resource_path: String,
    _phantom:      PhantomData<T>,
}

/// Response shape returned when an export is started.
#[derive(Debug, Deserialize)]
pub(crate) struct ExportStarted {
    pub export_uuid: String,
}

#[derive(Debug, Deserialize)]
struct ExportStatus {
    status:           String,
    #[serde(default)]
    chunks_available: Vec<u32>,
}

impl<T: DeserializeOwned> ExportJob<T> {
    pub(crate) fn new(client: TenableClient, resource_path: String) -> Self {
        Self { client, resource_path, _phantom: PhantomData }
    }

    /// Cancel this in-progress export.
    pub async fn cancel(self) -> Result<(), TenableError> {
        let path = format!("{}/cancel", self.resource_path);
        let resp = self.client.post(&path, &serde_json::json!({})).await?;
        check_response(resp).await?;
        Ok(())
    }

    /// Poll until the export is FINISHED, then download and deserialize all chunks.
    ///
    /// Polls every `POLL_INTERVAL_SECS` seconds for up to `MAX_POLL_ATTEMPTS`
    /// attempts (~10 minutes total).
    pub async fn collect_all(self) -> Result<Vec<T>, TenableError> {
        let chunks = self.wait_for_chunks().await?;
        let mut records = Vec::new();
        for chunk_id in chunks {
            let path = format!("{}/chunks/{}", self.resource_path, chunk_id);
            let resp = self.client.get(&path).await?;
            let resp = check_response(resp).await?;
            let chunk: Vec<T> = resp.json().await?;
            records.extend(chunk);
        }
        Ok(records)
    }

    async fn wait_for_chunks(&self) -> Result<Vec<u32>, TenableError> {
        let status_path = format!("{}/status", self.resource_path);
        for _ in 0..MAX_POLL_ATTEMPTS {
            let resp = self.client.get(&status_path).await?;
            let resp = check_response(resp).await?;
            let status: ExportStatus = resp.json().await?;
            match status.status.as_str() {
                "FINISHED"  => return Ok(status.chunks_available),
                "ERROR"     => return Err(TenableError::ExportFailed { status: status.status }),
                "CANCELLED" => return Err(TenableError::ExportFailed { status: status.status }),
                // QUEUED and PROCESSING are in-progress states — keep polling
                _ => sleep(Duration::from_secs(POLL_INTERVAL_SECS)).await,
            }
        }
        Err(TenableError::ExportFailed {
            status: "timed out waiting for export to finish".to_string(),
        })
    }
}

/// Map HTTP error codes to typed errors; pass successful responses through.
///
/// 401 → `Auth`, 403 → `Forbidden`, any other non-2xx → `Api`.
pub(crate) async fn check_response(
    resp: reqwest::Response,
) -> Result<reqwest::Response, TenableError> {
    match resp.status().as_u16() {
        200..=299 => Ok(resp),
        401 => Err(TenableError::Auth),
        403 => Err(TenableError::Forbidden),
        status => {
            let message = resp.text().await.unwrap_or_default();
            Err(TenableError::Api { status, message })
        }
    }
}
