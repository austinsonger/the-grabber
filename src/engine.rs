//! High-level engine used by the desktop GUI.

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use tokio::runtime::Runtime;

use crate::app_config::AppConfig;
use crate::credentials::CredentialVault;

/// Shared application state for the desktop GUI.
///
/// The engine owns the loaded application configuration, the credential vault,
/// and a dedicated Tokio runtime so that synchronous UI layers (Tauri commands,
/// test harnesses, etc.) can drive async collection work without blocking the
/// calling thread.
pub struct Engine {
    pub config: AppConfig,
    pub vault: CredentialVault,
    pub runtime: Arc<Runtime>,
}

impl Engine {
    pub fn new(config: AppConfig, data_dir: PathBuf) -> Result<Self> {
        let runtime = Arc::new(Runtime::new().context("Failed to create Tokio runtime")?);
        let vault = CredentialVault::open(data_dir)?;
        Ok(Self {
            config,
            vault,
            runtime,
        })
    }
}

/// Sink for progress events emitted during a collection run.
pub trait ProgressSink: Send + Sync {
    fn emit(&self, event: ProgressEvent);
}

/// Snapshot of progress for a single collector invocation.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ProgressEvent {
    pub run_id: String,
    pub account: String,
    pub region: Option<String>,
    pub collector: String,
    pub status: String,
    pub records: u64,
    pub message: Option<String>,
}
