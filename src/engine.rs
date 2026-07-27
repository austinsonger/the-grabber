//! High-level engine used by the desktop GUI.

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use tokio::runtime::Runtime;
use uuid::Uuid;

use crate::app_config::AppConfig;
use crate::cli::Cli;
use crate::credentials::{load_aws_sdk_config, CredentialKind, CredentialSecret, CredentialVault};
use crate::runner::cli_runners::run_standard_cli;

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

    pub async fn collect(
        &self,
        req: CollectionRequest,
        sink: Box<dyn ProgressSink>,
    ) -> Result<RunSummary> {
        let credential_id = Uuid::parse_str(&req.credential_id).context("Invalid credential id")?;
        let (entry, secret) = self
            .vault
            .get(credential_id)
            .context("Failed to load credential")?
            .context("Credential not found")?;

        // Apply credentials to the process environment so the AWS default
        // credentials chain picks them up. The desktop app runs one collection
        // at a time, so process-wide env vars are acceptable.
        match (&entry.kind, &secret) {
            (
                CredentialKind::AwsAccessKey { access_key_id },
                CredentialSecret::AwsAccessKeySecret {
                    secret_access_key,
                    session_token,
                },
            ) => {
                std::env::set_var("AWS_ACCESS_KEY_ID", access_key_id);
                std::env::set_var("AWS_SECRET_ACCESS_KEY", secret_access_key);
                match session_token {
                    Some(t) => std::env::set_var("AWS_SESSION_TOKEN", t),
                    None => std::env::remove_var("AWS_SESSION_TOKEN"),
                }
            }
            (CredentialKind::AwsProfileReference { profile_name }, _) => {
                std::env::set_var("AWS_PROFILE", profile_name);
            }
            (CredentialKind::AwsSso { .. }, _) => {
                // Ensure the SSO profile block exists in ~/.aws/config.
                let region = req
                    .regions
                    .first()
                    .cloned()
                    .unwrap_or_else(|| "us-east-1".to_string());
                let _ = load_aws_sdk_config(&entry, &secret, Some(region)).await;
                std::env::set_var("AWS_PROFILE", &entry.name);
            }
            _ => {}
        }

        let region = req
            .regions
            .first()
            .cloned()
            .unwrap_or_else(|| "us-east-1".to_string());
        let cli = Cli {
            start_date: Some(req.start_date),
            end_date: Some(req.end_date),
            region,
            regions: Some(req.regions.clone()),
            output: Some(req.output_dir.clone()),
            collectors: Some(req.collectors.clone()),
            include_raw: req.include_raw,
            zip: req.zip,
            sign: req.sign,
            signing_key: req.signing_key,
            write_run_manifest: req.write_run_manifest,
            write_chain_of_custody: req.write_chain_of_custody,
            ..Cli::default()
        };

        sink.emit(ProgressEvent {
            run_id: req.run_id.clone(),
            account: req.account_name.clone(),
            region: None,
            collector: "all".into(),
            status: "started".into(),
            records: 0,
            message: Some("Collection run started".into()),
        });

        run_standard_cli(&cli)
            .await
            .context("Collection run failed")?;

        sink.emit(ProgressEvent {
            run_id: req.run_id.clone(),
            account: req.account_name.clone(),
            region: None,
            collector: "all".into(),
            status: "finished".into(),
            records: 0,
            message: Some("Collection run finished".into()),
        });

        Ok(RunSummary {
            run_id: req.run_id,
            account: req.account_name,
            regions: req.regions,
            collectors: req.collectors.len(),
            output_dir: req.output_dir,
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

/// Request to start an evidence-collection run.
#[derive(Debug, Clone)]
pub struct CollectionRequest {
    pub run_id: String,
    pub account_name: String,
    pub credential_id: String,
    pub regions: Vec<String>,
    pub start_date: String,
    pub end_date: String,
    pub collectors: Vec<String>,
    pub output_dir: PathBuf,
    pub zip: bool,
    pub sign: bool,
    pub include_raw: bool,
    pub write_run_manifest: bool,
    pub write_chain_of_custody: bool,
    pub signing_key: Option<String>,
}

/// Summary returned when a run completes.
#[derive(Debug, Clone, serde::Serialize)]
pub struct RunSummary {
    pub run_id: String,
    pub account: String,
    pub regions: Vec<String>,
    pub collectors: usize,
    pub output_dir: PathBuf,
}
