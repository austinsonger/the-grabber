//! High-level engine used by the desktop GUI.

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use tokio::runtime::Runtime;
use uuid::Uuid;

use crate::app_config::AppConfig;
use crate::cli::Cli;
use crate::credentials::{load_aws_sdk_config, CredentialKind, CredentialSecret, CredentialVault};
use crate::runner::cli_runners::{run_inventory_cli, run_poam_cli, run_standard_cli};

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

    /// Apply a stored AWS credential to the process environment so the AWS
    /// default credentials chain picks it up. The desktop app runs one
    /// workflow at a time, so process-wide env vars are acceptable.
    async fn apply_aws_credential(
        &self,
        credential_id: &str,
        region: Option<String>,
    ) -> Result<()> {
        let credential_id = Uuid::parse_str(credential_id).context("Invalid credential id")?;
        let (entry, secret) = self
            .vault
            .get(credential_id)
            .context("Failed to load credential")?
            .context("Credential not found")?;

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
                let region = region.unwrap_or_else(|| "us-east-1".to_string());
                let _ = load_aws_sdk_config(&entry, &secret, Some(region)).await;
                std::env::set_var("AWS_PROFILE", &entry.name);
            }
            _ => {}
        }
        Ok(())
    }

    pub async fn collect(
        &self,
        req: CollectionRequest,
        sink: Box<dyn ProgressSink>,
    ) -> Result<RunSummary> {
        self.apply_aws_credential(&req.credential_id, req.regions.first().cloned())
            .await?;

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

    /// Run the unified asset-inventory workflow.
    pub async fn inventory(
        &self,
        req: InventoryRequest,
        sink: Box<dyn ProgressSink>,
    ) -> Result<RunSummary> {
        self.apply_aws_credential(&req.credential_id, req.regions.first().cloned())
            .await?;

        let region = req
            .regions
            .first()
            .cloned()
            .unwrap_or_else(|| "us-east-1".to_string());
        let cli = Cli {
            inventory: true,
            inventory_all_accounts: req.all_accounts,
            inventory_types: if req.inventory_types.is_empty() {
                None
            } else {
                Some(req.inventory_types.clone())
            },
            region,
            regions: Some(req.regions.clone()),
            output: Some(req.output_dir.clone()),
            zip: req.zip,
            ..Cli::default()
        };

        let emit = |status: &str, message: &str| {
            sink.emit(ProgressEvent {
                run_id: req.run_id.clone(),
                account: req.account_name.clone(),
                region: None,
                collector: "inventory".into(),
                status: status.into(),
                records: 0,
                message: Some(message.into()),
            });
        };

        emit("started", "Inventory run started");
        run_inventory_cli(&cli).await.context("Inventory failed")?;
        emit("finished", "Inventory run finished");

        Ok(RunSummary {
            run_id: req.run_id,
            account: req.account_name,
            regions: req.regions,
            collectors: req.inventory_types.len(),
            output_dir: req.output_dir,
        })
    }

    /// Reconcile evidence findings into a POA&M document.
    pub async fn poam(&self, req: PoamRequest, sink: Box<dyn ProgressSink>) -> Result<RunSummary> {
        let cli = Cli {
            poam: true,
            poam_evidence_base: req.evidence_base.clone(),
            poam_year: req.year.clone(),
            poam_month: req.month.clone(),
            poam_format: req.format.clone(),
            output: Some(req.output_dir.clone()),
            ..Cli::default()
        };

        let emit = |status: &str, message: &str| {
            sink.emit(ProgressEvent {
                run_id: req.run_id.clone(),
                account: req.evidence_base.clone(),
                region: None,
                collector: "poam".into(),
                status: status.into(),
                records: 0,
                message: Some(message.into()),
            });
        };

        emit("started", "POA&M generation started");
        run_poam_cli(&cli)
            .await
            .context("POA&M generation failed")?;
        emit("finished", "POA&M generation finished");

        Ok(RunSummary {
            run_id: req.run_id,
            account: req.evidence_base,
            regions: Vec::new(),
            collectors: 0,
            output_dir: req.output_dir,
        })
    }

    /// Build an Okta client from a stored API-token credential.
    #[cfg(feature = "okta")]
    fn okta_client(&self, credential_id: &str) -> Result<okta_rs::OktaClient> {
        let credential_id = Uuid::parse_str(credential_id).context("Invalid credential id")?;
        let (entry, secret) = self
            .vault
            .get(credential_id)
            .context("Failed to load credential")?
            .context("Credential not found")?;

        let domain = match &entry.kind {
            CredentialKind::ApiToken { domain } => domain.clone(),
            _ => anyhow::bail!("Credential '{}' is not an Okta API token", entry.name),
        };
        let token = match &secret {
            CredentialSecret::ApiToken { token } => token.clone(),
            _ => anyhow::bail!("Credential '{}' has no API token stored", entry.name),
        };

        okta_rs::OktaClient::new(&domain, &token)
            .map_err(|e| anyhow::anyhow!("Okta client build failed: {e}"))
    }

    /// Evaluate every Okta STIG check against the tenant behind `credential_id`.
    #[cfg(feature = "okta")]
    pub async fn stig_scan(&self, credential_id: &str) -> Result<Vec<StigFinding>> {
        let client = self.okta_client(credential_id)?;
        let map = crate::okta_stig_map::bundled();
        let results = crate::providers::okta::stig::evaluate_all(&client).await;

        Ok(results
            .into_iter()
            .map(|r| {
                let meta = map.get(&r.v_id);
                StigFinding {
                    title: meta.map(|m| m.title.clone()).unwrap_or_default(),
                    severity: meta.map(|m| m.severity.clone()).unwrap_or_default(),
                    fedramp_req_ids: meta.map(|m| m.fedramp_req_ids.clone()).unwrap_or_default(),
                    status: r.status.as_stig_str().to_string(),
                    actionable: r.status.is_actionable(),
                    expected_value: r.expected_value,
                    actual_value: r.actual_value,
                    details: r.details,
                    needs_text_input: r.remediation.iter().any(|t| t.needs_text_input()),
                    remediation: r.remediation.iter().map(|t| t.describe()).collect(),
                    v_id: r.v_id,
                }
            })
            .collect())
    }

    /// Apply remediation for the given V-IDs. The tenant is re-scanned first so
    /// the targets acted on reflect current state rather than a stale UI list.
    #[cfg(feature = "okta")]
    pub async fn stig_apply(&self, req: StigApplyRequest) -> Result<Vec<StigRemediationOutcome>> {
        use crate::stig_status::RemediationInputs;

        let client = self.okta_client(&req.credential_id)?;
        let map = crate::okta_stig_map::bundled();
        let results = crate::providers::okta::stig::evaluate_all(&client).await;
        let inputs = RemediationInputs {
            text: req.text_input.clone().filter(|s| !s.is_empty()),
        };
        let out_dir = req
            .output_dir
            .join(&req.tenant_name)
            .join(crate::runner::output::date_path_suffix());

        let mut outcomes = Vec::new();
        for result in results.iter().filter(|r| req.v_ids.contains(&r.v_id)) {
            let title = map
                .get(&result.v_id)
                .map(|m| m.title.clone())
                .unwrap_or_default();

            for target in &result.remediation {
                let outcome =
                    crate::providers::okta::stig::remediate::apply(&client, target, &inputs).await;

                let entry = crate::stig_remediation_log::RemediationLogEntry::new(
                    &req.tenant_name,
                    &result.v_id,
                    &title,
                    &result.details,
                    outcome.label(),
                    &outcome.detail(),
                );
                let log_path =
                    crate::stig_remediation_log::append_remediation_log(&out_dir, &entry)
                        .ok()
                        .map(|p| p.display().to_string());

                outcomes.push(StigRemediationOutcome {
                    v_id: result.v_id.clone(),
                    target: target.describe(),
                    label: outcome.label().to_string(),
                    detail: outcome.detail(),
                    log_path,
                });
            }
        }

        Ok(outcomes)
    }
}

/// A STIG check result flattened for the UI, joined with its checklist metadata.
#[derive(Debug, Clone, serde::Serialize)]
pub struct StigFinding {
    pub v_id: String,
    pub title: String,
    pub severity: String,
    pub fedramp_req_ids: Vec<String>,
    pub status: String,
    pub actionable: bool,
    pub expected_value: String,
    pub actual_value: String,
    pub details: String,
    pub needs_text_input: bool,
    /// Human-readable description of each remediation target, in apply order.
    pub remediation: Vec<String>,
}

/// Request to remediate a set of STIG findings.
#[derive(Debug, Clone)]
pub struct StigApplyRequest {
    pub credential_id: String,
    pub tenant_name: String,
    pub v_ids: Vec<String>,
    pub text_input: Option<String>,
    pub output_dir: PathBuf,
}

/// The result of applying one remediation target.
#[derive(Debug, Clone, serde::Serialize)]
pub struct StigRemediationOutcome {
    pub v_id: String,
    pub target: String,
    pub label: String,
    pub detail: String,
    pub log_path: Option<String>,
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

/// Request to start an asset-inventory run.
#[derive(Debug, Clone)]
pub struct InventoryRequest {
    pub run_id: String,
    pub account_name: String,
    pub credential_id: String,
    pub regions: Vec<String>,
    /// Empty means "every inventory asset type".
    pub inventory_types: Vec<String>,
    pub output_dir: PathBuf,
    pub all_accounts: bool,
    pub zip: bool,
}

/// Request to generate a POA&M document from previously collected evidence.
#[derive(Debug, Clone)]
pub struct PoamRequest {
    pub run_id: String,
    /// Root directory the reconciler scans for evidence findings.
    pub evidence_base: String,
    pub year: Option<String>,
    pub month: Option<String>,
    /// `xlsx` for the legacy workbook, `oscal` for the OSCAL JSON document.
    pub format: String,
    pub output_dir: PathBuf,
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
