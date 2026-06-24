mod app_config;
mod audit_log;
mod aws_loader;
mod cli;
mod evidence;
mod inventory_core;
mod inventory_orchestrator;
mod inventory_xlsx;
mod platform;
mod poam;
mod providers;
mod runner;
mod signing;
mod tui;
mod zip_bundle;

use anyhow::{Context, Result};
use clap::Parser;

use crate::cli::Cli;
use crate::runner::cli_runners::{run_inventory_cli, run_poam_cli, run_standard_cli};
use crate::runner::tui_session::run_tui_session;

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

fn main() -> Result<()> {
    tokio::runtime::Builder::new_multi_thread()
        .thread_stack_size(16 * 1024 * 1024)
        .enable_all()
        .build()?
        .block_on(async_main())
}

async fn async_main() -> Result<()> {
    let cli = Cli::parse();

    // ── Verify-only mode (no collection) ─────────────────────────────────────
    if let Some(ref manifest_path) = cli.verify_manifest {
        let key_hex = cli
            .signing_key
            .as_deref()
            .context("--signing-key <hex> is required with --verify-manifest")?;
        let key = signing::SigningKey::from_hex(key_hex)?;
        let report = signing::verify_manifest(std::path::Path::new(manifest_path), &key)?;
        report.print();
        return Ok(());
    }

    if cli.inventory {
        return run_inventory_cli(&cli).await;
    }

    if cli.poam {
        return run_poam_cli(&cli).await;
    }

    if cli.start_date.is_none() && cli.lookback.is_none() {
        return run_tui_session(&cli).await;
    }

    // ── Non-interactive (CLI flags) mode ─────────────────────────────────
    run_standard_cli(&cli).await
}
