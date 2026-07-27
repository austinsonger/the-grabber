use anyhow::{Context, Result};
use clap::Parser;

use the_grabber::cli::Cli;
use the_grabber::runner::cli_runners::{run_inventory_cli, run_poam_cli, run_standard_cli};
use the_grabber::runner::tui_session::run_tui_session;

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
        let key = the_grabber::signing::SigningKey::from_hex(key_hex)?;
        let report =
            the_grabber::signing::verify_manifest(std::path::Path::new(manifest_path), &key)?;
        report.print();
        return Ok(());
    }

    if cli.inventory {
        return run_inventory_cli(&cli).await;
    }

    if cli.poam
        || cli.poam_add_item.is_some()
        || cli.poam_remove_item.is_some()
        || cli.poam_item_title.is_some()
        || cli.poam_item_description.is_some()
    {
        return run_poam_cli(&cli).await;
    }

    if cli.start_date.is_none() && cli.lookback.is_none() {
        return run_tui_session(&cli).await;
    }

    // ── Non-interactive (CLI flags) mode ─────────────────────────────────
    run_standard_cli(&cli).await
}
