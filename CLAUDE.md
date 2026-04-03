# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Project Is

**Grabber** is an AWS compliance evidence collector written in Rust. It collects 100+ AWS service snapshots and audit records for FedRAMP, SOC 2, HIPAA, and internal audit submissions. It provides both an interactive TUI wizard and a non-interactive CLI mode.

## Build & Run Commands

```bash
# Build
cargo build --release               # Binary: target/release/grabber

# Run (interactive TUI mode)
./target/release/grabber

# Run (CLI mode — requires --start-date)
./target/release/grabber --start-date 2026-01-01 --region us-east-1 --profile myprofile

# Install to PATH
cargo install --path .

# Check/lint
cargo check
cargo clippy

# Run tests (there are few currently)
cargo test

# Run a single test
cargo test <test_name>
```

## Key CLI Flags

| Flag | Purpose |
|------|---------|
| `--start-date YYYY-MM-DD` | Triggers CLI mode (skips TUI) |
| `--end-date YYYY-MM-DD` | End of collection window (defaults to today) |
| `--region us-east-1` | AWS region |
| `--profile myprofile` | AWS profile name |
| `--collectors cloudtrail,ec2-instances` | Comma-separated collector filter |
| `--all-regions` | Round-robin all 17 supported regions |
| `--s3-bucket mybucket` | S3 bucket for CloudTrail log collection |

## Architecture

### Entry Point & Mode Selection (`src/main.rs`)

`main.rs` is the largest file (~87KB). It:
1. Parses CLI args (via `clap`)
2. Determines mode: if `--start-date` is provided → CLI mode; otherwise → TUI
3. Loads `config.toml` (or `~/.config/evidence/config.toml`) for multi-account setup
4. Registers all collectors via `if wants("key") { collectors.push(...) }` pattern
5. Executes collectors concurrently with 3-minute per-collector timeouts
6. Writes output files to `evidence-output/<account>/`

### Three Collector Traits (`src/evidence.rs`)

All collectors implement exactly one trait:

1. **`EvidenceCollector`** — time-windowed, JSON output. Used for CloudTrail events, backup records, RDS snapshots.
2. **`JsonCollector`** — point-in-time snapshot, JSON output wrapped in `JsonInventoryReport`. Used for IAM roles, KMS config, EventBridge rules.
3. **`CsvCollector`** — point-in-time snapshot, CSV output. Used for EC2 instances, security groups, VPCs, S3 buckets, etc.

### Adding a New Collector

1. Create `src/my_service.rs` implementing one of the three traits
2. Register in `main.rs` with `if wants("my-service") { ... }`
3. Add an entry to `evidence-list.md`

### TUI (`src/tui/mod.rs` + `src/tui/ui.rs`)

State machine with screens: `Welcome → SelectAccount → SelectProfile → SelectRegion → SetDates → SelectCollectors → SetOptions → Confirm → Preparing → Running → Results`

Uses `ratatui` for rendering and `crossterm` for events. Progress updates flow via an `mpsc` channel from async collector tasks to the UI render loop.

### Configuration (`src/app_config.rs`)

TOML-based (`config.toml`). Resolution order for which collectors run:
1. If `enable` is set → only those
2. Otherwise: all collectors minus `disable` list, plus `enable_extra`

```toml
[defaults]
region = "us-east-1"
output_dir = "./evidence-output"

[[account]]
name = "Production"
account_id = "123456789012"
profile = "ProdAdmin-123456789012"
region = "us-east-1"
output_dir = "./evidence-output/production"
```

See `config.example.toml` for full reference.

### Output

- Files: `<AccountName>_<CollectorName>-<YYYY-MM-DD-HHmmss>.<json|csv>`
- JSON output is wrapped in a `JsonInventoryReport` envelope with metadata (account, region, timestamp, record count)
- Logs: `evidence-collection.log` (WARN+ level; keeps terminal clean during TUI)

### Async Runtime

Tokio multi-threaded runtime with **16MB thread stacks** (custom config in `main.rs`) to support many concurrent async collectors without stack overflows.

## Collector Module Map

80+ modules in `src/`. Key groupings:
- **IAM:** `iam_inventory`, `iam_policies`, `iam_trusts`, `iam_certs`
- **EC2/VPC:** `ec2_inventory`, `ec2_detailed`, `ec2_config`, `vpc`, `network_gateways`
- **Storage:** `s3_config`, `s3_detail`, `s3_inventory`, `s3_policies`, `efs`, `dynamodb`
- **RDS:** `rds`, `rds_inventory`, `rds_snapshots`, `backup_config`
- **Security:** `guardduty`, `securityhub`, `inspector`, `access_analyzer`, `macie`
- **Audit/Logging:** `cloudtrail`, `cloudtrail_details`, `cloudtrail_config`, `config_history`
- **KMS:** `kms`, `kms_config`, `kms_policies`
- **Monitoring:** `cloudwatch_resources`, `cloudwatch_config`, `cloudwatch_alarms`
- **Containers:** `ecr`, `ecs`, `eks`
- **Other:** `elasticache`, `lambda_config`, `route53_config`, `organizations`, `cloudformation_drift`

See `evidence-list.md` for the full collector list with keys and output formats.

## IAM Permissions

Minimal IAM policies for running Grabber are in the `iam/` directory.