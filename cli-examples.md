# Grabber CLI Examples

This guide shows common non-interactive CLI patterns for Grabber.

If you are running from a local checkout and have **not** installed the binary to your PATH yet, use one of these forms:

```bash
# Run with Cargo
cargo run -- --help

# Run a built release binary
./target/release/grabber --help
```

If you already installed it with `cargo install --path .`, you can use:

```bash
grabber --help
```

## Quick start

### Basic single-region run

```bash
./target/release/grabber \
  --start-date 2026-01-01 \
  --end-date 2026-04-01 \
  --region us-east-1 \
  --profile ProdAdmin-123456789012
```

### Write output to a specific directory

```bash
./target/release/grabber \
  --start-date 2026-01-01 \
  --end-date 2026-04-01 \
  --region us-east-1 \
  --profile ProdAdmin-123456789012 \
  --output ./evidence-output/prod-cli
```

### Include raw JSON for time-windowed JSON collectors

```bash
./target/release/grabber \
  --start-date 2026-01-01 \
  --end-date 2026-04-01 \
  --region us-east-1 \
  --profile ProdAdmin-123456789012 \
  --include-raw
```

## Collector selection

### Run a small collector subset

```bash
./target/release/grabber \
  --start-date 2026-01-01 \
  --end-date 2026-04-01 \
  --region us-east-1 \
  --profile ProdAdmin-123456789012 \
  --collectors cloudtrail,backup,rds
```

### Run a few current-state collectors

```bash
./target/release/grabber \
  --start-date 2026-01-01 \
  --end-date 2026-04-01 \
  --region us-east-1 \
  --profile ProdAdmin-123456789012 \
  --collectors iam-users,iam-policies,security-groups,kms
```

### Find valid collector keys

Collector keys are maintained in `evidence-list.md`. Use that file as the reference for the current catalog.

## Inventory functionality

The dedicated **Inventory** feature is the unified asset inventory workflow, and it is now exposed through the CLI with `--inventory`.

Its selectable asset types are exactly:

1. `kms-key` — KMS Key
2. `s3-bucket` — S3 Bucket
3. `lambda-function` — Lambda Function
4. `ec2-instance` — EC2 Instance
5. `alb` — Application Load Balancer (ALB)
6. `rds-db-instance` — RDS DB Instance
7. `elasticache-cluster` — ElastiCache Cluster
8. `container` — Container (ECR/ECS/EKS)

That inventory flow produces a unified `AWS_Inventory-<timestamp>.csv` and, when the template exists, an Excel workbook based on `assets/Inventory.xlsx`.

Use `--inventory` to run the unified inventory mode. When no type flags are provided, all eight asset types above are collected. Restrict the run with either individual type flags (`--kms`, `--s3`, `--lambda`, `--ec2`, `--alb`, `--rds`, `--elasticache`, `--containers`) or a comma-separated `--inventory-types` list — both are additive.

### Collect all inventory asset types

```bash
./target/release/grabber \
  --inventory \
  --profile ProdAdmin-123456789012
```

### Collect a subset of inventory asset types

```bash
# EC2 and RDS only, via individual flags
./target/release/grabber --inventory --ec2 --rds \
  --profile ProdAdmin-123456789012

# Same result via --inventory-types
./target/release/grabber --inventory \
  --inventory-types ec2-instance,rds-db-instance \
  --profile ProdAdmin-123456789012
```

### Multi-account merged inventory

```bash
# Merges inventory from every account in config.toml / okta-config / jira-config / tenable-config
./target/release/grabber --inventory --inventory-all-accounts \
  --output ./evidence-output/inventory-all
```

### Collect inventory across multiple regions

```bash
./target/release/grabber \
  --inventory \
  --regions us-east-1,us-east-2,us-west-2 \
  --profile ProdAdmin-123456789012
```

### Auto-discover enabled regions for inventory

```bash
./target/release/grabber \
  --inventory \
  --all-regions \
  --profile ProdAdmin-123456789012
```

### Write inventory output to a specific directory

```bash
./target/release/grabber \
  --inventory \
  --output ./evidence-output/inventory \
  --profile ProdAdmin-123456789012
```

### Package and sign inventory output

```bash
./target/release/grabber \
  --inventory \
  --profile ProdAdmin-123456789012 \
  --zip \
  --sign
```

Inventory mode writes a unified `AWS_Inventory-<timestamp>.csv` and, when `assets/Inventory.xlsx` exists, also writes the inventory Excel workbook.

## Multi-region runs

### Auto-discover enabled regions

```bash
./target/release/grabber \
  --start-date 2026-01-01 \
  --end-date 2026-04-01 \
  --profile ProdAdmin-123456789012 \
  --all-regions \
  --output ./evidence-output/all-regions
```

### Use an explicit region list

```bash
./target/release/grabber \
  --start-date 2026-01-01 \
  --end-date 2026-04-01 \
  --profile ProdAdmin-123456789012 \
  --regions us-east-1,us-east-2,us-west-2 \
  --output ./evidence-output/selected-regions
```

## CloudTrail S3 log collection

### Collect CloudTrail history directly from an S3 bucket

```bash
./target/release/grabber \
  --start-date 2026-01-01 \
  --end-date 2026-04-01 \
  --region us-east-1 \
  --profile ProdAdmin-123456789012 \
  --collectors s3 \
  --s3-bucket my-central-cloudtrail-logs
```

### Cross-account S3 access with extra accounts and regions

```bash
./target/release/grabber \
  --start-date 2026-01-01 \
  --end-date 2026-04-01 \
  --region us-east-1 \
  --profile AuditRole-123456789012 \
  --collectors s3 \
  --s3-bucket my-central-cloudtrail-logs \
  --s3-prefix management \
  --s3-profile LogArchiveRole-999999999999 \
  --s3-accounts 123456789012,210987654321 \
  --s3-regions us-east-1,us-west-2
```

## Packaging and signing

### Zip the run output

```bash
./target/release/grabber \
  --start-date 2026-01-01 \
  --end-date 2026-04-01 \
  --region us-east-1 \
  --profile ProdAdmin-123456789012 \
  --zip
```

### Sign output files with an auto-generated key

```bash
./target/release/grabber \
  --start-date 2026-01-01 \
  --end-date 2026-04-01 \
  --region us-east-1 \
  --profile ProdAdmin-123456789012 \
  --sign
```

### Sign output files with a provided key

```bash
./target/release/grabber \
  --start-date 2026-01-01 \
  --end-date 2026-04-01 \
  --region us-east-1 \
  --profile ProdAdmin-123456789012 \
  --sign \
  --signing-key 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
```

### Verify a signing manifest later

```bash
./target/release/grabber \
  --verify-manifest ./SIGNING-MANIFEST-2026-04-10-220000.json \
  --signing-key 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
```

## Lookback windows

`--lookback` is a shortcut that computes `--start-date` from today. It accepts a plain integer (interpreted as days) or a value with a `d` / `w` / `m` / `y` suffix. It cannot be combined with `--start-date` / `--end-date`.

```bash
# Last 90 days
./target/release/grabber --lookback 90d --profile ProdAdmin-123456789012

# Last 12 weeks
./target/release/grabber --lookback 12w --profile ProdAdmin-123456789012

# Last 3 months, all regions
./target/release/grabber --lookback 3m --all-regions --profile ProdAdmin-123456789012
```

## POA&M reconciliation

POA&M mode reads Inspector2 findings from an existing evidence directory and reconciles them against a FedRAMP POA&M Excel workbook.

```bash
./target/release/grabber \
  --poam \
  --region us-east-1 \
  --poam-year 2026 \
  --poam-month May \
  --poam-evidence-base evidence-output/security
```

The evidence directory resolves to `<poam-evidence-base>/<region>/<year>/<MM-MON>/`.

## Inspector SBOM export

The `inspector-sbom` collector triggers an AWS Inspector V2 SBOM export, polls until complete, and downloads the result from S3.

```bash
./target/release/grabber \
  --lookback 90d \
  --collectors inspector-sbom \
  --sbom-bucket my-sbom-exports \
  --sbom-kms-key arn:aws:kms:us-east-1:123456789012:key/abc-123 \
  --sbom-format cyclonedx14
```

If `--sbom-bucket` is omitted, the collector emits a `SKIPPED` row explaining the missing flags instead of failing.

## Audit trail opt-ins

Both audit artifacts are off by default. Opt in per run:

```bash
./target/release/grabber \
  --lookback 30d \
  --write-run-manifest \
  --write-chain-of-custody
```

## Okta

### Okta — core evidence subset

```bash
./target/release/grabber \
  --start-date 2026-01-01 \
  --end-date   2026-04-01 \
  --collectors okta-users,okta-groups,okta-apps,okta-policies,okta-factors,okta-system-log
```

### Okta — compliance evidence subset

```bash
./target/release/grabber \
  --lookback 90d \
  --collectors okta-access-reviews,okta-deprovisioning,okta-offboarding-sla,okta-group-changes,okta-threat-insight
```

The Okta tenant URL and API token come from `okta-config.toml` (or `OKTA_DOMAIN` / `OKTA_API_TOKEN`). The CLI auto-discovers the configured Okta account by `provider = "okta"`.

## Jira

```bash
# Core inventory
./target/release/grabber \
  --lookback 90d \
  --collectors jira-projects,jira-issues

# Compliance evidence targeting specific control tickets
./target/release/grabber \
  --lookback 90d \
  --collectors jira-offboarding-sla,jira-remote-access-approvals,jira-dr-test,jira-ir-lessons
```

Jira credentials come from `jira-config.toml` (or `JIRA_DOMAIN` / `JIRA_EMAIL` / `JIRA_API_TOKEN`). The compliance collectors additionally consult a `[project_keys]` block in `jira-config.toml` for the project/JQL scope of each key.

## Tenable

```bash
./target/release/grabber \
  --collectors tenable-vulns,tenable-was,tenable-pci-asv,tenable-assets,tenable-compliance
```

Credentials come from `tenable-config.toml` (or `TENABLE_ACCESS_KEY` / `TENABLE_SECRET_KEY`). Tenable is region-agnostic — `--region`, `--all-regions`, and `--regions` have no effect.

## CrowdStrike

```bash
./target/release/grabber \
  --collectors crowdstrike-hosts,crowdstrike-alerts,crowdstrike-vulnerabilities,crowdstrike-prevention-policies,crowdstrike-sensor-update-policies
```

Credentials come from `crowdstrike-config.toml` (or `CROWDSTRIKE_CLIENT_ID` / `CROWDSTRIKE_CLIENT_SECRET` / `CROWDSTRIKE_BASE_URL`). CrowdStrike is region-agnostic — `--region`, `--all-regions`, and `--regions` have no effect. `crowdstrike-alerts` respects `--start-date`/`--end-date` (or `--lookback`) like any other time-windowed collector; the others are point-in-time snapshots.

## Useful local commands

### Show generated help

```bash
cargo run -- --help
```

### Build a release binary

```bash
cargo build --release
```

### Install the command to your PATH

```bash
cargo install --path .
grabber --help
```

## Notes

1. `--start-date` turns on non-interactive collection mode.
2. `--end-date` is required whenever `--start-date` is used.
3. `--verify-manifest` is a verification-only path and does not collect new evidence.
4. `--output` points to a directory, not a single file.
5. `--help` output from the binary is the source of truth for the current flag set.
