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

Use `--inventory` to run the unified inventory mode. It always includes all eight asset types above.

### Collect all inventory asset types

```bash
./target/release/grabber \
  --inventory \
  --profile ProdAdmin-123456789012
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
