# The Grabber — CLI Reference

> **Non-interactive mode** is enabled by providing `--start-date`, `--lookback`, `--inventory`, or `--poam`.  
> Omitting all four launches the interactive TUI wizard instead.

---

## Table of Contents

1. [Modes](#modes)
2. [Quick-Start Examples](#quick-start-examples)
3. [Global Flags](#global-flags)
4. [Time Window Flags](#time-window-flags)
5. [Collectors Mode](#collectors-mode)
6. [Inventory Mode](#inventory-mode)
7. [POA&M Mode](#poam-mode)
8. [Signing & Verification](#signing--verification)
9. [Output & Packaging](#output--packaging)
10. [S3 CloudTrail Flags](#s3-cloudtrail-flags)
11. [Multi-Region Flags](#multi-region-flags)
12. [Skip Flags](#skip-flags)
13. [Collector Keys Reference](#collector-keys-reference)
14. [Inventory Asset Types](#inventory-asset-types)
15. [Config File Defaults](#config-file-defaults)
16. [Exit Behavior](#exit-behavior)

---

## Modes

The tool operates in one of four mutually-exclusive modes:

| Mode | Trigger Flag | Purpose |
|------|-------------|---------|
| **TUI** | *(no flags)* | Interactive wizard — accounts, dates, collectors, options |
| **Collectors** | `--start-date` or `--lookback` | Time-windowed evidence collection (CSV + JSON) |
| **Inventory** | `--inventory` | Current-state asset inventory (unified CSV) |
| **POA&M** | `--poam` | POA&M workbook reconciliation against Inspector findings |
| **Verify** | `--verify-manifest` | Verify a previously-signed evidence manifest |

---

## Quick-Start Examples

```bash
# Last 90 days of evidence — most common invocation
grabber --lookback 90d --profile ProdAdmin --region us-east-1

# Specific date range
grabber --start-date 2026-02-01 --end-date 2026-05-01 --profile ProdAdmin

# Only CloudTrail and GuardDuty findings, last 30 days
grabber --lookback 30d --collectors cloudtrail,guardduty

# All regions, 3-month lookback, zip the output
grabber --lookback 3m --all-regions --zip --profile ProdAdmin

# Full asset inventory — EC2 and RDS only
grabber --inventory --ec2 --rds --region us-east-1

# Full asset inventory across all regions
grabber --inventory --all-regions --profile ProdAdmin

# POA&M reconciliation for May 2026
grabber --poam --region us-east-1 --poam-year 2026 --poam-month May

# Sign output for tamper detection
grabber --lookback 90d --sign --output ./evidence-out

# Verify a previously-signed manifest
grabber --verify-manifest ./SIGNING-MANIFEST-2026-05-01-120000.json \
        --signing-key <64-char-hex>
```

---

## Global Flags

These flags apply to all modes unless noted otherwise.

| Flag | Default | Description |
|------|---------|-------------|
| `--region <REGION>` | `us-east-1` | Primary AWS region for collection |
| `--profile <PROFILE>` | *(ambient credentials)* | AWS named profile from `~/.aws/config` |
| `--output <PATH>` / `-o` | `.` (current dir) | Directory to write output files into |

---

## Time Window Flags

Time window flags define the **collection period** for time-windowed collectors (CloudTrail, GuardDuty findings, RDS snapshots, AWS Backup, etc.). Exactly one of `--lookback` or `--start-date`/`--end-date` must be provided to enable Collectors mode.

### `--lookback <DURATION>`

Computes the start date by subtracting a duration from today. End date is always **today at 23:59:59 UTC**.

```
--lookback 30d        30 days back
--lookback 12w        12 weeks back
--lookback 3m         3 months back
--lookback 1y         1 year back
```

**Accepted unit forms:**

| Unit | Aliases |
|------|---------|
| Days | `d`, `day`, `days` |
| Weeks | `w`, `week`, `weeks` |
| Months | `m`, `month`, `months` |
| Years | `y`, `year`, `years` |

> **Note:** `--lookback` cannot be combined with `--start-date` or `--end-date`.

### `--start-date <YYYY-MM-DD>`

Inclusive start of the collection window. Requires `--end-date`. Enables Collectors mode.

### `--end-date <YYYY-MM-DD>`

Inclusive end of the collection window. Required when `--start-date` is provided. Time is set to `23:59:59 UTC`.

---

## Collectors Mode

Triggered by `--start-date` or `--lookback`.

Runs up to 124 collectors that query AWS service APIs and write time-windowed or current-state evidence to CSV and JSON files.

### Selecting Collectors

```
--collectors <KEY>[,<KEY>...]
```

Comma-separated list of collector keys to run. Omit to run the full configured set (all defaults minus opt-ins — see [Config File Defaults](#config-file-defaults)).

**Examples:**

```bash
# Run only CloudTrail and IAM collectors
grabber --lookback 90d --collectors cloudtrail,iam-users,iam-roles,iam-policies

# Run the full set for all regions
grabber --lookback 3m --all-regions --profile ProdAdmin

# Run a single collector
grabber --lookback 7d --collectors ct-changes
```

See [Collector Keys Reference](#collector-keys-reference) for the full list of keys.

### Filter

```
--filter <STRING>
```

Optional string passed to time-windowed collectors that support server-side or client-side filtering (e.g. a resource prefix, event source). Behavior is collector-specific.

### Include Raw

```
--include-raw
```

Append the raw API response JSON to each record in the output. Significantly increases output file size.

---

## Inventory Mode

Triggered by `--inventory`. Does **not** use `--start-date` / `--end-date`. Use `--lookback` to attach an audit window to the run metadata.

Queries selected AWS asset types in parallel and writes a **single unified CSV** (`AWS_Inventory-<timestamp>.csv`) using the canonical 14-column FedRAMP/compliance schema.

### Asset Type Flags

Select which asset types to collect. If **none** are specified, all 8 types are collected.

Individual flags and `--inventory-types` are **additive** — you can combine them freely. Duplicates are removed automatically.

| Flag | Asset Type | Key |
|------|-----------|-----|
| `--kms` | KMS Keys | `kms-key` |
| `--s3` | S3 Buckets | `s3-bucket` |
| `--lambda` | Lambda Functions | `lambda-function` |
| `--ec2` | EC2 Instances | `ec2-instance` |
| `--alb` | Application Load Balancers | `alb` |
| `--rds` | RDS DB Instances | `rds-db-instance` |
| `--elasticache` | ElastiCache Clusters | `elasticache-cluster` |
| `--containers` | Containers (ECR/ECS/EKS) | `container` |

### `--inventory-types <KEY>[,<KEY>...]`

Alternative to individual flags — comma-separated list of asset type keys. Additive with individual flags.

```bash
# EC2 and RDS using individual flags
grabber --inventory --ec2 --rds

# EC2 and RDS using --inventory-types
grabber --inventory --inventory-types ec2-instance,rds-db-instance

# Mixed — results in ec2-instance, rds-db-instance, s3-bucket
grabber --inventory --ec2 --rds --inventory-types s3-bucket

# All types (default)
grabber --inventory --region us-east-1
```

### `--skip-inventory-csv`

Skip writing the `AWS_Inventory-*.csv` file. Useful when only the XLSX output is needed (the XLSX is written regardless).

### Lookback with Inventory

```bash
grabber --inventory --lookback 90d --ec2 --rds
```

The lookback window is attached to the run for audit-trail consistency with TUI behavior. The inventory collection itself is always current-state; the lookback does not filter assets by creation date.

---

## POA&M Mode

Triggered by `--poam`. Reconciles Inspector2 findings from the evidence directory against a FedRAMP POA&M Excel workbook.

### Required Flags

| Flag | Description |
|------|-------------|
| `--poam-year <YYYY>` | 4-digit findings year (e.g. `2026`) |
| `--poam-month <Month>` | Month name (e.g. `January`, `May`, `December`) |

### Optional Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--poam-evidence-base <PATH>` | `evidence-output/security` | Base directory for evidence files |
| `--region <REGION>` | `us-east-1` | Region sub-directory inside the evidence path |

### Evidence Path Resolution

The tool derives the evidence directory as:

```
<poam-evidence-base>/<region>/<year>/<MM-MON>/
```

For example, `--poam-evidence-base evidence-output/security --region us-east-1 --poam-year 2026 --poam-month May` resolves to:

```
evidence-output/security/us-east-1/2026/05-MAY/
```

### Examples

```bash
# Reconcile May 2026 findings for us-east-1
grabber --poam --region us-east-1 --poam-year 2026 --poam-month May

# Custom evidence base
grabber --poam \
  --poam-evidence-base ./audit/federal/ops \
  --region us-east-1 \
  --poam-year 2026 \
  --poam-month January
```

### Output

The command prints a reconciliation summary to stderr:

```
POA&M reconciliation complete.
  Region: us-east-1  Year: 2026  Month: May
  Evidence path: evidence-output/security/us-east-1/2026/05-MAY
  CSV used: Inspector2_Findings-2026-05-01-120000.csv
  Findings opened:  12
  Findings closed:  4
  WARN: ...
```

---

## Signing & Verification

### `--sign`

HMAC-SHA256-sign all output files after collection. Writes two files to the **current working directory**:

- `SIGNING-MANIFEST-<timestamp>.json` — cryptographic hash of every output file
- `SIGNING-<timestamp>.key` — hex-encoded HMAC key

> **Important:** Move the `.key` file to secure, separate storage before sharing the evidence package. Anyone with the key can verify the manifest; anyone without it cannot forge it.

### `--signing-key <HEX>`

Provide a 64-character hex signing key instead of auto-generating one. Use with `--sign` (to sign with a known key) or with `--verify-manifest` (to verify an existing manifest).

### `--verify-manifest <PATH>`

Verify a `SIGNING-MANIFEST-*.json` without collecting new evidence. Requires `--signing-key`.

```bash
grabber --verify-manifest ./SIGNING-MANIFEST-2026-05-01-120000.json \
        --signing-key a1b2c3d4...
```

Prints a per-file verification report and exits.

---

## Output & Packaging

### `--output <PATH>` / `-o`

Directory to write all output files. Created if it does not exist. Defaults to the current working directory.

In multi-region mode, output is automatically organized into `<output>/<region>/YYYY/MM-MON/` subdirectories.

### `--zip`

Bundle all output files into a single `Evidence-<timestamp>.zip` after collection. The zip is written to the current working directory.

```bash
grabber --lookback 90d --zip --output ./evidence-out
```

---

## S3 CloudTrail Flags

These flags enable the `s3` collector, which parses CloudTrail events directly from S3 log files. Required only when using key `s3` in `--collectors`.

| Flag | Description |
|------|-------------|
| `--s3-bucket <BUCKET>` | S3 bucket containing CloudTrail logs |
| `--s3-prefix <PREFIX>` | Key prefix before `AWSLogs/` (e.g. `management`). Default: `""` |
| `--s3-profile <PROFILE>` | AWS profile for S3 access when the bucket is in a different account |
| `--s3-accounts <ID>[,<ID>...]` | Additional account IDs to scan in S3 logs |
| `--s3-regions <REGION>[,<REGION>...]` | Additional regions to scan in S3 logs |

```bash
grabber --lookback 7m \
        --collectors s3 \
        --s3-bucket my-org-cloudtrail-logs \
        --s3-prefix management \
        --s3-profile LogArchiveAdmin \
        --s3-accounts 111111111111,222222222222
```

---

## Inspector SBOM Export Flags

These flags configure the `inspector-sbom` collector, which triggers an AWS Inspector V2 SBOM export, polls until complete, and downloads the result from S3. Required only when using key `inspector-sbom` in `--collectors`.

| Flag | Default | Description |
|------|---------|-------------|
| `--sbom-bucket <BUCKET>` | _(required)_ | S3 bucket where Inspector should write the SBOM export |
| `--sbom-kms-key <ARN>` | _(required)_ | KMS key ARN used to encrypt the export in S3 |
| `--sbom-format <FORMAT>` | `cyclonedx14` | SBOM format: `cyclonedx14` or `spdx23` |

When `--sbom-bucket` is omitted, the collector emits a `SKIPPED` row explaining the missing flags instead of failing.

```bash
grabber --lookback 90d \
        --collectors inspector-sbom \
        --sbom-bucket my-sbom-exports \
        --sbom-kms-key arn:aws:kms:us-east-1:123456789012:key/abc-123 \
        --sbom-format cyclonedx14
```

---

## Multi-Region Flags

By default the tool collects from a single region (`--region`). These flags enable round-robin collection across multiple regions.

| Flag | Description |
|------|-------------|
| `--all-regions` | Auto-discover all enabled regions via `EC2 DescribeRegions` and collect from each |
| `--regions <R>[,<R>...]` | Explicit list of regions (implies round-robin mode, skips discovery) |

**Behavior in multi-region mode:**

- **Global services** (IAM, S3, Route53, CloudFront, Organizations) run once from the base region.
- **Regional services** run once per region.
- Output is written to `<output>/<region>/YYYY/MM-MON/` subdirectories.

```bash
# Auto-discover all regions
grabber --lookback 90d --all-regions --profile ProdAdmin

# Specific regions only
grabber --lookback 90d --regions us-east-1,us-west-2,eu-west-1
```

---

## Skip Flags

These flags suppress specific output artifacts that are generated by default.

| Flag | Mode | What it skips |
|------|------|--------------|
| `--skip-run-manifest` | Collectors | `RUN-MANIFEST-<timestamp>.json` per-run outcome log |
| `--skip-chain-of-custody` | Collectors | `CHAIN-OF-CUSTODY-<timestamp>.json` operator identity log |
| `--skip-inventory-csv` | Inventory | `AWS_Inventory-<timestamp>.csv` unified asset CSV |

```bash
# CI run — skip audit files for faster pipeline
grabber --lookback 30d --collectors iam-users,iam-roles \
        --skip-run-manifest --skip-chain-of-custody

# Inventory — XLSX only, no CSV
grabber --inventory --ec2 --rds --skip-inventory-csv
```

---

## Collector Keys Reference

All 124+ collector keys organized by category. Pass any combination to `--collectors`.

### App Layer & DNS

| Key | Output | Description |
|-----|--------|-------------|
| `api-gateway` | CSV | API Gateway REST APIs |
| `cloudfront` | CSV | CloudFront distributions |
| `lambda-config` | CSV | Lambda function configuration |
| `lambda-permissions` | CSV | Lambda resource-based policies |
| `route53-zones` | CSV | Route53 hosted zones |
| `route53-resolver` | CSV | Route53 resolver rules |

### Audit Trail

| Key | Output | Description |
|-----|--------|-------------|
| `config-recorder` | CSV | AWS Config recorder state |
| `config-rules` | CSV | AWS Config rules and compliance |
| `cfn-drift` | CSV | CloudFormation stack drift |
| `cloudtrail` | JSON | CloudTrail events (last 90 days) |
| `ct-changes` | CSV | CloudTrail change events (last 7 days) |
| `cloudtrail-config` | CSV | CloudTrail trail configuration |
| `ct-selectors` | CSV | CloudTrail event selectors |
| `ct-full-config` | CSV | CloudTrail full configuration |
| `ct-validation` | CSV | CloudTrail log validation status |
| `s3` | JSON | CloudTrail S3 logs (requires `--s3-bucket`) |
| `ct-s3-policy` | CSV | CloudTrail S3 bucket policies |
| `config-compliance` | CSV | Config compliance history |
| `config-history` | CSV | Config resource history |
| `config-timeline` | CSV | Config resource timeline |
| `config-snapshot` | CSV | Config point-in-time snapshot |
| `ct-config-changes` | CSV | CT config change events (last 90 days) |
| `ct-iam-changes` | CSV | CT high-risk IAM changes (last 90 days) |

### Compute

| Key | Output | Description |
|-----|--------|-------------|
| `asg` | CSV | Auto Scaling Groups |
| `ec2-detailed` | CSV | EC2 AMI/IMDS details |
| `ec2-config` | CSV | EC2 instance configuration |
| `ec2-instances` | CSV | EC2 instances inventory |
| `launch-templates` | CSV | EC2 launch templates |
| `ssm-maint-windows` | CSV | SSM maintenance windows |
| `ssm-instances` | CSV | SSM managed instances |
| `ssm-params` | CSV | SSM Parameter Store |
| `ssm-baselines` | CSV | SSM patch baselines |
| `ssm-patches` | CSV | SSM patch compliance |
| `ssm-patch-detail` | CSV | SSM patch detail per instance |
| `ssm-patch-exec` | CSV | SSM patch execution history |
| `ssm-patch-summary` | CSV | SSM patch summary per instance |
| `time-sync` | CSV | EC2 time sync configuration |

### Containers

| Key | Output | Description |
|-----|--------|-------------|
| `ecr-scan` | CSV | ECR image scan findings |
| `ecr-config` | CSV | ECR repository configuration |
| `ecs` | CSV | ECS clusters |
| `eks` | CSV | EKS clusters |

### Database & Backup

| Key | Output | Description |
|-----|--------|-------------|
| `backup` | JSON | AWS Backup job history |
| `backup-plans` | CSV | AWS Backup plans |
| `backup-vaults` | CSV | Backup vault configuration |
| `rds-backup-config` | CSV | RDS backup configuration |
| `rds-inventory` | CSV | RDS instance inventory |
| `rds` | JSON | RDS snapshots (last 30 days) |
| `rds-snapshots` | CSV | RDS snapshots current state |

### Encryption & Secrets

| Key | Output | Description |
|-----|--------|-------------|
| `ebs-encryption` | CSV | EBS default encryption |
| `ebs-config` | CSV | EBS encryption configuration |
| `kms-config` | CSV | KMS key full configuration |
| `kms-policies` | CSV | KMS key policies |
| `kms` | CSV | KMS keys |
| `secrets` | CSV | Secrets Manager secrets |
| `secrets-policies` | CSV | Secrets Manager resource policies |

### Identity & Access

| Key | Output | Description |
|-----|--------|-------------|
| `access-analyzer` | CSV | IAM Access Analyzer findings |
| `iam-access-keys` | CSV | IAM access keys |
| `iam-account-summary` | CSV | IAM account summary |
| `iam-certs` | CSV | IAM server certificates |
| `iam-password-policy` | CSV | IAM account password policy |
| `iam-policies` | CSV | IAM managed policies |
| `iam-role-policies` | CSV | IAM role inline/attached policies |
| `iam-trusts` | CSV | IAM role trust policies |
| `iam-roles` | CSV | IAM roles |
| `iam-user-policies` | CSV | IAM user policies |
| `iam-users` | CSV | IAM users |
| `saml-providers` | CSV | SAML identity provider configuration |

### Monitoring & Events

| Key | Output | Description |
|-----|--------|-------------|
| `cw-alarms` | CSV | CloudWatch alarms (active) |
| `cw-log-groups` | CSV | CloudWatch log groups |
| `cw-config-alarms` | CSV | CloudWatch alarms (all) |
| `cw-log-config` | CSV | CloudWatch log group configuration |
| `change-event-rules` | CSV | EventBridge change rules |
| `eventbridge-rules` | CSV | EventBridge rules |
| `metric-filters` | CSV | Log metric filters and alarms |
| `metric-filter-config` | CSV | Metric filter configuration |
| `sns-policies` | CSV | SNS topic resource policies |
| `sns` | CSV | SNS topic subscribers |

### Network

| Key | Output | Description |
|-----|--------|-------------|
| `acm` | CSV | ACM certificates |
| `alb-logs` | CSV | ALB access log configuration |
| `igw` | CSV | Internet gateways |
| `elb-full-config` | CSV | Load balancer full configuration |
| `elb-listeners` | CSV | Load balancer listeners |
| `elb` | CSV | Load balancers |
| `nat-gateways` | CSV | NAT gateways |
| `nacl` | CSV | Network ACLs |
| `public-resources` | CSV | Publicly exposed resources |
| `rt-config` | CSV | Route table configuration |
| `route-tables` | CSV | Route tables |
| `sg-config` | CSV | Security group configuration |
| `security-groups` | CSV | Security groups |
| `vpc-config` | CSV | VPC configuration |
| `vpc-endpoints` | CSV | VPC endpoints |
| `vpc-flow-logs` | CSV | VPC flow logging |
| `vpc` | CSV | VPCs |
| `waf-config` | CSV | WAF full configuration |
| `waf-logging` | CSV | WAF logging configuration |
| `waf` | CSV | WAF regional web ACLs |

### Organization & Account

| Key | Output | Description |
|-----|--------|-------------|
| `account-contacts` | CSV | Account alternate contacts |
| `org-config` | CSV | AWS Organizations configuration *(requires org master)* |
| `scp` | CSV | Organization Service Control Policies *(requires org admin)* |
| `resource-tags` | CSV | Resource tagging configuration |

### Security Detection

| Key | Output | Description |
|-----|--------|-------------|
| `guardduty-config` | CSV | GuardDuty detector configuration |
| `guardduty` | CSV | GuardDuty findings |
| `gd-full-config` | CSV | GuardDuty full configuration |
| `guardduty-rules` | CSV | GuardDuty suppression rules |
| `inspector-history` | CSV | Inspector2 findings history |
| `inspector-config` | CSV | Inspector2 configuration |
| `inspector-ecr-images` | CSV | Inspector2 ECR image findings |
| `inspector` | CSV | Inspector2 findings |
| `inspector-sbom` | CSV | Inspector2 SBOM export (requires `--sbom-bucket`, `--sbom-kms-key`) |
| `macie` | CSV | Macie findings |
| `securityhub` | CSV | Security Hub findings |
| `sh-config` | CSV | Security Hub configuration |
| `sh-standards` | CSV | Security Hub enabled standards |

### Storage

| Key | Output | Description |
|-----|--------|-------------|
| `dynamodb` | CSV | DynamoDB tables |
| `ebs` | CSV | EBS volumes |
| `efs` | CSV | EFS file systems |
| `elasticache` | CSV | ElastiCache clusters |
| `elasticache-global` | CSV | ElastiCache global datastores |
| `s3-logging` | CSV | S3 bucket access logging |
| `s3-policies` | CSV | S3 bucket policies (summary) |
| `s3-bucket-policy` | CSV | S3 bucket policies (full document) |
| `s3-config` | CSV | S3 buckets configuration |
| `s3-data-events` | CSV | S3 data events configuration |
| `s3-encryption` | CSV | S3 encryption configuration |
| `s3-logging-config` | CSV | S3 logging configuration |
| `s3-public-access` | CSV | S3 public access block |

---

## Inventory Asset Types

Used with `--inventory` mode. The individual flags (`--ec2`, `--rds`, etc.) and `--inventory-types` are additive. If nothing is specified, all types are collected.

| Flag | `--inventory-types` Key | Asset Description |
|------|------------------------|------------------|
| `--kms` | `kms-key` | KMS customer-managed keys |
| `--s3` | `s3-bucket` | S3 buckets |
| `--lambda` | `lambda-function` | Lambda functions |
| `--ec2` | `ec2-instance` | EC2 instances |
| `--alb` | `alb` | Application Load Balancers |
| `--rds` | `rds-db-instance` | RDS DB instances |
| `--elasticache` | `elasticache-cluster` | ElastiCache clusters |
| `--containers` | `container` | Containers (ECR repositories, ECS clusters, EKS clusters) |

**Output file:** `AWS_Inventory-<timestamp>.csv` — 14-column canonical schema:

| Column | Description |
|--------|-------------|
| `UNIQUE ASSET IDENTIFIER` | ARN or primary ID |
| `IPv4 or IPv6 Address` | IP address (where applicable) |
| `Virtual` | Always `Yes` for cloud-managed services |
| `Public` | `Yes` if publicly reachable |
| `DNS Name or URL` | Public endpoint or DNS name |
| `MAC Address` | MAC address (EC2 ENI only) |
| `Location` | AWS region and/or AZ |
| `Asset Type` | Human-readable asset type label |
| `Hardware Make/Model` | Instance type or service tier |
| `Software/ Database Vendor` | AWS |
| `Software/ Database Name & Version` | Service name and engine version |
| `Function` | Functional role of the asset |
| `VLAN/ Network ID` | VPC ID or network identifier |
| `Comments` | Additional metadata |

---

## Config File Defaults

A `config.toml` in the project root (or `~/.config/evidence/config.toml`) sets defaults that apply to both TUI and CLI modes.

```toml
[defaults]
region                 = "us-east-1"
output_dir             = "./evidence-output"
start_date_offset_days = 90      # used by TUI only; CLI uses --lookback or --start-date
include_raw            = false
zip                    = false
sign                   = false

[defaults.collectors]
# Run only these collectors (exclusive — disables all others):
# enable = ["iam-users", "iam-roles", "s3-config"]

# Disable these from the default set:
disable = ["s3", "macie", "inspector", "inspector-config", "scp", "org-config"]

# Add these on top of the default set:
# enable_extra = ["sh-standards", "inspector"]
```

**Per-account overrides** in `[[account]]` blocks support the same `collectors.enable`, `collectors.disable`, and `collectors.enable_extra` keys and take precedence over `[defaults.collectors]`.

CLI `--collectors` always takes final precedence over both config defaults and account overrides.

---

## Exit Behavior

| Condition | Exit Code |
|-----------|-----------|
| Collection completed successfully | `0` |
| `--verify-manifest` — all files verified | `0` |
| Invalid flag combination or missing required flag | `1` |
| No collectors selected | `1` |
| AWS credential failure (all accounts) | `1` |
| Collection completed with some collector errors | `0` *(errors logged to stderr)* |

Collector-level errors (API permission denied, service not enabled) are non-fatal — collection continues for all other collectors and the errors are written to `evidence-collection.log` in the output directory.
