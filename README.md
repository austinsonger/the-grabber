# The Grabber

The Grabber. Collects current-state snapshots and time-windowed audit records from AWS, Okta, Jira, and Tenable, writing them as CSV and JSON. Supports exporting inventory and POA&M artifacts using FedRAMP-aligned templates, suitable for FedRAMP, SOC 2, HIPAA, or internal audits.

![Alt text](assets/1.Grabber_LandingPage.png)

---

## Features

- **Interactive TUI** — wizard-style interface for selecting accounts, date ranges, collectors, and options
- **Multi-account support** — TOML config drives an account picker; each account maps to an AWS SSO profile
- **200+ collectors across four providers** — 144 AWS, 24 Okta, 28 Jira, 5 Tenable (see `evidence-list.md` for the current catalog)
- **Dual output formats** — structured JSON (inventory/policy data) and CSV (tabular snapshots)
- **Chain-of-custody audit trail** — per-run `CHAIN-OF-CUSTODY-*.json` and an append-only `CHAIN-OF-CUSTODY.jsonl` log capture operator identity, hostname, AWS caller ARN, and the sanitized CLI invocation
- **Run manifest** — `RUN-MANIFEST-*.json` records every collector's outcome (success/empty/error/timeout), record count, and file size
- **Zip bundling** — `--zip` packages all output files into a single `Evidence-<timestamp>.zip`
- **HMAC-SHA256 signing** — `--sign` generates a cryptographic manifest over every output file for tamper detection
- **Per-collector timeouts** — collectors that hang are cancelled after 3 minutes and collection continues
- **Clean TUI output** — all WARN messages are captured to `evidence-collection.log` so the terminal stays readable
- **Non-interactive CLI** — pass flags directly for scripted/CI use

---

## Requirements

- Rust 1.75 or later (`rustup update stable`)
- AWS CLI v2 with configured SSO or credential profiles
- IAM permissions for the services you want to collect (see [IAM Permissions](#iam-permissions))

---

## Configuration

Create `config.toml`:

```toml
[defaults]
region                 = "us-east-1"
output_dir             = "./evidence-output"
start_date_offset_days = 90      # start date = today minus N days
include_raw            = false

[defaults.collectors]
disable = [
    "s3",                # requires --s3-bucket flag
    "macie",             # optional service
    "scp",               # requires org admin role
    "org-config",        # requires org master account
]

[[account]]
name        = "Production"
account_id  = "123456789012"
profile     = "ProdAdmin-123456789012"   # must match a profile in ~/.aws/config
region      = "us-east-1"
output_dir  = "./evidence-output/production"

[[account]]
name        = "Operations"
account_id  = "098765432109"
profile     = "OpsAdmin-098765432109"
region      = "us-east-1"
output_dir  = "./evidence-output/operations"

# Master account — add org-level collectors
[[account]]
name        = "Master"
account_id  = "111122223333"
profile     = "MasterAdmin-111122223333"
region      = "us-east-1"
output_dir  = "./evidence-output/master"

[account.collectors]
enable_extra = ["scp", "org-config"]
```

The `name` field becomes the prefix on every output file (e.g. `Production_IAM_Roles-2026-04-01-120000.json`).

### Collector resolution order

For each account, the active collector set is resolved as follows:

1. If `enable` is set → run **only** those collectors (exclusive list)
2. Otherwise: start with all defaults, remove any in `disable`, then add any in `enable_extra`

This lets you lock an account to a minimal set, opt out of expensive collectors, or layer on org-level collectors without duplicating the full default list.

Profile names must exactly match entries in `~/.aws/config`. To find your profile names:

```bash
aws configure list-profiles
```

---

## AWS SSO Login

Authenticate before running:

```bash
# Login to your SSO session (session name is in ~/.aws/config)
aws sso login --sso-session <session-name>

# Verify a profile works
aws sts get-caller-identity --profile <profile-name>
```

To add a new profile for an account/role you have access to, add a block to `~/.aws/config`:

```ini
[profile RoleName-AccountId]
sso_session   = <session-name>
sso_account_id = 123456789012
sso_role_name  = RoleName
region         = us-east-1
```

---

## Usage

### Interactive TUI (recommended)

The binary must be built before running. From the repo root:

```bash
# Build once (output: target/release/grabber)
cargo build --release

# Run directly
./target/release/grabber

# Or install to PATH
cargo install --path .
grabber
```




The wizard opens on a **Welcome** screen, then a **Feature Selection** screen (Evidence Collection / Inventory / POA&M / Tenable scan). Once a feature is chosen, the wizard walks through the steps below (some steps only apply to particular providers or features — for example the All-Regions toggle is only shown for AWS accounts, and Tenable adds a Scan Selection step).

---

### Account

Displays every `[[account]]` block from your `config.toml` as a selectable list. Each row shows the account name, account ID, AWS profile, and region.

Navigate with `↑`/`↓` and press `Enter` to select. Selecting an account:

- Sets the AWS profile, region, and output directory from that account's config block.
- Applies any per-account collector overrides (`enable`, `disable`, `enable_extra`) before you reach the Collectors step — so the collector list is already filtered for that account.

An **Other** option at the bottom falls back to a manual profile/region picker if the account is not in config.

![Alt text](assets/2.Grabber_AccountSelector.png)


---

### Dates

Two text fields: **Start Date** and **End Date** (format: `YYYY-MM-DD`).

`Tab` switches between fields and clears the newly focused field so you type fresh. `Ctrl+U` clears the current field. Dates are validated on `Enter` — an invalid format shows an inline error and does not advance.

These dates bound all time-windowed collectors (CloudTrail events, Backup job history, RDS backup events, etc.). Snapshot collectors (IAM, EC2, S3, etc.) run at the current moment regardless.


![Alt text](assets/3.Grabber_DateRange.png)


---

### Collectors

A scrollable checklist of 144 AWS collectors grouped into categories (IAM, EC2/Networking, Storage, RDS, KMS, CloudTrail, Config, Security Services, SSM, Monitoring, Containers, etc.). Non-AWS providers (Okta, Jira, Tenable) surface their own per-provider collector menus with only the keys relevant to that provider.

- `Space` toggles the collector under the cursor.
- The title shows **X of Y selected** as you make changes.
- Per-account `disable` and `enable_extra` overrides from `config.toml` are already applied — disabled collectors are pre-unchecked and extra collectors are pre-checked.
- At least one collector must be selected to advance.


![Alt text](assets/4.Grabber_CollectorsSelection.png)




---

### Options

Two settings:

| Setting | Description |
|---------|-------------|
| **Output Dir** | Read-only — sourced from the selected account's `output_dir` in config. |
| **Include Raw** | Toggle (`Space`) between **Disabled** and **Enabled**. When enabled, the full raw AWS API response is embedded inside each JSON evidence record. Off by default. |

`Tab` moves between fields.

![Alt text](assets/5.Grabber_Options.png)

---

### Confirm

A summary screen showing all selected settings before anything runs:

- Profile, Region, Start Date, End Date
- Number of collectors selected
- Output directory, Include Raw setting

Press `Enter` (or the **▸▸ Start Collection ◂◂** button) to begin. No AWS calls have been made up to this point.


![Alt text](assets/6.Grabber_Confirm.png)


---

### Run

Collection executes all selected collectors concurrently. The screen shows:

- **Progress bar** — `X / Y collectors` complete.
- **Collector list** — each entry shows a live status icon: `·` waiting, spinner running, `✓` done with record count, `✗` failed with error message.
- **Stats card** — elapsed time, completed count, total records collected, error count.
- **Activity log** — reverse-chronological feed of the last 20 collector events (started / finished / failed).

Each collector has a **3-minute timeout** — if it hangs it is cancelled and collection continues. All `WARN`-level messages are written to `evidence-collection.log` in the output directory so the terminal stays readable.

When all collectors finish, the **Results** screen shows a success banner, total file count, total record count, and the full list of output file paths written.

![Alt text](assets/7.Grabber_Running.png)



## Non-interactive CLI

### Evidence collection mode

```bash
./target/release/grabber \
  --start-date 2026-01-01 \
  --end-date   2026-04-01 \
  --region     us-east-1 \
  --profile    ProdAdmin-123456789012
```

Passing `--start-date` bypasses the TUI entirely and runs an evidence collection non-interactively.

### Inventory mode

```bash
./target/release/grabber \
  --inventory \
  --profile ProdAdmin-123456789012
```

Inventory mode runs the unified asset inventory workflow from the CLI and does not use `--start-date` or `--end-date`. Verification-only mode is also available with `--verify-manifest`.

```bash
# From a local checkout without installing to PATH
cargo run -- --help

# Or, after cargo build --release
./target/release/grabber --help

# Or, if you already installed it with cargo install --path .
grabber --help
```

Use the help output from the binary you are actually invoking as the source-of-truth flag list. The summary below explains the current flags and how they behave today.

For copy-paste CLI and inventory examples, see [cli-examples.md](cli-examples.md).

## CLI Options

Non-interactive mode is enabled by providing any of `--start-date`, `--lookback`, `--inventory`, `--poam`, or `--verify-manifest`. Omitting all of them launches the TUI.

| Flag | Default | Description |
|------|---------|-------------|
| `--start-date` | — | Start of collection window (YYYY-MM-DD). Requires `--end-date`. |
| `--end-date` | — | End of collection window (YYYY-MM-DD). Required with `--start-date`. |
| `--lookback` | — | Lookback window from today, e.g. `30`, `30d`, `12w`, `3m`, `1y`. Bare integers = days. Cannot combine with `--start-date`/`--end-date`. |
| `--region` | `us-east-1` | Primary AWS region |
| `--profile` | ambient | AWS named profile |
| `-o`, `--output` | current directory | Output directory for collected evidence |
| `--filter` | — | Optional filter string passed to supported time-windowed collectors |
| `--include-raw` | off | Embed raw AWS API response inside each JSON record |
| `--collectors` | full configured set | Comma-separated collector keys. See `evidence-list.md`. |
| `--all-regions` | off | Collect from every enabled AWS region (round-robin). AWS only. |
| `--regions` | — | Explicit comma-separated region list |
| `--s3-bucket` / `--s3-prefix` / `--s3-profile` / `--s3-accounts` / `--s3-regions` | — | Options for the `s3` CloudTrail-from-S3 collector |
| `--zip` | off | Bundle all output files into `Evidence-<timestamp>.zip` |
| `--sign` | off | HMAC-SHA256 sign all files; writes `SIGNING-MANIFEST-<ts>.json` + `SIGNING-<ts>.key` |
| `--signing-key` | auto | 64-char hex key to sign or verify with |
| `--verify-manifest` | — | Verify an existing `SIGNING-MANIFEST-*.json` (no collection) |
| `--write-run-manifest` | off | Opt in to `RUN-MANIFEST-<run_id>.json` (collectors mode) |
| `--write-chain-of-custody` | off | Opt in to `CHAIN-OF-CUSTODY-<run_id>.json` + `CHAIN-OF-CUSTODY.jsonl` (collectors mode) |
| `--inventory` | off | Run the unified inventory workflow (see Inventory below) |
| `--inventory-all-accounts` | off | With `--inventory`: merge inventory from every configured account into one unified CSV+XLSX (mutually exclusive with `--profile`) |
| `--skip-inventory-csv` | off | Skip the unified CSV (XLSX still written) |
| `--inventory-types` | all types | Comma-separated asset-type keys: `kms-key,s3-bucket,lambda-function,ec2-instance,alb,rds-db-instance,elasticache-cluster,container` |
| `--kms` / `--s3` / `--lambda` / `--ec2` / `--alb` / `--rds` / `--elasticache` / `--containers` | off | Individual inventory asset-type opt-ins; additive with `--inventory-types` |
| `--poam` | off | Run POA&M reconciliation (requires `--poam-year` and `--poam-month`) |
| `--poam-year` | — | 4-digit findings year, e.g. `2026` |
| `--poam-month` | — | Month name, e.g. `January` … `December` |
| `--poam-evidence-base` | `evidence-output/security` | Base evidence directory for POA&M reconciliation |
| `--sbom-bucket` / `--sbom-kms-key` / `--sbom-format` | — / — / `cyclonedx14` | Inspector V2 SBOM export destination + format (`cyclonedx14` or `spdx23`) for the `inspector-sbom` collector |

### CLI mode notes

1. Any of `--start-date`, `--lookback`, `--inventory`, `--poam`, or `--verify-manifest` bypasses the TUI.
2. `--verify-manifest` is a standalone verification path and requires `--signing-key`.
3. `--collectors` accepts keys across every enabled provider (AWS/Okta/Jira/Tenable); the maintained key list lives in `evidence-list.md`.
4. `--inventory` writes the unified `AWS_Inventory-<timestamp>.csv` plus the FedRAMP-templated `.xlsx` when `assets/Inventory.xlsx` is present. `RUN-MANIFEST` and `CHAIN-OF-CUSTODY` files are opt-in via their `--write-*` flags in collectors mode only.

---

## Output Files

Files are written to the configured output directory. Filenames follow the pattern:

```
<AccountName>_<CollectorName>-<YYYY-MM-DD-HHmmss>.<csv|json>
```

Example:
```
evidence-output/production/
  Production_IAM_Roles-2026-04-01-120000.json
  Production_IAM_Users-2026-04-01-120000.csv
  Production_KMS_Key_Configuration-2026-04-01-120000.json
  Production_SecurityHub_Findings-2026-04-01-120000.csv
  ...
  RUN-MANIFEST-<run_id>.json        ← per-run outcome record
  CHAIN-OF-CUSTODY-<run_id>.json    ← immutable per-run audit entry
  CHAIN-OF-CUSTODY.jsonl            ← append-only log of all runs
  evidence-collection.log           ← WARN messages from all collectors
```

### JSON envelope

JSON files (inventory/policy data) include a metadata envelope:

```json
{
  "collected_at": "2026-04-01T12:00:00Z",
  "account_id": "Production",
  "region": "us-east-1",
  "collector": "IAM Roles",
  "record_count": 42,
  "records": [ ... ]
}
```

### Run manifest

`RUN-MANIFEST-<run_id>.json` records the outcome of every collector in the run:

```json
{
  "run_id": "abc123",
  "tool_version": "0.1.0",
  "account_id": "123456789012",
  "region": "us-east-1",
  "collection_window": { "start": "2026-01-01", "end": "2026-04-01" },
  "summary": {
    "succeeded": 118,
    "empty": 4,
    "failed": 1,
    "timed_out": 1,
    "total_files": 120,
    "total_records": 84321
  },
  "collectors": [
    {
      "name": "IAM Roles",
      "status": "Success",
      "record_count": 42,
      "filename": "Production_IAM_Roles-2026-04-01-120000.json",
      "file_size_bytes": 15892
    }
  ]
}
```

### Chain of custody

`CHAIN-OF-CUSTODY-<run_id>.json` is written once per run and captures who ran it, from where, and with which AWS identity:

```json
{
  "run_id": "abc123",
  "operator": "jsmith",
  "hostname": "laptop-001.example.com",
  "local_ip": "10.0.1.50",
  "aws_identity": {
    "account_id": "123456789012",
    "caller_arn": "arn:aws:sts::123456789012:assumed-role/AuditRole/jsmith",
    "user_id": "AROA..."
  },
  "profile": "ProdAdmin-123456789012",
  "region": "us-east-1",
  "cli_invocation": "grabber --start-date 2026-01-01 --profile ProdAdmin-123456789012",
  "started_at": "2026-04-01T12:00:00Z"
}
```

`CHAIN-OF-CUSTODY.jsonl` accumulates one entry per run in NDJSON format, providing a persistent audit log across all collection runs against an output directory. Signing keys are automatically redacted from the stored CLI invocation.

### Zip and signing

When `--zip` is passed, all output files (evidence, manifest, chain-of-custody) are bundled into `Evidence-<timestamp>.zip` after collection completes.

When `--sign` is passed, an HMAC-SHA256 digest is computed for every output file and written to `SIGNING-MANIFEST-<timestamp>.json` alongside `SIGNING-<timestamp>.key` (the hex-encoded HMAC key). Move the `.key` file to secure storage separate from the evidence before sharing — anyone with the key can forge the manifest. The manifest can be verified later with `--verify-manifest` + `--signing-key`.

---

## Collectors

### Time-windowed (query a date range)

| Key | Description |
|-----|-------------|
| `cloudtrail` | CloudTrail management events |
| `s3` | CloudTrail S3 data events (requires `--s3-bucket`) |
| `backup` | AWS Backup job records |
| `rds` | RDS automated backup events |

### IAM

| Key | Output | Description |
|-----|--------|-------------|
| `iam-users` | CSV | Users with MFA status, last login, key status |
| `iam-roles` | JSON | Roles with trust policies and attached policies |
| `iam-policies` | CSV | Customer-managed policies with permissions summary |
| `iam-access-keys` | CSV | Access keys with status and last-used date |
| `iam-role-policies` | JSON | Role inline and attached policies |
| `iam-user-policies` | JSON | User inline, attached policies, permissions boundary |
| `iam-trusts` | CSV | Cross-account and service trust relationships |
| `iam-certs` | CSV | Server certificates |
| `iam-password-policy` | CSV | Account password policy |
| `iam-account-summary` | CSV | Account-level IAM summary |
| `saml-providers` | CSV | SAML identity provider configs |
| `access-analyzer` | CSV | IAM Access Analyzer findings |

### EC2 / Networking

| Key | Output | Description |
|-----|--------|-------------|
| `ec2-instances` | CSV | Instance inventory |
| `ec2-detailed` | CSV | Detailed instance config |
| `ec2-config` | CSV | Instance-level config settings |
| `vpc` | CSV | VPC configuration |
| `vpc-config` | CSV | VPC attributes |
| `vpc-flow-logs` | CSV | VPC flow log settings |
| `vpc-endpoints` | CSV | VPC endpoint inventory |
| `nacl` | CSV | Network ACL rules |
| `security-groups` | CSV | Security group rules |
| `sg-config` | CSV | Security group config details |
| `route-tables` | CSV | Route table entries |
| `rt-config` | CSV | Route table configuration |
| `igw` | CSV | Internet gateways |
| `nat-gateways` | CSV | NAT gateways |
| `launch-templates` | CSV | EC2 launch templates |
| `ebs` | CSV | EBS volume inventory |
| `ebs-config` | CSV | EBS volume configuration |
| `ebs-encryption` | CSV | EBS default encryption settings |

### Storage

| Key | Output | Description |
|-----|--------|-------------|
| `s3-config` | CSV | S3 bucket configuration |
| `s3-logging` | CSV | S3 access logging settings |
| `s3-logging-config` | CSV | S3 logging configuration detail |
| `s3-encryption` | CSV | S3 bucket encryption settings |
| `s3-public-access` | CSV | S3 public access block settings |
| `s3-policies` | CSV | S3 bucket policies |
| `s3-bucket-policy` | CSV | S3 bucket policy detail |
| `s3-data-events` | CSV | S3 CloudTrail data event selectors |
| `efs` | CSV | EFS file systems |
| `dynamodb` | CSV | DynamoDB tables |

### RDS

| Key | Output | Description |
|-----|--------|-------------|
| `rds-inventory` | CSV | RDS instance inventory |
| `rds-snapshots` | CSV | Automated and manual snapshots |
| `rds-backup-config` | CSV | Backup retention and window settings |

### KMS

| Key | Output | Description |
|-----|--------|-------------|
| `kms` | CSV | KMS key inventory |
| `kms-config` | JSON | Key configuration with full key policy |
| `kms-policies` | CSV | Key policies summary |

### CloudTrail

| Key | Output | Description |
|-----|--------|-------------|
| `cloudtrail-config` | CSV | Trail inventory |
| `ct-selectors` | CSV | Event selector configuration |
| `ct-validation` | CSV | Log file validation settings |
| `ct-s3-policy` | CSV | S3 bucket policies for trails |
| `ct-full-config` | CSV | Full trail configuration |
| `ct-changes` | CSV | CloudTrail change events |
| `ct-config-changes` | JSON | Config-related CloudTrail events |
| `ct-iam-changes` | CSV | IAM-related CloudTrail events |

### AWS Config

| Key | Output | Description |
|-----|--------|-------------|
| `config-rules` | CSV | Config rules and compliance status |
| `config-history` | CSV | Config change history |
| `config-timeline` | CSV | Resource configuration timeline |
| `config-compliance` | CSV | Compliance history |
| `config-snapshot` | CSV | Config snapshot summary |
| `config-recorder` | CSV | Configuration recorder settings |

### Security Services

| Key | Output | Description |
|-----|--------|-------------|
| `guardduty` | CSV | GuardDuty findings |
| `guardduty-config` | CSV | GuardDuty detector configuration |
| `guardduty-rules` | CSV | GuardDuty suppression rules |
| `gd-full-config` | CSV | Full GuardDuty configuration |
| `securityhub` | CSV | Security Hub findings |
| `sh-standards` | CSV | Enabled Security Hub standards |
| `sh-config` | CSV | Security Hub configuration |
| `macie` | CSV | Macie findings (if enabled) |
| `inspector` | CSV | Inspector findings |
| `inspector-config` | CSV | Inspector configuration |
| `inspector-history` | CSV | Inspector findings history |
| `access-analyzer` | CSV | IAM Access Analyzer findings |
| `public-resources` | CSV | Publicly accessible resources |

### SSM / Patch Management

| Key | Output | Description |
|-----|--------|-------------|
| `ssm-patches` | CSV | SSM patch compliance |
| `ssm-patch-summary` | CSV | Patch compliance summary |
| `ssm-patch-detail` | CSV | Per-instance patch detail |
| `ssm-patch-exec` | CSV | Patch execution history |
| `ssm-baselines` | CSV | Patch baselines |
| `ssm-maint-windows` | CSV | Maintenance windows |
| `ssm-instances` | CSV | Managed instance inventory |
| `ssm-params` | CSV | Parameter Store entries |
| `time-sync` | CSV | EC2 time synchronization config |

### Monitoring / Alerting

| Key | Output | Description |
|-----|--------|-------------|
| `cw-alarms` | CSV | CloudWatch alarms |
| `cw-log-groups` | CSV | CloudWatch log groups |
| `cw-config-alarms` | CSV | Config-related CloudWatch alarms |
| `cw-log-config` | CSV | Log group configuration |
| `metric-filters` | CSV | Metric filter alarm mappings |
| `metric-filter-config` | CSV | Metric filter configuration |
| `change-event-rules` | CSV | EventBridge change event rules |
| `eventbridge-rules` | JSON | EventBridge rule configuration |

### Compute / Containers

| Key | Output | Description |
|-----|--------|-------------|
| `ecs` | CSV | ECS cluster inventory |
| `eks` | CSV | EKS cluster inventory |
| `ecr-config` | CSV | ECR repository configuration |
| `lambda-config` | CSV | Lambda function configuration |
| `lambda-permissions` | CSV | Lambda resource-based policies |
| `asg` | CSV | Auto Scaling groups |

### Other Services

| Key | Output | Description |
|-----|--------|-------------|
| `acm` | CSV | ACM certificates |
| `elb` | CSV | Load balancer inventory |
| `elb-listeners` | CSV | Load balancer listener rules |
| `elb-full-config` | CSV | Full load balancer configuration |
| `alb-logs` | CSV | ALB access log settings |
| `sns` | CSV | SNS topic subscriptions |
| `sns-policies` | CSV | SNS topic policies |
| `secrets` | CSV | Secrets Manager secrets |
| `secrets-policies` | CSV | Secrets Manager resource policies |
| `cloudfront` | CSV | CloudFront distributions |
| `api-gateway` | CSV | API Gateway inventory |
| `backup-plans` | CSV | AWS Backup plans |
| `backup-vaults` | CSV | AWS Backup vaults |
| `route53-zones` | CSV | Route 53 hosted zones |
| `route53-resolver` | CSV | Route 53 Resolver rules |
| `waf` | CSV | WAF web ACLs |
| `waf-config` | CSV | WAF configuration |
| `waf-logging` | CSV | WAF logging configuration |
| `elasticache` | CSV | ElastiCache clusters |
| `elasticache-global` | CSV | ElastiCache global datastores |
| `cfn-drift` | CSV | CloudFormation stack drift |
| `resource-tags` | CSV | Resource tagging inventory |
| `account-contacts` | CSV | Account alternate contacts |
| `scp` | CSV | Service Control Policies (org admin required) |
| `org-config` | CSV | Organization configuration (master account required) |

---

## IAM Permissions

The collecting identity needs read-only access to the services it queries. A minimal policy covering all collectors:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "access-analyzer:List*",
        "acm:List*", "acm:Describe*",
        "autoscaling:Describe*",
        "backup:List*", "backup:Describe*", "backup:Get*",
        "cloudformation:Describe*", "cloudformation:List*", "cloudformation:Detect*",
        "cloudfront:List*", "cloudfront:Get*",
        "cloudtrail:Describe*", "cloudtrail:Get*", "cloudtrail:List*", "cloudtrail:LookupEvents",
        "cloudwatch:Describe*", "cloudwatch:List*", "cloudwatch:Get*",
        "config:Describe*", "config:Get*", "config:List*", "config:Select*",
        "dynamodb:List*", "dynamodb:Describe*",
        "ec2:Describe*",
        "ecr:Describe*", "ecr:List*", "ecr:Get*",
        "ecs:List*", "ecs:Describe*",
        "efs:Describe*",
        "eks:List*", "eks:Describe*",
        "elasticache:Describe*",
        "elasticloadbalancing:Describe*",
        "guardduty:List*", "guardduty:Get*",
        "iam:List*", "iam:Get*", "iam:GenerateCredentialReport",
        "inspector2:List*", "inspector2:Get*",
        "kms:List*", "kms:Describe*", "kms:Get*",
        "lambda:List*", "lambda:Get*",
        "logs:Describe*", "logs:List*",
        "macie2:List*", "macie2:Get*",
        "organizations:List*", "organizations:Describe*",
        "rds:Describe*", "rds:List*",
        "route53:List*", "route53:Get*",
        "route53resolver:List*",
        "s3:List*", "s3:Get*",
        "secretsmanager:List*", "secretsmanager:Get*",
        "securityhub:Describe*", "securityhub:Get*", "securityhub:List*",
        "sns:List*", "sns:Get*",
        "ssm:Describe*", "ssm:List*", "ssm:Get*",
        "sts:GetCallerIdentity",
        "tag:Get*",
        "wafv2:List*", "wafv2:Get*"
      ],
      "Resource": "*"
    }
  ]
}
```

---

## Okta

Optional feature — build with `--features okta` (enabled by default).

### Configuration

Create `okta-config.toml` in the repo root (gitignored):

```toml
[[account]]
name           = "Okta"
provider       = "okta"
description    = "Okta production tenant"
output_dir     = "./evidence-output/okta"
okta_domain    = "https://acme.okta.com"
okta_api_token = ""
```

Or set the values via environment variables (env wins over TOML):

- `OKTA_DOMAIN` — e.g. `https://acme.okta.com`
- `OKTA_API_TOKEN` — SSWS API token

Create an API token in the Okta admin console: **Security → API → Tokens → Create token**.

The token inherits the role of the user that created it; for evidence collection the user needs at least the **Read-only Administrator** role.

### Collectors

Core inventory:

| Key | Output | Description |
|-----|--------|-------------|
| `okta-users` | CSV | All users with status, login, MFA-relevant timestamps |
| `okta-groups` | CSV | Groups with type, description, membership-updated timestamps |
| `okta-group-members` | CSV | Per-group membership lists |
| `okta-apps` | CSV | Applications with sign-on mode, status |
| `okta-policies` | CSV | Sign-on, password, MFA enrollment, IDP discovery, access, profile enrollment policies |
| `okta-factors` | CSV | Per-user enrolled MFA factors |
| `okta-system-log` | CSV | Time-windowed system log events (logins, MFA, admin actions) |

Compliance evidence (audit-oriented — most are time-windowed):

| Key | Output | Description |
|-----|--------|-------------|
| `okta-access-reviews` | CSV | Access certification campaigns |
| `okta-auto-provisioning` | CSV | Automated provisioning events |
| `okta-contractor-deprov` | CSV | Contractor deprovisioning records |
| `okta-deprovisioning` | CSV | Deprovisioning timeliness |
| `okta-group-changes` | CSV | Group membership change log |
| `okta-hris-config` | CSV | Lifecycle / HRIS integration config |
| `okta-offboarding-sla` | CSV | Offboarding SLA compliance |
| `okta-password-policy` | CSV | Password policy first-use records |
| `okta-prod-recert` | CSV | Production access recertification |
| `okta-publisher-groups` | CSV | Publisher group membership |
| `okta-risk-suspend` | CSV | Risk-based account suspend timing |
| `okta-session-policy` | CSV | Session policy configuration |
| `okta-shared-account-broker` | CSV | Shared-account broker config |
| `okta-shared-groups` | CSV | Group inventory (shared) |
| `okta-signin-widget` | CSV | Sign-in widget configuration |
| `okta-threat-insight` | CSV | ThreatInsight detections |
| `okta-transfer-diff` | CSV | Access diff on internal transfer |

### Required Okta API scopes

The SSWS token is bound to a user; minimum role: **Read-only Administrator**. For the System Log specifically, the user must also have permission to view the System Log (granted by the Read-only Administrator role by default).

---

## Jira

Optional feature — build with `--features jira` (enabled by default).

### Configuration

Create `jira-config.toml` in the repo root (gitignored):

```toml
[[account]]
name           = "Jira"
provider       = "jira"
description    = "Jira Cloud production tenant"
output_dir     = "./evidence-output/jira"
jira_domain    = "https://acme.atlassian.net"
jira_email     = "you@acme.com"
jira_api_token = ""
```

Or set the values via environment variables (env wins over TOML):

- `JIRA_DOMAIN` — e.g. `https://acme.atlassian.net`
- `JIRA_EMAIL` — the Atlassian account email used for Basic auth
- `JIRA_API_TOKEN` — API token

Create an API token at: **Atlassian account → Security → Create and manage API tokens**.

### Collectors

Core inventory:

| Key | Output | Description |
|-----|--------|-------------|
| `jira-projects` | CSV | All projects with key, name, type, lead, and category |
| `jira-issues` | CSV | All issues across projects with status, assignee, reporter, and timestamps |

Compliance evidence (time-windowed audit collectors targeting specific ISO/FedRAMP controls):

| Key | Output | Description |
|-----|--------|-------------|
| `jira-allowlist-review` | CSV | Allowlist / whitelist review tickets |
| `jira-audit-posture` | CSV | Audit posture change coordination |
| `jira-baseline-exceptions` | CSV | Baseline configuration exceptions |
| `jira-change-retention` | CSV | Change record retention |
| `jira-cp-test-poam` | CSV | CP test → POA&M linkage |
| `jira-cp-update` | CSV | Contingency plan update triggers |
| `jira-data-reassignment` | CSV | Data reassignment tickets |
| `jira-dr-test` | CSV | DR test results |
| `jira-external-system-approvals` | CSV | External system connection approvals |
| `jira-fw-exception` | CSV | Firewall exception duration tracking |
| `jira-ir-cp` | CSV | Incident-response ↔ contingency coordination |
| `jira-ir-external` | CSV | External IR reporting |
| `jira-ir-lessons` | CSV | IR lessons learned |
| `jira-ir-severity` | CSV | IR severity vs. rigor |
| `jira-isa-annual` | CSV | ISA annual review |
| `jira-logging-coordination` | CSV | Logging change coordination |
| `jira-malware-fp` | CSV | Malware false-positive tickets |
| `jira-offboarding-sla` | CSV | Offboarding SLA |
| `jira-patch-test` | CSV | Patch test records |
| `jira-public-content` | CSV | Public content review |
| `jira-remote-access-approvals` | CSV | Remote access approvals |
| `jira-remote-maint` | CSV | Remote maintenance approvals |
| `jira-sanctions-isso` | CSV | Sanctions / ISSO notifications |
| `jira-special-protection` | CSV | Special-protection approvals |
| `jira-sw-license` | CSV | Software license review |
| `jira-transfer-notify` | CSV | Internal transfer notifications |

The compliance collectors read a `[project_keys]` block in `jira-config.toml` that maps each collector to the project(s) and JQL fragments it should target. See `jira-config.example.toml` for the full schema.

### Required Jira permissions

The user behind the API token needs **Browse Projects** permission on every project that should be collected. For full coverage, use an account with site-admin / org-admin read rights.

---

## Tenable

Optional feature — build with `--features tenable` (enabled by default).

### Configuration

Create `tenable-config.toml` in the repo root (gitignored):

```toml
[[account]]
name              = "Tenable"
provider          = "tenable"
description       = "Tenable.io / Tenable Vulnerability Management"
output_dir        = "./evidence-output/tenable"
tenable_access_key = ""
tenable_secret_key = ""
```

Or via environment variables (env wins over TOML):

- `TENABLE_ACCESS_KEY`
- `TENABLE_SECRET_KEY`

### Collectors

| Key | Output | Description |
|-----|--------|-------------|
| `tenable-vulns` | CSV | Vulnerability findings (VM) |
| `tenable-was` | CSV | Web Application Scanning findings |
| `tenable-pci-asv` | CSV | PCI ASV scan results |
| `tenable-assets` | CSV | Asset inventory |
| `tenable-compliance` | CSV | Compliance / audit-file findings |

---

## Elastic

Optional feature — build with `--features elastic` (enabled by default).

### Configuration

Create `elastic-config.toml` in the repo root (gitignored):

```toml
[[account]]
name               = "Elastic"
provider           = "elastic"
description        = "Elastic Security production deployment"
output_dir         = "./evidence-output/elastic"
elastic_kibana_url = "https://my-deployment.kb.us-east-1.aws.found.io"
elastic_es_url     = "https://my-deployment.es.us-east-1.aws.found.io"
elastic_api_key    = ""
```

Or set the values via environment variables (env wins over TOML):

- `ELASTIC_KIBANA_URL` — Kibana base URL (Detection Engine, Exception Lists, Cases)
- `ELASTIC_ES_URL` — Elasticsearch base URL (direct alert search)
- `ELASTIC_API_KEY` — API key, base64-encoded `id:api_key` form

Create an API key in Kibana: **Stack Management → API Keys → Create API key**. Copy the "Encoded" value — this is what Kibana-created keys use to authenticate directly against both Kibana and Elasticsearch. The key needs the Security "Read" feature privilege (or higher) for Cases and Rule Management, plus read access to the `.alerts-security.alerts-*` index.

### Collectors

| Key | Output | Description |
|-----|--------|-------------|
| `elastic-rules` | CSV | Detection rules inventory (type, severity, risk score, enabled state) |
| `elastic-exceptions` | CSV | Exception list items across all exception lists |
| `elastic-alerts` | CSV | Time-windowed security alerts from `.alerts-security.alerts-*` |
| `elastic-cases` | CSV | Time-windowed Security Solution cases |

Elastic has no region concept, like Tenable/Okta/Jira — `--all-regions` and region selection do not apply.

---

## Azure / GCP

Both providers are compiled behind opt-in Cargo features (`--features azure`, `--features gcp`). They are stubs today — factory scaffolding exists in `src/providers/{azure,gcp}/` but no collectors ship yet. Enabling the feature will surface an empty provider in the TUI account picker; use `config.example.toml` as a reference for adding an `[[account]]` block when collectors land.

---

## Troubleshooting

**SSO token expired**
```bash
aws sso login --sso-session <session-name>
```

**Profile not found**
```bash
aws configure list-profiles   # see available profiles
aws configure sso             # add a new profile interactively
```

**Files created but empty / `dispatch failure` in log**
The SSO session expired mid-run or the profile lacks permissions. Re-authenticate and verify:
```bash
aws sts get-caller-identity --profile <profile-name>
```

**Collector hangs**
Each collector has a 3-minute timeout. If a collector consistently times out, disable it in `config.toml`:
```toml
[defaults.collectors]
disable = ["guardduty", "inspector"]
```

**TUI shows 0 files**
The output directory may not exist — it is created automatically on first run. Check that `output_dir` in `config.toml` is a writable path.

**Stack overflow at startup**
The runtime uses 16MB thread stacks to accommodate the large number of concurrent async collectors. If you see stack overflows on a constrained system, reduce the number of selected collectors.
