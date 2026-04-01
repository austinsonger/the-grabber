# evidence

A Rust CLI tool that collects AWS Backup compliance evidence from two independent sources:

- **AWS Backup API** — structured job records (`ListBackupJobs`)
- **AWS CloudTrail** — immutable audit log entries (`LookupEvents`)

Both sources are correlated and written to a single JSON report containing `StartBackupJob` and `BackupJobCompleted` events with timestamps, backup plan IDs, and resource identifiers — suitable for FedRAMP, SOC 2, or internal audit submissions.

---

## Requirements

- Rust 1.91.1 or later (`rustup update stable`)
- AWS credentials with the permissions listed below
- An AWS account with AWS Backup enabled and at least one completed backup job in the query window

---

## AWS Credentials Setup

The tool uses the standard AWS credential chain in this priority order:

1. **Environment variables** — fastest for CI/CD
2. **AWS profile** (`~/.aws/credentials` + `~/.aws/config`) — recommended for local use
3. **IAM role** (EC2 instance profile, ECS task role, Lambda execution role)
4. **AWS SSO** — via `aws sso login`

### Option 1 — Environment Variables

```bash
export AWS_ACCESS_KEY_ID=AKIA...
export AWS_SECRET_ACCESS_KEY=...
export AWS_DEFAULT_REGION=us-east-1
```

For temporary credentials (assumed role, SSO, etc.) also set:

```bash
export AWS_SESSION_TOKEN=...
```

### Option 2 — Named Profile (`~/.aws/config`)

```ini
[profile evidence-collector]
region = us-east-1
output = json
```

```ini
# ~/.aws/credentials
[evidence-collector]
aws_access_key_id = AKIA...
aws_secret_access_key = ...
```

Then activate the profile before running:

```bash
export AWS_PROFILE=evidence-collector
```

### Option 3 — AWS SSO

```bash
aws configure sso
# follow prompts to set up SSO profile

aws sso login --profile my-sso-profile
export AWS_PROFILE=my-sso-profile
```

### Option 4 — Assume a Role

```bash
eval $(aws sts assume-role \
  --role-arn arn:aws:iam::123456789012:role/EvidenceCollectorRole \
  --role-session-name evidence-session \
  --query 'Credentials.[AccessKeyId,SecretAccessKey,SessionToken]' \
  --output text | awk '{print "export AWS_ACCESS_KEY_ID="$1"\nexport AWS_SECRET_ACCESS_KEY="$2"\nexport AWS_SESSION_TOKEN="$3}')
```

---

## IAM Permissions

The identity (user or role) running this tool needs the following minimum permissions.
A ready-to-use policy document is at [iam/evidence-collector-policy.json](iam/evidence-collector-policy.json).

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "cloudtrail:LookupEvents",
        "backup:ListBackupJobs",
        "backup:DescribeBackupJob"
      ],
      "Resource": "*"
    }
  ]
}
```

### Attach the policy via AWS CLI

```bash
# Create the policy
aws iam create-policy \
  --policy-name EvidenceCollectorPolicy \
  --policy-document file://iam/evidence-collector-policy.json

# Attach to a user
aws iam attach-user-policy \
  --user-name <your-user> \
  --policy-arn arn:aws:iam::<account-id>:policy/EvidenceCollectorPolicy

# Or attach to a role
aws iam attach-role-policy \
  --role-name <your-role> \
  --policy-arn arn:aws:iam::<account-id>:policy/EvidenceCollectorPolicy
```

---

## Installation

```bash
git clone <repo-url>
cd evidence
cargo build --release
```

The binary will be at `target/release/evidence`.

Optionally install to `~/.cargo/bin`:

```bash
cargo install --path .
```

---

## Usage

```
evidence --start-date <YYYY-MM-DD> --end-date <YYYY-MM-DD> [OPTIONS]
```

### Options

| Flag | Default | Description |
|------|---------|-------------|
| `--start-date` | *(required)* | Start of query window, inclusive |
| `--end-date` | *(required)* | End of query window, inclusive |
| `--region` | `us-east-1` | AWS region to query |
| `-o, --output` | stdout | Write JSON report to this file |
| `--backup-plan-id` | *(all plans)* | Filter results to a specific backup plan ID |
| `--collectors` | `cloudtrail,backup` | Comma-separated list of collectors to run |
| `--include-raw` | off | Embed full CloudTrail event JSON in each record |

### Examples

Collect all backup evidence for March 2026, write to a file:

```bash
evidence \
  --start-date 2026-03-01 \
  --end-date 2026-03-31 \
  --region us-east-1 \
  --output evidence-march-2026.json
```

Run only the Backup API collector (faster, no CloudTrail rate limiting):

```bash
evidence \
  --start-date 2026-03-01 \
  --end-date 2026-03-31 \
  --collectors backup \
  --output evidence-backup-only.json
```

Filter to a specific backup plan and include raw CloudTrail events:

```bash
evidence \
  --start-date 2026-03-01 \
  --end-date 2026-03-31 \
  --backup-plan-id abc123-plan-id \
  --include-raw \
  --output evidence-plan-abc123.json
```

---

## Output Format

The report is a single JSON object:

```json
{
  "metadata": {
    "collected_at": "2026-04-01T12:00:00Z",
    "region": "us-east-1",
    "start_date": "2026-03-01",
    "end_date": "2026-03-31",
    "filter": null
  },
  "sections": [
    {
      "collector": "CloudTrail",
      "record_count": 42,
      "records": [
        {
          "source": "cloud_trail",
          "event_name": "StartBackupJob",
          "timestamp": "2026-03-15T02:00:01Z",
          "job_id": "abc-123",
          "plan_id": "plan-xyz",
          "resource_arn": "arn:aws:ec2:us-east-1:123456789012:volume/vol-0abc",
          "resource_type": "EBS",
          "status": null
        }
      ]
    },
    {
      "collector": "AWS Backup",
      "record_count": 84,
      "records": [
        {
          "source": "backup_api",
          "event_name": "StartBackupJob",
          "timestamp": "2026-03-15T02:00:00Z",
          "job_id": "abc-123",
          "plan_id": "plan-xyz",
          "resource_arn": "arn:aws:ec2:us-east-1:123456789012:volume/vol-0abc",
          "resource_type": "EBS",
          "status": "COMPLETED",
          "completion_timestamp": "2026-03-15T02:47:33Z"
        },
        {
          "source": "backup_api",
          "event_name": "BackupJobCompleted",
          "timestamp": "2026-03-15T02:47:33Z",
          "job_id": "abc-123",
          "plan_id": "plan-xyz",
          "resource_arn": "arn:aws:ec2:us-east-1:123456789012:volume/vol-0abc",
          "resource_type": "EBS",
          "status": "COMPLETED",
          "completion_timestamp": "2026-03-15T02:47:33Z"
        }
      ]
    }
  ]
}
```

**Note on dual sources**: The Backup API section provides structured, reliable job data including completion status and timestamps. The CloudTrail section provides the immutable audit trail — auditors often require both to satisfy the "automated initiation and completion" evidence requirement.

---

## Adding New Evidence Collectors

The project is designed to be extended. To add a new evidence type (e.g. GuardDuty findings, AWS Config compliance, IAM Access Analyzer):

1. Create a new module, e.g. `src/guardduty.rs`
2. Implement the `EvidenceCollector` trait:

```rust
use async_trait::async_trait;
use crate::evidence::{CollectParams, EvidenceCollector, EvidenceRecord};

pub struct GuardDutyCollector { /* AWS client */ }

#[async_trait]
impl EvidenceCollector for GuardDutyCollector {
    fn name(&self) -> &str { "GuardDuty" }

    async fn collect(&self, params: &CollectParams) -> anyhow::Result<Vec<EvidenceRecord>> {
        // query the AWS API, map results to EvidenceRecord, return
        todo!()
    }
}
```

3. Add the SDK dependency to `Cargo.toml`:

```toml
aws-sdk-guardduty = "1"
```

4. Register it in `src/main.rs` — find the collector registration block and add one line:

```rust
let all_collectors: Vec<(&str, Box<dyn EvidenceCollector>)> = vec![
    ("cloudtrail", Box::new(CloudTrailCollector::new(&config))),
    ("backup",     Box::new(BackupCollector::new(&config))),
    ("guardduty",  Box::new(GuardDutyCollector::new(&config))),  // <-- add this
];
```

The new collector will automatically appear in `--help`, be selectable via `--collectors guardduty`, and produce a named section in the JSON report.

---

## Troubleshooting

**`NoCredentialsError` / `CredentialsNotLoaded`**
Run `aws sts get-caller-identity` to verify your credentials are valid before running the tool.

**`AccessDeniedException` on CloudTrail or Backup**
Check that the IAM policy above is attached to your identity. Use `aws iam simulate-principal-policy` to test permissions without making real API calls.

**CloudTrail returns 0 events but Backup API returns jobs**
CloudTrail `LookupEvents` only returns events from the last 90 days. For older data, use only `--collectors backup`.

**Rate limit errors from CloudTrail**
The tool already adds a 500 ms delay between paginated CloudTrail calls. If you're still hitting limits, use `--collectors backup` to skip CloudTrail entirely.

**Backup API returns jobs but `plan_id` is null**
Jobs created manually (not from a backup plan) do not have a `plan_id`. This is expected.
