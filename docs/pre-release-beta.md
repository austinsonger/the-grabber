# Beta pre-release notes (June 2026)

This document summarizes new functionality on the `beta` branch compared with `main` and highlights what is ready now versus still in progress.

## Scope

- Baseline: `main` (AWS-only collector)
- Pre-release target: `beta` (multi-provider collector)

## New functionality in this pre-release

### 1) Multi-provider architecture

- Provider-aware collector system introduced via `ProviderFactory` and `CloudProvider` dispatch.
- Core provider set now includes AWS, Tenable, Okta, and Jira.
- Provider-oriented module layout under `src/providers/` replaces the previous flat collector layout.

### 2) New non-AWS providers (shipping)

- **Tenable**:
  - Dedicated crate: `crates/tenable-rs`
  - Collectors for vulnerabilities, assets, compliance, audit log, users/permissions, WAS, and PCI ASV
  - Endpoint support for commercial and FedRAMP Tenable clouds
- **Okta**:
  - Dedicated crate: `crates/okta-rs`
  - CSV collectors for users, groups, group members, apps, policies, factors, and system log
- **Jira**:
  - Dedicated crate: `crates/jira-rs`
  - Collectors for projects and issues
  - Optional project-key filtering integrated with issue collection

### 3) TUI workflow enhancements

- New provider-selection screen (`Screen::ProviderSelection`).
- Tenable-specific scan selection flow for VM and WAS scans.
- Jira project selection flow for targeted issue collection.
- Improved run output visibility with skipped-item panel support.

### 4) Expanded AWS coverage

New or expanded AWS collector coverage includes:

- ACM Private CA
- Client VPN
- Network Firewall
- Route 53 DNSSEC
- Shield / DDoS
- Service Quotas
- License Manager
- SSM software inventory
- SSM Session Manager logs
- CloudTrail Change Events / S3 Data Events
- Inspector V2 SBOM export

### 5) Evidence catalog expansion (Waves 1 + 2 — 111 new AWS collectors)

The catalog grew from 124 to **235 evidence sources** across two waves of expansion focused on NIST 800-53 IRL coverage and modern AWS service breadth.

#### Wave 1 — NIST 800-53 coverage (55 new collectors, EV125–EV179)

Targeted at the A-LIGN NIST 800-53 IRL (555 "General" evidence requests). New collectors group by control family:

- **CloudTrail / Audit (AU)** — account-management events, session events, privileged-action events, Insights, Lake event-data stores, Athena log-review queries
- **IAM / Access (AC, IA)** — credential report, Access Advisor, roles-last-used, Identity Center assignments, Identity Store users/groups, Cognito user pools, STS federation sources
- **Monitoring / Detective (AU, SI, CA)** — Logs Insights saved queries, EventBridge archives, Contributor Insights, Detective graphs, Security Hub insights, GuardDuty coverage, CloudWatch anomaly detectors, Firehose delivery streams
- **Backup / Contingency (CP)** — Backup vault-lock, copy actions, restore-testing plans, DRS replication status, Route53 ARC, RDS PITR/backtrack, S3 replication, S3 Object Lock
- **SI / Patch (SI, CM)** — SSM compliance summary, association compliance, automation executions, Inspector2 coverage and suppression rules
- **SA / SC (SA, SC)** — WAF logging destinations, VPC traffic mirroring, TGW route tables, PrivateLink services, Route53 Resolver DNS Firewall, KMS grants + rotation, AppMesh TLS
- **SR (Supply Chain)** — AWS Signer, ECR image signatures + registry scanning, CodeArtifact, Artifact reports, CodePipeline + CodeBuild config
- **Cross-cutting** — Trusted Advisor, AWS Health, Organizations delegated admins, Control Tower guardrails, Audit Manager assessments, Resource Explorer, FIS experiments, Synthetics canaries, Macie classification jobs

All 124 pre-existing collectors were also back-filled with `NIST_800_53` mappings under `framework_refs` in `framework_mapping/evidence-list.json`.

A NIST 800-53 IRL coverage report is published at `docs/nist-800-53-irl-coverage.md` mapping each control family to closing evidence collectors.

#### Wave 2 — Service breadth (56 new collectors, EV180–EV235)

Targeted at modern AWS surface area, organized by domain:

- **Cost & financial governance** — Cost Anomaly Detection, Budgets, Savings Plans + RIs, Compute Optimizer
- **Tag & SCP governance** — Resource Tagging Compliance, Organizations Tag Policies, SCP attachment graph
- **Identity deeper** — IAM Policy Simulator, Identity Center inline policies, IAM Roles Anywhere, IAM Permissions Boundaries
- **Operational / SRE** — SSM OpsItems, SSM Change Manager requests, Resilience Hub, OAM observability links, AppConfig deployments
- **Containers / K8s deeper** — EKS Add-ons, EKS Access Entries, EKS Pod Identity, ECS task definitions, ECR Replication
- **Data / streaming / analytics** — Glue Catalog, Lake Formation permissions, Redshift, OpenSearch, MSK, Step Functions, Kinesis Data Streams
- **Network deeper** — VPC Lattice, Verified Permissions, Direct Connect + VPN, Global Accelerator, API Gateway deep config, CloudFront OAC
- **Security tooling** — Network Firewall rules, Security Lake, Firewall Manager, GuardDuty Malware Protection + Runtime Monitoring, WAF rule groups deep
- **DR / migration** — MGN source servers, DMS replication, Snowball jobs
- **ML / AI** — SageMaker posture, Bedrock models + guardrails, Bedrock Knowledge Bases
- **IoT** — IoT Things + Policies, IoT Device Defender audit findings
- **Compliance & governance meta** — Config Conformance Packs, Config Aggregators, Well-Architected Workloads, Service Catalog
- **Drift detection** — Resource last-modified drift, CloudFormation StackSets drift, Trusted Advisor priority recommendations
- **Bonus** — App Runner services, Audit Manager evidence folders

#### Catalog summary

| Category | Pre-Wave-1 | After Wave 1 | After Wave 2 |
|---|---|---|---|
| JSON evidence collectors | 4 | 4 | 4 |
| CSV evidence collectors | 120 | 175 | 231 |
| Inventory asset types | 8 | 8 | 8 |
| **Total** | **124** | **179** | **235** |

#### New AWS services covered

AppConfig, AppMesh, App Runner, Artifact, Athena, Audit Manager, Bedrock, Budgets, CodeArtifact, CodeBuild, CodePipeline, Cognito, Compute Optimizer, Config Conformance/Aggregators, Control Tower, Cost Anomaly, Detective, Direct Connect, DMS, DRS, EKS access entries/add-ons/pod-identity, EventBridge Archives, Firehose, Firewall Manager, FIS, Global Accelerator, Glue, Health, Identity Center, Identity Store, IoT Core, IoT Device Defender, Kinesis, Lake Formation, MGN, MSK, OAM, OpenSearch, Redshift, Resilience Hub, Resource Explorer, Roles Anywhere, Route53 ARC, SageMaker, Savings Plans, Security Lake, Service Catalog, Signer, Snowball, Step Functions, Synthetics, Trusted Advisor, Verified Permissions, VPC Lattice, Well-Architected.

### 6) Output and execution behavior changes

- Manifest artifacts (`--write-run-manifest`, `--write-chain-of-custody`) are now opt-in instead of always-on.
- Provider-specific output folders are used under `evidence-output/` (for example, Jira and Okta outputs).
- Signing and verification pipeline remains compatible with existing behavior.

## In-progress providers (not shipping in this pre-release)

### Azure (`--features azure`)

- Scaffolded with provider module and factory.
- Dispatch and feature gating are wired.
- Service collectors are planned but not implemented yet.

### GCP (`--features gcp`)

- Scaffolded with provider module and factory.
- Dispatch and feature gating are wired.
- Service collectors are planned but not implemented yet.

## Configuration additions

- New provider config files:
  - `tenable-config.toml`
  - `okta-config.toml`
  - `jira-config.toml`
- Environment variable fallback support is available for each provider.

## Compatibility notes

- Existing AWS inventory and POA&M flows remain available.
- Legacy AWS profile and region selection continues to work.

## Pre-release validation focus

Before full release, validate:

- Provider-specific auth and config fallback behavior (Tenable, Okta, Jira)
- TUI provider-selection and provider-specific selection screens
- Output path correctness and evidence file integrity/signing verification
- Regression coverage for AWS collectors and inventory flow
