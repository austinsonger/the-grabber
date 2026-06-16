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

### 5) Output and execution behavior changes

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
