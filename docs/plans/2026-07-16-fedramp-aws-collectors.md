# FedRAMP AWS Collectors Implementation Plan (Plan 2)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add 10 new AWS evidence collectors, covering FedRAMP Moderate controls AC-02(02), CA-09b/c, CM-07(02)/(05), CP-09c, IA-05e, SC-07(07)/(12)/(18), SI-02b, SI-03c, SI-06d, SI-07b that grabber currently doesn't collect, plus one mapping refinement for existing collectors that already satisfy new controls.

**Architecture:** Each collector is one flat module under `src/providers/aws/`, follows the existing `CsvCollector` trait pattern (see `src/providers/aws/access_analyzer.rs` as a canonical minimal example), gets registered in `src/providers/aws/mod.rs` + `src/providers/aws/factory.rs`, and its `filename_prefix` gets a mapping entry in `assets/fedramp-map.json`.

**Tech Stack:** Rust · `aws-sdk-ec2`/`iam`/`ssm`/`s3`/`backup`/`guardduty`/`networkfirewall`/`inspector2` (all already in `Cargo.toml`) · `anyhow` · `async-trait` · `tokio`.

## Global Constraints

- Every commit authored `Austin Songer <asonger.pixel@gmail.com>`. No `Co-Authored-By` trailers.
- Work directly on `main` — no feature branches.
- No test writing. `cargo check` per task is the compilation bar. `cargo clippy -- -D warnings` may still fire on pre-existing repo debt (currently 39 errors on `main`); each task must not INCREASE that count.
- Every new collector file starts with `//!` module doc explaining its scope.
- Every new collector uses `anyhow::Result`, `anyhow::Context`, `.context("...")?` per project convention. Never `.unwrap()`/`.expect()` in collect paths.
- AWS SDK paginators MUST be used where available (`.into_paginator().items().send()` or a manual `next_token` loop matching the surrounding modules).
- Every collector's `filename_prefix` MUST already exist in `assets/fedramp-map.json` (Plan 1 seeded 52 P0 collector prefixes into that file). If a task's prefix isn't there, the task adds the entry.
- New collector CSVs automatically inherit the FedRAMP metadata columns + footer via Plan 1's infrastructure — no per-collector wiring needed.
- Registration order: `pub mod X;` in `mod.rs` (alphabetical), import in `factory.rs` (alphabetical inside the `use crate::providers::aws::{...}` block), `if has("X-key")` branch in `factory.rs::csv_collectors` (added near end, no strict ordering).
- Every task ends with `cargo check` clean, then a single commit.

---

## File Structure

**Create (one per new collector, 10 files):**
- `src/providers/aws/iam_credential_report.rs` — Task 1
- `src/providers/aws/transit_gateway_peering.rs` — Task 2
- `src/providers/aws/session_timeouts.rs` — Task 3
- `src/providers/aws/ssm_allowlist.rs` — Task 4
- `src/providers/aws/doc_repo_backup.rs` — Task 5
- `src/providers/aws/guardduty_runtime.rs` — Task 6
- `src/providers/aws/network_firewall_failclosed.rs` — Task 7
- `src/providers/aws/guardduty_malware_scans.rs` — Task 8
- `src/providers/aws/ssm_automation_runbooks.rs` — Task 9
- `src/providers/aws/ami_default_creds.rs` — Task 10

**Modify (all shared by every task):**
- `src/providers/aws/mod.rs` — add one `pub mod X;` line per task
- `src/providers/aws/factory.rs` — add one import line + one `if has(...)` branch per task
- `assets/fedramp-map.json` — Plan 1 seeded all 10 prefixes already; each task verifies presence and mapping correctness
- `evidence-list.md` — Task 12 adds EV125–EV134 rows
- `assets/fedramp-map.json` — Task 11 refines mappings for existing collectors

**Do not touch:**
- Anything in `src/providers/okta/`, `src/providers/jira/`, `src/providers/gcp/`, `src/providers/azure/`, `src/providers/tenable/`.
- `src/inventory_*` or `src/runner/*` — the metadata pipeline from Plan 1 automatically covers new collectors.

---

## Task 1: `IAM_Credential_Report_Expiration` collector

**Files:**
- Create: `src/providers/aws/iam_credential_report.rs`
- Modify: `src/providers/aws/mod.rs` (add `pub mod iam_credential_report;` alphabetically among the other `pub mod`s)
- Modify: `src/providers/aws/factory.rs` (add import + `has("iam-cred-report")` branch)

**Interfaces:**
- Consumes: `aws_sdk_iam::Client`.
- Produces: `pub struct IamCredentialReportCollector` implementing `CsvCollector` with `filename_prefix = "IAM_Credential_Report_Expiration"`.

- [ ] **Step 1: Create the collector file**

Write `src/providers/aws/iam_credential_report.rs`:

```rust
//! `iam:GenerateCredentialReport` + `iam:GetCredentialReport` — parses the
//! CSV credential report AWS produces per-account and surfaces per-user
//! password/access-key rotation and expiration data for FedRAMP AC-02(02).

use anyhow::{Context, Result};
use async_trait::async_trait;
use aws_sdk_iam::Client as IamClient;

use crate::evidence::CsvCollector;

pub struct IamCredentialReportCollector {
    client: IamClient,
}

impl IamCredentialReportCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self {
            client: IamClient::new(config),
        }
    }
}

#[async_trait]
impl CsvCollector for IamCredentialReportCollector {
    fn name(&self) -> &str {
        "IAM Credential Report — Password/Key Expiration"
    }
    fn filename_prefix(&self) -> &str {
        "IAM_Credential_Report_Expiration"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "User",
            "ARN",
            "User Creation Time",
            "Password Enabled",
            "Password Last Used",
            "Password Last Changed",
            "Password Next Rotation",
            "MFA Active",
            "Access Key 1 Active",
            "Access Key 1 Last Rotated",
            "Access Key 1 Last Used Date",
            "Access Key 2 Active",
            "Access Key 2 Last Rotated",
            "Access Key 2 Last Used Date",
            "Cert 1 Active",
            "Cert 1 Last Rotated",
            "Cert 2 Active",
            "Cert 2 Last Rotated",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        // Trigger generation; ignore "already in progress" states.
        let _ = self
            .client
            .generate_credential_report()
            .send()
            .await
            .context("iam:GenerateCredentialReport")?;

        // Poll until report is available (max ~20s).
        let mut rows_out: Vec<Vec<String>> = Vec::new();
        let mut body: Option<Vec<u8>> = None;
        for _ in 0..10 {
            match self.client.get_credential_report().send().await {
                Ok(r) => {
                    if let Some(b) = r.content() {
                        body = Some(b.as_ref().to_vec());
                        break;
                    }
                }
                Err(_) => {
                    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                }
            }
        }
        let bytes = body.context("iam:GetCredentialReport returned no content after retries")?;
        let text = String::from_utf8(bytes).context("credential report is not UTF-8")?;

        // The report is CSV; header row + one row per user.
        let mut rdr = csv::Reader::from_reader(text.as_bytes());
        let headers = rdr.headers().context("read credential report header")?.clone();
        let idx = |name: &str| headers.iter().position(|h| h == name);
        let cols: Vec<Option<usize>> = [
            "user",
            "arn",
            "user_creation_time",
            "password_enabled",
            "password_last_used",
            "password_last_changed",
            "password_next_rotation",
            "mfa_active",
            "access_key_1_active",
            "access_key_1_last_rotated",
            "access_key_1_last_used_date",
            "access_key_2_active",
            "access_key_2_last_rotated",
            "access_key_2_last_used_date",
            "cert_1_active",
            "cert_1_last_rotated",
            "cert_2_active",
            "cert_2_last_rotated",
        ]
        .iter()
        .map(|k| idx(k))
        .collect();

        for rec in rdr.records() {
            let rec = rec.context("read credential report row")?;
            let row: Vec<String> = cols
                .iter()
                .map(|opt| opt.and_then(|i| rec.get(i)).unwrap_or("").to_string())
                .collect();
            rows_out.push(row);
        }
        Ok(rows_out)
    }
}
```

- [ ] **Step 2: Register in `mod.rs`**

In `src/providers/aws/mod.rs`, add `pub mod iam_credential_report;` in alphabetical position (after `pub mod iam;` if present, or between `pub mod eks;` and the next entry — read the file first).

- [ ] **Step 3: Register in `factory.rs`**

In `src/providers/aws/factory.rs`:
1. Inside the `use crate::providers::aws::{...}` block, add `iam_credential_report::IamCredentialReportCollector,` alphabetically among the other `iam_*` imports.
2. Inside the `csv_collectors` function, add:
   ```rust
   if has("iam-cred-report") {
       v.push(Box::new(IamCredentialReportCollector::new(cfg)));
   }
   ```
   Place it next to the other `iam-*` branches.

- [ ] **Step 4: Verify mapping exists in `assets/fedramp-map.json`**

Run:
```bash
python3 -c "import json; d=json.load(open('/Users/austin-songer/code/grabber/assets/fedramp-map.json')); print(d['collectors'].get('IAM_Credential_Report_Expiration'))"
```
Expected: `{'req_ids': ['NIST-1048'], 'control_ids': ['AC-02(02)']}` (or similar). If empty or missing, add:
```bash
python3 -c "
import json
p='/Users/austin-songer/code/grabber/assets/fedramp-map.json'
d=json.load(open(p))
d['collectors']['IAM_Credential_Report_Expiration']={'req_ids':['NIST-1048'],'control_ids':['AC-02(02)']}
d['collectors']=dict(sorted(d['collectors'].items()))
open(p,'w').write(json.dumps(d,indent=2,ensure_ascii=False)+'\n')
"
```

- [ ] **Step 5: `cargo check`**

Run: `cargo check --manifest-path /Users/austin-songer/code/grabber/Cargo.toml`
Expected: clean.

- [ ] **Step 6: Commit**

```bash
cd /Users/austin-songer/code/grabber
git add src/providers/aws/iam_credential_report.rs src/providers/aws/mod.rs src/providers/aws/factory.rs assets/fedramp-map.json
git -c user.name="Austin Songer" -c user.email="asonger.pixel@gmail.com" commit -m "feat(aws): add IAM credential-report expiration collector (AC-02(02))"
```

---

## Task 2: `TransitGateway_VPCPeering_Config` collector

**Files:**
- Create: `src/providers/aws/transit_gateway_peering.rs`
- Modify: `src/providers/aws/mod.rs`, `src/providers/aws/factory.rs`

**Interfaces:**
- Consumes: `aws_sdk_ec2::Client`.
- Produces: `pub struct TransitGatewayPeeringCollector` implementing `CsvCollector` with `filename_prefix = "TransitGateway_VPCPeering_Config"`.

- [ ] **Step 1: Create the collector file**

```rust
//! Enumerates every AWS internal network interconnection so auditors can see
//! all TGWs, TGW attachments, and VPC peering connections with peer accounts,
//! states, and route-table associations. Satisfies FedRAMP CA-09b.

use anyhow::{Context, Result};
use async_trait::async_trait;
use aws_sdk_ec2::Client as Ec2Client;

use crate::evidence::CsvCollector;

pub struct TransitGatewayPeeringCollector {
    client: Ec2Client,
}

impl TransitGatewayPeeringCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self {
            client: Ec2Client::new(config),
        }
    }
}

#[async_trait]
impl CsvCollector for TransitGatewayPeeringCollector {
    fn name(&self) -> &str {
        "Transit Gateways & VPC Peering"
    }
    fn filename_prefix(&self) -> &str {
        "TransitGateway_VPCPeering_Config"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Kind",
            "ID",
            "Name",
            "State",
            "Owner Account",
            "Peer Account",
            "Peer VPC",
            "Peer Region",
            "Local VPC / Subnets",
            "Association",
            "Default Route Table",
            "Notes",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let mut rows: Vec<Vec<String>> = Vec::new();

        // Transit gateways
        let mut tgw_next: Option<String> = None;
        loop {
            let mut req = self.client.describe_transit_gateways();
            if let Some(t) = tgw_next.as_ref() {
                req = req.next_token(t);
            }
            let resp = req.send().await.context("ec2:DescribeTransitGateways")?;
            for tgw in resp.transit_gateways() {
                let name = tgw
                    .tags()
                    .iter()
                    .find(|t| t.key() == Some("Name"))
                    .and_then(|t| t.value())
                    .unwrap_or("")
                    .to_string();
                rows.push(vec![
                    "TransitGateway".into(),
                    tgw.transit_gateway_id().unwrap_or("").into(),
                    name,
                    tgw.state().map(|s| s.as_str().to_string()).unwrap_or_default(),
                    tgw.owner_id().unwrap_or("").into(),
                    String::new(),
                    String::new(),
                    region.into(),
                    String::new(),
                    String::new(),
                    tgw.options()
                        .and_then(|o| o.default_route_table_association())
                        .map(|s| s.as_str().to_string())
                        .unwrap_or_default(),
                    String::new(),
                ]);
            }
            tgw_next = resp.next_token().map(|s| s.to_string());
            if tgw_next.is_none() {
                break;
            }
        }

        // TGW attachments
        let mut att_next: Option<String> = None;
        loop {
            let mut req = self.client.describe_transit_gateway_attachments();
            if let Some(t) = att_next.as_ref() {
                req = req.next_token(t);
            }
            let resp = req
                .send()
                .await
                .context("ec2:DescribeTransitGatewayAttachments")?;
            for att in resp.transit_gateway_attachments() {
                rows.push(vec![
                    "TGWAttachment".into(),
                    att.transit_gateway_attachment_id().unwrap_or("").into(),
                    String::new(),
                    att.state().map(|s| s.as_str().to_string()).unwrap_or_default(),
                    att.resource_owner_id().unwrap_or("").into(),
                    String::new(),
                    att.resource_id().unwrap_or("").into(),
                    region.into(),
                    att.transit_gateway_id().unwrap_or("").into(),
                    att.association()
                        .and_then(|a| a.state())
                        .map(|s| s.as_str().to_string())
                        .unwrap_or_default(),
                    String::new(),
                    att.resource_type()
                        .map(|s| s.as_str().to_string())
                        .unwrap_or_default(),
                ]);
            }
            att_next = resp.next_token().map(|s| s.to_string());
            if att_next.is_none() {
                break;
            }
        }

        // VPC peerings
        let mut pcx_next: Option<String> = None;
        loop {
            let mut req = self.client.describe_vpc_peering_connections();
            if let Some(t) = pcx_next.as_ref() {
                req = req.next_token(t);
            }
            let resp = req
                .send()
                .await
                .context("ec2:DescribeVpcPeeringConnections")?;
            for pcx in resp.vpc_peering_connections() {
                let acc = pcx.accepter_vpc_info();
                let req = pcx.requester_vpc_info();
                rows.push(vec![
                    "VpcPeering".into(),
                    pcx.vpc_peering_connection_id().unwrap_or("").into(),
                    String::new(),
                    pcx.status()
                        .and_then(|s| s.code())
                        .map(|s| s.as_str().to_string())
                        .unwrap_or_default(),
                    req.and_then(|v| v.owner_id()).unwrap_or("").into(),
                    acc.and_then(|v| v.owner_id()).unwrap_or("").into(),
                    acc.and_then(|v| v.vpc_id()).unwrap_or("").into(),
                    acc.and_then(|v| v.region()).unwrap_or(region).into(),
                    req.and_then(|v| v.vpc_id()).unwrap_or("").into(),
                    String::new(),
                    String::new(),
                    String::new(),
                ]);
            }
            pcx_next = resp.next_token().map(|s| s.to_string());
            if pcx_next.is_none() {
                break;
            }
        }
        Ok(rows)
    }
}
```

- [ ] **Step 2: Register in `mod.rs`**

Add `pub mod transit_gateway_peering;` alphabetically.

- [ ] **Step 3: Register in `factory.rs`**

Add import `transit_gateway_peering::TransitGatewayPeeringCollector,` and:
```rust
if has("tgw-peering") {
    v.push(Box::new(TransitGatewayPeeringCollector::new(cfg)));
}
```

- [ ] **Step 4: Verify mapping in `assets/fedramp-map.json`**

Expected: `TransitGateway_VPCPeering_Config` → `req_ids: ['NIST-1203']`, `control_ids: ['CA-09b']`. If missing, follow the same one-liner pattern from Task 1 Step 4 to add.

- [ ] **Step 5: `cargo check`** — clean.

- [ ] **Step 6: Commit**

```bash
cd /Users/austin-songer/code/grabber
git add src/providers/aws/transit_gateway_peering.rs src/providers/aws/mod.rs src/providers/aws/factory.rs assets/fedramp-map.json
git -c user.name="Austin Songer" -c user.email="asonger.pixel@gmail.com" commit -m "feat(aws): add TransitGateway + VPC peering config collector (CA-09b)"
```

---

## Task 3: `Session_Timeout_Config` collector

**Files:**
- Create: `src/providers/aws/session_timeouts.rs`
- Modify: `src/providers/aws/mod.rs`, `src/providers/aws/factory.rs`

**Interfaces:**
- Consumes: `aws_sdk_elasticloadbalancingv2::Client`, `aws_sdk_ec2::Client` (Client VPN), `aws_sdk_ssm::Client` (Session Manager preferences).
- Produces: `pub struct SessionTimeoutConfigCollector` implementing `CsvCollector` with `filename_prefix = "Session_Timeout_Config"`.

- [ ] **Step 1: Create the collector file**

```rust
//! Consolidates session-timeout settings across load balancers, Client VPN
//! endpoints, and SSM Session Manager for FedRAMP CA-09c evidence of
//! internal-connection auto-termination.

use anyhow::{Context, Result};
use async_trait::async_trait;
use aws_sdk_ec2::Client as Ec2Client;
use aws_sdk_elasticloadbalancingv2::Client as ElbClient;
use aws_sdk_ssm::Client as SsmClient;

use crate::evidence::CsvCollector;

pub struct SessionTimeoutConfigCollector {
    elb: ElbClient,
    ec2: Ec2Client,
    ssm: SsmClient,
}

impl SessionTimeoutConfigCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self {
            elb: ElbClient::new(config),
            ec2: Ec2Client::new(config),
            ssm: SsmClient::new(config),
        }
    }
}

#[async_trait]
impl CsvCollector for SessionTimeoutConfigCollector {
    fn name(&self) -> &str {
        "Session Timeouts (ELB / Client VPN / SSM)"
    }
    fn filename_prefix(&self) -> &str {
        "Session_Timeout_Config"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Source",
            "Resource ID",
            "Resource Name",
            "Setting",
            "Value",
            "Region",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let mut rows: Vec<Vec<String>> = Vec::new();

        // ELB idle timeout
        let mut marker: Option<String> = None;
        loop {
            let mut req = self.elb.describe_load_balancers();
            if let Some(m) = marker.as_ref() {
                req = req.marker(m);
            }
            let resp = req.send().await.context("elbv2:DescribeLoadBalancers")?;
            for lb in resp.load_balancers() {
                if let Some(arn) = lb.load_balancer_arn() {
                    let attrs = self
                        .elb
                        .describe_load_balancer_attributes()
                        .load_balancer_arn(arn)
                        .send()
                        .await
                        .with_context(|| format!("elbv2:DescribeLoadBalancerAttributes {arn}"))?;
                    for a in attrs.attributes() {
                        if a.key() == Some("idle_timeout.timeout_seconds") {
                            rows.push(vec![
                                "ELB".into(),
                                arn.into(),
                                lb.load_balancer_name().unwrap_or("").into(),
                                "idle_timeout.timeout_seconds".into(),
                                a.value().unwrap_or("").into(),
                                region.into(),
                            ]);
                        }
                    }
                }
            }
            marker = resp.next_marker().map(|s| s.to_string());
            if marker.is_none() {
                break;
            }
        }

        // Client VPN session timeout
        let mut cvpn_next: Option<String> = None;
        loop {
            let mut req = self.ec2.describe_client_vpn_endpoints();
            if let Some(t) = cvpn_next.as_ref() {
                req = req.next_token(t);
            }
            let resp = req.send().await.context("ec2:DescribeClientVpnEndpoints")?;
            for ep in resp.client_vpn_endpoints() {
                rows.push(vec![
                    "ClientVPN".into(),
                    ep.client_vpn_endpoint_id().unwrap_or("").into(),
                    ep.description().unwrap_or("").into(),
                    "session_timeout_hours".into(),
                    ep.session_timeout_hours()
                        .map(|h| h.to_string())
                        .unwrap_or_default(),
                    region.into(),
                ]);
            }
            cvpn_next = resp.next_token().map(|s| s.to_string());
            if cvpn_next.is_none() {
                break;
            }
        }

        // SSM Session Manager preferences (single doc "SSM-SessionManagerRunShell")
        if let Ok(pref) = self
            .ssm
            .get_document()
            .name("SSM-SessionManagerRunShell")
            .send()
            .await
        {
            let content = pref.content().unwrap_or("");
            rows.push(vec![
                "SSM Session Manager".into(),
                "SSM-SessionManagerRunShell".into(),
                "Session Manager Preferences".into(),
                "document_content_length".into(),
                content.len().to_string(),
                region.into(),
            ]);
        }

        Ok(rows)
    }
}
```

- [ ] **Step 2:** Register `pub mod session_timeouts;` in `mod.rs`.
- [ ] **Step 3:** Add `session_timeouts::SessionTimeoutConfigCollector,` import in `factory.rs`, and:
  ```rust
  if has("session-timeouts") {
      v.push(Box::new(SessionTimeoutConfigCollector::new(cfg)));
  }
  ```
- [ ] **Step 4:** Verify mapping in `assets/fedramp-map.json`: `Session_Timeout_Config` → `NIST-1204` / `CA-09c`. Add if missing (same one-liner pattern as Task 1 Step 4).
- [ ] **Step 5:** `cargo check` clean.
- [ ] **Step 6:** Commit:

```bash
git add src/providers/aws/session_timeouts.rs src/providers/aws/mod.rs src/providers/aws/factory.rs assets/fedramp-map.json
git -c user.name="Austin Songer" -c user.email="asonger.pixel@gmail.com" commit -m "feat(aws): add session-timeout collector across ELB/ClientVPN/SSM (CA-09c)"
```

---

## Task 4: `SSM_Application_Allowlist` collector

**Files:**
- Create: `src/providers/aws/ssm_allowlist.rs`
- Modify: `src/providers/aws/mod.rs`, `src/providers/aws/factory.rs`

**Interfaces:**
- Consumes: `aws_sdk_ssm::Client`.
- Produces: `pub struct SsmApplicationAllowlistCollector`, `filename_prefix = "SSM_Application_Allowlist"`.

- [ ] **Step 1:** Write `src/providers/aws/ssm_allowlist.rs`:

```rust
//! Lists SSM State Manager associations and Distributor packages that
//! implement application allow-listing; each association becomes one row so
//! auditors can see the deny-by-default posture for FedRAMP CM-07(02)/(05).

use anyhow::{Context, Result};
use async_trait::async_trait;
use aws_sdk_ssm::Client as SsmClient;

use crate::evidence::CsvCollector;

pub struct SsmApplicationAllowlistCollector {
    client: SsmClient,
}

impl SsmApplicationAllowlistCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self {
            client: SsmClient::new(config),
        }
    }
}

#[async_trait]
impl CsvCollector for SsmApplicationAllowlistCollector {
    fn name(&self) -> &str {
        "SSM Application Allowlist (State Manager + Distributor)"
    }
    fn filename_prefix(&self) -> &str {
        "SSM_Application_Allowlist"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Association ID",
            "Association Name",
            "Document Name",
            "Targets",
            "Schedule",
            "Compliance Severity",
            "Last Execution Status",
            "Compliance Type",
            "Region",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let mut rows: Vec<Vec<String>> = Vec::new();
        let mut next: Option<String> = None;
        loop {
            let mut req = self.client.list_associations();
            if let Some(t) = next.as_ref() {
                req = req.next_token(t);
            }
            let resp = req.send().await.context("ssm:ListAssociations")?;
            for a in resp.associations() {
                let doc = a.name().unwrap_or("");
                // Filter to associations that plausibly represent allow-listing:
                // Distributor packages typically have doc names starting with
                // "AWS-ConfigureAWSPackage" or contain "Allowlist"/"Applock" tokens.
                let is_allowlist = doc.contains("Distributor")
                    || doc.contains("ConfigureAWSPackage")
                    || doc.to_lowercase().contains("allowlist")
                    || doc.to_lowercase().contains("applock");
                if !is_allowlist {
                    continue;
                }
                let targets = a
                    .targets()
                    .iter()
                    .map(|t| {
                        format!(
                            "{}={}",
                            t.key().unwrap_or(""),
                            t.values().join("|")
                        )
                    })
                    .collect::<Vec<_>>()
                    .join(";");
                rows.push(vec![
                    a.association_id().unwrap_or("").into(),
                    a.association_name().unwrap_or("").into(),
                    doc.into(),
                    targets,
                    a.schedule_expression().unwrap_or("").into(),
                    a.compliance_severity()
                        .map(|s| s.as_str().to_string())
                        .unwrap_or_default(),
                    a.overview()
                        .and_then(|o| o.status())
                        .unwrap_or("")
                        .to_string(),
                    a.overview()
                        .and_then(|o| o.detailed_status())
                        .unwrap_or("")
                        .to_string(),
                    region.into(),
                ]);
            }
            next = resp.next_token().map(|s| s.to_string());
            if next.is_none() {
                break;
            }
        }
        Ok(rows)
    }
}
```

- [ ] **Step 2:** `pub mod ssm_allowlist;` in `mod.rs`.
- [ ] **Step 3:** `ssm_allowlist::SsmApplicationAllowlistCollector,` in factory.rs; `if has("ssm-allowlist")` branch.
- [ ] **Step 4:** Verify mapping: `SSM_Application_Allowlist` → `NIST-1243|NIST-1246` / `CM-07(02)|CM-07(05)(b)`. Add if missing.
- [ ] **Step 5:** `cargo check` clean.
- [ ] **Step 6:** Commit:

```bash
git add src/providers/aws/ssm_allowlist.rs src/providers/aws/mod.rs src/providers/aws/factory.rs assets/fedramp-map.json
git -c user.name="Austin Songer" -c user.email="asonger.pixel@gmail.com" commit -m "feat(aws): add SSM application-allowlist collector (CM-07(02)/(05))"
```

---

## Task 5: `Doc_Repo_Backup_Config` collector

**Files:**
- Create: `src/providers/aws/doc_repo_backup.rs`
- Modify: `src/providers/aws/mod.rs`, `src/providers/aws/factory.rs`

**Interfaces:**
- Consumes: `aws_sdk_s3::Client`, `aws_sdk_backup::Client`.
- Produces: `pub struct DocRepoBackupConfigCollector`, `filename_prefix = "Doc_Repo_Backup_Config"`.

- [ ] **Step 1:** Write `src/providers/aws/doc_repo_backup.rs`:

```rust
//! For every S3 bucket, emits its versioning + replication status and any
//! AWS Backup vault that targets buckets. Auditors use this to prove the
//! 3-copy backup posture on documentation stores for FedRAMP CP-09c.

use anyhow::{Context, Result};
use async_trait::async_trait;
use aws_sdk_backup::Client as BackupClient;
use aws_sdk_s3::Client as S3Client;

use crate::evidence::CsvCollector;

pub struct DocRepoBackupConfigCollector {
    s3: S3Client,
    backup: BackupClient,
}

impl DocRepoBackupConfigCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self {
            s3: S3Client::new(config),
            backup: BackupClient::new(config),
        }
    }
}

#[async_trait]
impl CsvCollector for DocRepoBackupConfigCollector {
    fn name(&self) -> &str {
        "Documentation Repository Backup Config (S3 + Backup vaults)"
    }
    fn filename_prefix(&self) -> &str {
        "Doc_Repo_Backup_Config"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Kind",
            "Name / ARN",
            "Region",
            "Versioning",
            "Replication",
            "Vault Recovery Points",
            "Notes",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let mut rows: Vec<Vec<String>> = Vec::new();

        // S3 buckets — versioning + replication
        let buckets = self.s3.list_buckets().send().await.context("s3:ListBuckets")?;
        for b in buckets.buckets() {
            let name = match b.name() {
                Some(n) => n.to_string(),
                None => continue,
            };
            let ver = self
                .s3
                .get_bucket_versioning()
                .bucket(&name)
                .send()
                .await
                .map(|r| {
                    r.status()
                        .map(|s| s.as_str().to_string())
                        .unwrap_or_else(|| "Disabled".into())
                })
                .unwrap_or_else(|_| "Unknown".into());
            let repl = self
                .s3
                .get_bucket_replication()
                .bucket(&name)
                .send()
                .await
                .map(|r| {
                    r.replication_configuration()
                        .map(|c| {
                            c.rules()
                                .iter()
                                .map(|r| {
                                    format!(
                                        "{}→{}",
                                        r.id().unwrap_or(""),
                                        r.destination()
                                            .and_then(|d| d.bucket())
                                            .unwrap_or("?"),
                                    )
                                })
                                .collect::<Vec<_>>()
                                .join(";")
                        })
                        .unwrap_or_default()
                })
                .unwrap_or_default();
            rows.push(vec![
                "S3Bucket".into(),
                name,
                region.into(),
                ver,
                repl,
                String::new(),
                String::new(),
            ]);
        }

        // Backup vaults
        let mut next: Option<String> = None;
        loop {
            let mut req = self.backup.list_backup_vaults();
            if let Some(t) = next.as_ref() {
                req = req.next_token(t);
            }
            let resp = req.send().await.context("backup:ListBackupVaults")?;
            for v in resp.backup_vault_list() {
                rows.push(vec![
                    "BackupVault".into(),
                    v.backup_vault_arn().unwrap_or("").into(),
                    region.into(),
                    String::new(),
                    String::new(),
                    v.number_of_recovery_points().to_string(),
                    v.encryption_key_arn().unwrap_or("").into(),
                ]);
            }
            next = resp.next_token().map(|s| s.to_string());
            if next.is_none() {
                break;
            }
        }
        Ok(rows)
    }
}
```

- [ ] **Step 2:** `pub mod doc_repo_backup;` in `mod.rs`.
- [ ] **Step 3:** `doc_repo_backup::DocRepoBackupConfigCollector,` in factory; `if has("doc-repo-backup")` branch.
- [ ] **Step 4:** Verify mapping: `Doc_Repo_Backup_Config` → `NIST-1295` / `CP-09c`. Add if missing.
- [ ] **Step 5:** `cargo check` clean.
- [ ] **Step 6:** Commit:

```bash
git add src/providers/aws/doc_repo_backup.rs src/providers/aws/mod.rs src/providers/aws/factory.rs assets/fedramp-map.json
git -c user.name="Austin Songer" -c user.email="asonger.pixel@gmail.com" commit -m "feat(aws): add documentation-repo backup config collector (CP-09c)"
```

---

## Task 6: `GuardDuty_Runtime_Coverage` collector

**Files:**
- Create: `src/providers/aws/guardduty_runtime.rs`
- Modify: `src/providers/aws/mod.rs`, `src/providers/aws/factory.rs`

**Interfaces:**
- Consumes: `aws_sdk_guardduty::Client`.
- Produces: `pub struct GuardDutyRuntimeCoverageCollector`, `filename_prefix = "GuardDuty_Runtime_Coverage"`.

- [ ] **Step 1:** Write the file:

```rust
//! `guardduty:GetCoverageStatistics` + `ListCoverage` — emits per-resource
//! runtime-monitoring coverage for EKS, ECS, and EC2 so auditors can prove
//! HIPS/HIDS deployment percentage per FedRAMP SC-07(12).

use anyhow::{Context, Result};
use async_trait::async_trait;
use aws_sdk_guardduty::Client as GdClient;

use crate::evidence::CsvCollector;

pub struct GuardDutyRuntimeCoverageCollector {
    client: GdClient,
}

impl GuardDutyRuntimeCoverageCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self {
            client: GdClient::new(config),
        }
    }
}

#[async_trait]
impl CsvCollector for GuardDutyRuntimeCoverageCollector {
    fn name(&self) -> &str {
        "GuardDuty Runtime Coverage"
    }
    fn filename_prefix(&self) -> &str {
        "GuardDuty_Runtime_Coverage"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Detector ID",
            "Resource Type",
            "Resource ID",
            "Coverage Status",
            "Issue",
            "Updated At",
            "Region",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let mut rows: Vec<Vec<String>> = Vec::new();

        let mut det_next: Option<String> = None;
        let mut detectors: Vec<String> = Vec::new();
        loop {
            let mut req = self.client.list_detectors();
            if let Some(t) = det_next.as_ref() {
                req = req.next_token(t);
            }
            let resp = req.send().await.context("guardduty:ListDetectors")?;
            detectors.extend(resp.detector_ids().iter().cloned());
            det_next = resp.next_token().map(|s| s.to_string());
            if det_next.is_none() {
                break;
            }
        }

        for det in &detectors {
            let mut cov_next: Option<String> = None;
            loop {
                let mut req = self.client.list_coverage().detector_id(det);
                if let Some(t) = cov_next.as_ref() {
                    req = req.next_token(t);
                }
                let resp = req
                    .send()
                    .await
                    .with_context(|| format!("guardduty:ListCoverage {det}"))?;
                for r in resp.resources() {
                    rows.push(vec![
                        det.clone(),
                        r.resource_details()
                            .and_then(|d| d.resource_type())
                            .map(|s| s.as_str().to_string())
                            .unwrap_or_default(),
                        r.resource_id().unwrap_or("").into(),
                        r.coverage_status()
                            .map(|s| s.as_str().to_string())
                            .unwrap_or_default(),
                        r.issue().unwrap_or("").into(),
                        r.updated_at()
                            .map(|t| t.to_string())
                            .unwrap_or_default(),
                        region.into(),
                    ]);
                }
                cov_next = resp.next_token().map(|s| s.to_string());
                if cov_next.is_none() {
                    break;
                }
            }
        }
        Ok(rows)
    }
}
```

- [ ] **Step 2:** `pub mod guardduty_runtime;` in `mod.rs`.
- [ ] **Step 3:** `guardduty_runtime::GuardDutyRuntimeCoverageCollector,` import; `if has("guardduty-runtime")` branch.
- [ ] **Step 4:** Verify mapping: `GuardDuty_Runtime_Coverage` → `NIST-1643` / `SC-07(12)`. Add if missing.
- [ ] **Step 5:** `cargo check`.
- [ ] **Step 6:** Commit:

```bash
git add src/providers/aws/guardduty_runtime.rs src/providers/aws/mod.rs src/providers/aws/factory.rs assets/fedramp-map.json
git -c user.name="Austin Songer" -c user.email="asonger.pixel@gmail.com" commit -m "feat(aws): add GuardDuty runtime coverage collector (SC-07(12))"
```

---

## Task 7: `NetworkFirewall_FailClosed_Config` collector

**Files:**
- Create: `src/providers/aws/network_firewall_failclosed.rs`
- Modify: `src/providers/aws/mod.rs`, `src/providers/aws/factory.rs`

**Interfaces:**
- Consumes: `aws_sdk_networkfirewall::Client`.
- Produces: `pub struct NetworkFirewallFailClosedCollector`, `filename_prefix = "NetworkFirewall_FailClosed_Config"`.

- [ ] **Step 1:** Write the file:

```rust
//! For every AWS Network Firewall, emits the stream-exception-policy and
//! stateful-default-actions to prove the boundary device fails secure per
//! FedRAMP SC-07(18).

use anyhow::{Context, Result};
use async_trait::async_trait;
use aws_sdk_networkfirewall::Client as NfwClient;

use crate::evidence::CsvCollector;

pub struct NetworkFirewallFailClosedCollector {
    client: NfwClient,
}

impl NetworkFirewallFailClosedCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self {
            client: NfwClient::new(config),
        }
    }
}

#[async_trait]
impl CsvCollector for NetworkFirewallFailClosedCollector {
    fn name(&self) -> &str {
        "Network Firewall Fail-Closed Config"
    }
    fn filename_prefix(&self) -> &str {
        "NetworkFirewall_FailClosed_Config"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Firewall Name",
            "Firewall ARN",
            "Policy ARN",
            "Stream Exception Policy",
            "Stateful Default Actions",
            "Region",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let mut rows: Vec<Vec<String>> = Vec::new();
        let mut next: Option<String> = None;
        loop {
            let mut req = self.client.list_firewalls();
            if let Some(t) = next.as_ref() {
                req = req.next_token(t);
            }
            let resp = req.send().await.context("network-firewall:ListFirewalls")?;
            for f in resp.firewalls() {
                let name = f.firewall_name().unwrap_or("");
                let arn = f.firewall_arn().unwrap_or("");
                let fw = self
                    .client
                    .describe_firewall()
                    .firewall_name(name)
                    .send()
                    .await
                    .with_context(|| format!("network-firewall:DescribeFirewall {name}"))?;
                let policy_arn = fw
                    .firewall()
                    .and_then(|f| f.firewall_policy_arn())
                    .unwrap_or("")
                    .to_string();
                let pol = self
                    .client
                    .describe_firewall_policy()
                    .firewall_policy_arn(&policy_arn)
                    .send()
                    .await
                    .with_context(|| format!("network-firewall:DescribeFirewallPolicy {policy_arn}"))?;
                let (stream_pol, stateful_defaults) = pol
                    .firewall_policy()
                    .map(|p| {
                        (
                            p.stateful_engine_options()
                                .and_then(|o| o.stream_exception_policy())
                                .map(|s| s.as_str().to_string())
                                .unwrap_or_default(),
                            p.stateful_default_actions().join("|"),
                        )
                    })
                    .unwrap_or_default();
                rows.push(vec![
                    name.into(),
                    arn.into(),
                    policy_arn,
                    stream_pol,
                    stateful_defaults,
                    region.into(),
                ]);
            }
            next = resp.next_token().map(|s| s.to_string());
            if next.is_none() {
                break;
            }
        }
        Ok(rows)
    }
}
```

- [ ] **Step 2:** `pub mod network_firewall_failclosed;` in `mod.rs`.
- [ ] **Step 3:** `network_firewall_failclosed::NetworkFirewallFailClosedCollector,` import; `if has("nfw-failclosed")` branch.
- [ ] **Step 4:** Verify mapping: `NetworkFirewall_FailClosed_Config` → `NIST-1647` / `SC-07(18)`. Add if missing.
- [ ] **Step 5:** `cargo check`.
- [ ] **Step 6:** Commit:

```bash
git add src/providers/aws/network_firewall_failclosed.rs src/providers/aws/mod.rs src/providers/aws/factory.rs assets/fedramp-map.json
git -c user.name="Austin Songer" -c user.email="asonger.pixel@gmail.com" commit -m "feat(aws): add NetworkFirewall fail-closed config collector (SC-07(18))"
```

---

## Task 8: `GuardDuty_Malware_Scan_History` collector

**Files:**
- Create: `src/providers/aws/guardduty_malware_scans.rs`
- Modify: `src/providers/aws/mod.rs`, `src/providers/aws/factory.rs`

**Interfaces:**
- Consumes: `aws_sdk_guardduty::Client`.
- Produces: `pub struct GuardDutyMalwareScanHistoryCollector`, `filename_prefix = "GuardDuty_Malware_Scan_History"`.

- [ ] **Step 1:** Write the file:

```rust
//! `guardduty:DescribeMalwareScans` — one row per completed malware scan
//! with real timestamps so weekly-scan cadence can be proven for
//! FedRAMP SI-03c.

use anyhow::{Context, Result};
use async_trait::async_trait;
use aws_sdk_guardduty::Client as GdClient;

use crate::evidence::CsvCollector;

pub struct GuardDutyMalwareScanHistoryCollector {
    client: GdClient,
}

impl GuardDutyMalwareScanHistoryCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self {
            client: GdClient::new(config),
        }
    }
}

#[async_trait]
impl CsvCollector for GuardDutyMalwareScanHistoryCollector {
    fn name(&self) -> &str {
        "GuardDuty Malware Scan History"
    }
    fn filename_prefix(&self) -> &str {
        "GuardDuty_Malware_Scan_History"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Detector ID",
            "Scan ID",
            "Scan Type",
            "Scan Status",
            "Scan Start",
            "Scan End",
            "Total GB Scanned",
            "Threats Found",
            "Region",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let mut rows: Vec<Vec<String>> = Vec::new();

        // Detectors
        let mut det_next: Option<String> = None;
        let mut detectors: Vec<String> = Vec::new();
        loop {
            let mut req = self.client.list_detectors();
            if let Some(t) = det_next.as_ref() {
                req = req.next_token(t);
            }
            let resp = req.send().await.context("guardduty:ListDetectors")?;
            detectors.extend(resp.detector_ids().iter().cloned());
            det_next = resp.next_token().map(|s| s.to_string());
            if det_next.is_none() {
                break;
            }
        }

        for det in &detectors {
            let mut scan_next: Option<String> = None;
            loop {
                let mut req = self.client.describe_malware_scans().detector_id(det);
                if let Some(t) = scan_next.as_ref() {
                    req = req.next_token(t);
                }
                let resp = req
                    .send()
                    .await
                    .with_context(|| format!("guardduty:DescribeMalwareScans {det}"))?;
                for s in resp.scans() {
                    let threats = s.total_bytes().to_string();
                    rows.push(vec![
                        det.clone(),
                        s.scan_id().unwrap_or("").into(),
                        s.scan_type()
                            .map(|t| t.as_str().to_string())
                            .unwrap_or_default(),
                        s.scan_status()
                            .map(|s| s.as_str().to_string())
                            .unwrap_or_default(),
                        s.scan_start_time()
                            .map(|t| t.to_string())
                            .unwrap_or_default(),
                        s.scan_end_time()
                            .map(|t| t.to_string())
                            .unwrap_or_default(),
                        format!("{:.2}", s.total_bytes() as f64 / (1024.0 * 1024.0 * 1024.0)),
                        threats,
                        region.into(),
                    ]);
                }
                scan_next = resp.next_token().map(|s| s.to_string());
                if scan_next.is_none() {
                    break;
                }
            }
        }
        Ok(rows)
    }
}
```

- [ ] **Step 2:** `pub mod guardduty_malware_scans;` in `mod.rs`.
- [ ] **Step 3:** `guardduty_malware_scans::GuardDutyMalwareScanHistoryCollector,` import; `if has("guardduty-malware")` branch.
- [ ] **Step 4:** Verify mapping: `GuardDuty_Malware_Scan_History` → `NIST-1698` / `SI-03c.01[01]`. Add if missing.
- [ ] **Step 5:** `cargo check`. If the SDK field name for `total_bytes` differs in the vendored version, replace with whatever `s.` method returns bytes/GB — implementer inspects `aws_sdk_guardduty::types::Scan` docs and adjusts.
- [ ] **Step 6:** Commit:

```bash
git add src/providers/aws/guardduty_malware_scans.rs src/providers/aws/mod.rs src/providers/aws/factory.rs assets/fedramp-map.json
git -c user.name="Austin Songer" -c user.email="asonger.pixel@gmail.com" commit -m "feat(aws): add GuardDuty malware-scan history collector (SI-03c)"
```

---

## Task 9: `SSM_Automation_Response_Runbooks` collector

**Files:**
- Create: `src/providers/aws/ssm_automation_runbooks.rs`
- Modify: `src/providers/aws/mod.rs`, `src/providers/aws/factory.rs`

**Interfaces:**
- Consumes: `aws_sdk_ssm::Client`.
- Produces: `pub struct SsmAutomationRunbooksCollector`, `filename_prefix = "SSM_Automation_Response_Runbooks"`.

- [ ] **Step 1:** Write the file:

```rust
//! Lists SSM Automation documents (customer-owned) so auditors can see
//! automated remediation runbooks tied to security anomalies for
//! FedRAMP SI-06d.

use anyhow::{Context, Result};
use async_trait::async_trait;
use aws_sdk_ssm::{types::DocumentFilter, Client as SsmClient};

use crate::evidence::CsvCollector;

pub struct SsmAutomationRunbooksCollector {
    client: SsmClient,
}

impl SsmAutomationRunbooksCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self {
            client: SsmClient::new(config),
        }
    }
}

#[async_trait]
impl CsvCollector for SsmAutomationRunbooksCollector {
    fn name(&self) -> &str {
        "SSM Automation Response Runbooks"
    }
    fn filename_prefix(&self) -> &str {
        "SSM_Automation_Response_Runbooks"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Document Name",
            "Owner",
            "Document Type",
            "Document Format",
            "Schema Version",
            "Target Type",
            "Tags",
            "Created Date",
            "Region",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let mut rows: Vec<Vec<String>> = Vec::new();
        let mut next: Option<String> = None;
        loop {
            let filter = DocumentFilter::builder()
                .key("DocumentType")
                .value("Automation")
                .build()
                .context("build DocumentFilter")?;
            let mut req = self.client.list_documents().document_filter_list(filter);
            if let Some(t) = next.as_ref() {
                req = req.next_token(t);
            }
            let resp = req.send().await.context("ssm:ListDocuments Automation")?;
            for d in resp.document_identifiers() {
                let tags = d
                    .tags()
                    .iter()
                    .map(|t| format!("{}={}", t.key().unwrap_or(""), t.value().unwrap_or("")))
                    .collect::<Vec<_>>()
                    .join(";");
                rows.push(vec![
                    d.name().unwrap_or("").into(),
                    d.owner().unwrap_or("").into(),
                    d.document_type()
                        .map(|t| t.as_str().to_string())
                        .unwrap_or_default(),
                    d.document_format()
                        .map(|t| t.as_str().to_string())
                        .unwrap_or_default(),
                    d.schema_version().unwrap_or("").into(),
                    d.target_type().unwrap_or("").into(),
                    tags,
                    d.created_date()
                        .map(|t| t.to_string())
                        .unwrap_or_default(),
                    region.into(),
                ]);
            }
            next = resp.next_token().map(|s| s.to_string());
            if next.is_none() {
                break;
            }
        }
        Ok(rows)
    }
}
```

- [ ] **Step 2:** `pub mod ssm_automation_runbooks;` in `mod.rs`.
- [ ] **Step 3:** `ssm_automation_runbooks::SsmAutomationRunbooksCollector,` import; `if has("ssm-automation")` branch.
- [ ] **Step 4:** Verify mapping: `SSM_Automation_Response_Runbooks` → `NIST-1739` / `SI-06d`. Add if missing.
- [ ] **Step 5:** `cargo check`.
- [ ] **Step 6:** Commit:

```bash
git add src/providers/aws/ssm_automation_runbooks.rs src/providers/aws/mod.rs src/providers/aws/factory.rs assets/fedramp-map.json
git -c user.name="Austin Songer" -c user.email="asonger.pixel@gmail.com" commit -m "feat(aws): add SSM automation-runbook collector (SI-06d)"
```

---

## Task 10: `AMI_Default_Credential_Scan` collector

**Files:**
- Create: `src/providers/aws/ami_default_creds.rs`
- Modify: `src/providers/aws/mod.rs`, `src/providers/aws/factory.rs`

**Interfaces:**
- Consumes: `aws_sdk_ssm::Client` (State Manager compliance), `aws_sdk_inspector2::Client` (default-credential findings).
- Produces: `pub struct AmiDefaultCredentialScanCollector`, `filename_prefix = "AMI_Default_Credential_Scan"`.

- [ ] **Step 1:** Write the file:

```rust
//! Joins SSM compliance items with Inspector2 findings for default
//! credentials to prove new AMIs' default authenticators are rotated per
//! FedRAMP IA-05e.

use anyhow::{Context, Result};
use async_trait::async_trait;
use aws_sdk_inspector2::Client as InspectorClient;
use aws_sdk_ssm::Client as SsmClient;

use crate::evidence::CsvCollector;

pub struct AmiDefaultCredentialScanCollector {
    ssm: SsmClient,
    inspector: InspectorClient,
}

impl AmiDefaultCredentialScanCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self {
            ssm: SsmClient::new(config),
            inspector: InspectorClient::new(config),
        }
    }
}

#[async_trait]
impl CsvCollector for AmiDefaultCredentialScanCollector {
    fn name(&self) -> &str {
        "AMI Default-Credential Scan (SSM + Inspector2)"
    }
    fn filename_prefix(&self) -> &str {
        "AMI_Default_Credential_Scan"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Source",
            "Resource ID",
            "Finding Title",
            "Compliance Status",
            "Severity",
            "First Observed",
            "Region",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let mut rows: Vec<Vec<String>> = Vec::new();

        // SSM compliance items — Association type with "CIS" in the association name
        let mut ssm_next: Option<String> = None;
        loop {
            let mut req = self.ssm.list_compliance_items();
            if let Some(t) = ssm_next.as_ref() {
                req = req.next_token(t);
            }
            let resp = req.send().await.context("ssm:ListComplianceItems")?;
            for it in resp.compliance_items() {
                let title = it.title().unwrap_or("");
                if !title.to_lowercase().contains("default")
                    && !title.to_lowercase().contains("credential")
                {
                    continue;
                }
                rows.push(vec![
                    "SSM".into(),
                    it.resource_id().unwrap_or("").into(),
                    title.into(),
                    it.status()
                        .map(|s| s.as_str().to_string())
                        .unwrap_or_default(),
                    it.severity()
                        .map(|s| s.as_str().to_string())
                        .unwrap_or_default(),
                    String::new(),
                    region.into(),
                ]);
            }
            ssm_next = resp.next_token().map(|s| s.to_string());
            if ssm_next.is_none() {
                break;
            }
        }

        // Inspector2 findings — filter to titles mentioning default credentials
        let mut ins_next: Option<String> = None;
        loop {
            let mut req = self.inspector.list_findings();
            if let Some(t) = ins_next.as_ref() {
                req = req.next_token(t);
            }
            let resp = req.send().await.context("inspector2:ListFindings")?;
            for f in resp.findings() {
                let title = f.title().unwrap_or("");
                if !title.to_lowercase().contains("default")
                    && !title.to_lowercase().contains("credential")
                {
                    continue;
                }
                let res = f
                    .resources()
                    .first()
                    .and_then(|r| r.id())
                    .unwrap_or("")
                    .to_string();
                rows.push(vec![
                    "Inspector2".into(),
                    res,
                    title.into(),
                    f.status()
                        .map(|s| s.as_str().to_string())
                        .unwrap_or_default(),
                    f.severity()
                        .map(|s| s.as_str().to_string())
                        .unwrap_or_default(),
                    f.first_observed_at()
                        .map(|t| t.to_string())
                        .unwrap_or_default(),
                    region.into(),
                ]);
            }
            ins_next = resp.next_token().map(|s| s.to_string());
            if ins_next.is_none() {
                break;
            }
        }
        Ok(rows)
    }
}
```

- [ ] **Step 2:** `pub mod ami_default_creds;` in `mod.rs`.
- [ ] **Step 3:** `ami_default_creds::AmiDefaultCredentialScanCollector,` import; `if has("ami-default-creds")` branch.
- [ ] **Step 4:** Verify mapping: `AMI_Default_Credential_Scan` → `NIST-1321` / `IA-05e`. Add if missing.
- [ ] **Step 5:** `cargo check`.
- [ ] **Step 6:** Commit:

```bash
git add src/providers/aws/ami_default_creds.rs src/providers/aws/mod.rs src/providers/aws/factory.rs assets/fedramp-map.json
git -c user.name="Austin Songer" -c user.email="asonger.pixel@gmail.com" commit -m "feat(aws): add AMI default-credential scan collector (IA-05e)"
```

---

## Task 11: Refine mappings for existing collectors that satisfy new controls

Existing collectors already gather the underlying data for two controls the PRD flagged as new; only their `assets/fedramp-map.json` mapping needs updating.

- [ ] **Step 1:** Refine `ClientVPN_Config` and `AWS_Config_Rules` mappings

Run:
```bash
python3 << 'EOF'
import json
p = '/Users/austin-songer/code/grabber/assets/fedramp-map.json'
d = json.load(open(p))

def merge(prefix, req_add, ctrl_add):
    entry = d['collectors'].setdefault(prefix, {'req_ids': [], 'control_ids': []})
    entry['req_ids'] = sorted(set(entry['req_ids']) | set(req_add))
    entry['control_ids'] = sorted(set(entry['control_ids']) | set(ctrl_add))

# ClientVPN_Config already captures split-tunnel in its "Split Tunnel" column;
# grant it SC-07(07) directly rather than shipping a redundant collector.
merge('ClientVPN_Config', ['NIST-1638'], ['SC-07(07)'])

# AWS_Config_Rules includes integrity rules (s3-bucket-versioning,
# cloudtrail-log-file-validation, ec2-managedinstance-inventory); grant SI-07b.
merge('AWS_Config_Rules', ['NIST-1742'], ['SI-07b'])

d['collectors'] = dict(sorted(d['collectors'].items()))
open(p, 'w').write(json.dumps(d, indent=2, ensure_ascii=False) + '\n')
print('OK')
EOF
```

- [ ] **Step 2:** Verify the merge

```bash
python3 -c "
import json
d = json.load(open('/Users/austin-songer/code/grabber/assets/fedramp-map.json'))
for p in ['ClientVPN_Config','AWS_Config_Rules']:
    print(p, '→', d['collectors'][p])
"
```
Expected: both include the new req_ids/control_ids.

- [ ] **Step 3:** Commit

```bash
cd /Users/austin-songer/code/grabber
git add assets/fedramp-map.json
git -c user.name="Austin Songer" -c user.email="asonger.pixel@gmail.com" commit -m "feat(fedramp): map existing ClientVPN_Config to SC-07(07), AWS_Config_Rules to SI-07b

Both existing collectors already gather the underlying data; only the FedRAMP
mapping was missing. Avoids shipping redundant split-tunnel and FIM-rules
collectors."
```

---

## Task 12: Update `evidence-list.md`

- [ ] **Step 1:** Read the current `evidence-list.md` to identify where to insert the new rows (end of appropriate category sections).

- [ ] **Step 2:** Append the following 10 rows to the appropriate sections of `evidence-list.md` (each row's category chosen to match its AWS service):

Add to **### Account & Identity** table (after EV19 or wherever IAM entries live):
```
| EV125 | IAM Credential Report — Password/Key Expiration | `IAM_Credential_Report_Expiration` | User, ARN, User Creation Time, Password Enabled, Password Last Used, Password Last Changed, Password Next Rotation, MFA Active, Access Key 1 Active, Access Key 1 Last Rotated, Access Key 1 Last Used Date, Access Key 2 Active, Access Key 2 Last Rotated, Access Key 2 Last Used Date, Cert 1 Active, Cert 1 Last Rotated, Cert 2 Active, Cert 2 Last Rotated |
```

Add to **### Network** table (after the last `EV87`):
```
| EV126 | Transit Gateways & VPC Peering | `TransitGateway_VPCPeering_Config` | Kind, ID, Name, State, Owner Account, Peer Account, Peer VPC, Peer Region, Local VPC / Subnets, Association, Default Route Table, Notes |
| EV127 | Session Timeouts (ELB / Client VPN / SSM) | `Session_Timeout_Config` | Source, Resource ID, Resource Name, Setting, Value, Region |
| EV128 | Network Firewall Fail-Closed Config | `NetworkFirewall_FailClosed_Config` | Firewall Name, Firewall ARN, Policy ARN, Stream Exception Policy, Stateful Default Actions, Region |
```

Add to **### Systems Manager (SSM)** table:
```
| EV129 | SSM Application Allowlist | `SSM_Application_Allowlist` | Association ID, Association Name, Document Name, Targets, Schedule, Compliance Severity, Last Execution Status, Compliance Type, Region |
| EV130 | SSM Automation Response Runbooks | `SSM_Automation_Response_Runbooks` | Document Name, Owner, Document Type, Document Format, Schema Version, Target Type, Tags, Created Date, Region |
```

Add to **### Backup** table:
```
| EV131 | Documentation Repository Backup Config | `Doc_Repo_Backup_Config` | Kind, Name / ARN, Region, Versioning, Replication, Vault Recovery Points, Notes |
```

Add to **### Security Services** table:
```
| EV132 | GuardDuty Runtime Coverage | `GuardDuty_Runtime_Coverage` | Detector ID, Resource Type, Resource ID, Coverage Status, Issue, Updated At, Region |
| EV133 | GuardDuty Malware Scan History | `GuardDuty_Malware_Scan_History` | Detector ID, Scan ID, Scan Type, Scan Status, Scan Start, Scan End, Total GB Scanned, Threats Found, Region |
| EV134 | AMI Default-Credential Scan | `AMI_Default_Credential_Scan` | Source, Resource ID, Finding Title, Compliance Status, Severity, First Observed, Region |
```

Update the **Summary** table's counts: CSV evidence collectors row is `120 → 130`, Total is `124 → 134`.

- [ ] **Step 3:** Commit

```bash
cd /Users/austin-songer/code/grabber
git add evidence-list.md
git -c user.name="Austin Songer" -c user.email="asonger.pixel@gmail.com" commit -m "docs(evidence): add EV125–EV134 for the 10 new AWS FedRAMP collectors"
```

---

## Self-Review

**1. Spec coverage:** Ten new AWS collectors (Tasks 1–10) covering AC-02(02), CA-09b, CA-09c, CM-07(02)/(05), CP-09c, IA-05e, SC-07(12), SC-07(18), SI-03c, SI-06d. Mapping refinement (Task 11) covers SC-07(07) via existing `ClientVPN_Config` and SI-07b via existing `AWS_Config_Rules`, replacing the PRD's two redundant new collectors. Docs update (Task 12). Every P0-AWS-* item in the parent PRD has an owning task or a mapping-only satisfier.

**2. Placeholder scan:** No "TBD", "similar to Task N", or "add appropriate error handling". Each task contains complete Rust source for the collector, exact SDK method calls, exact column headers, and exact commit message. Task 8's note about a possible SDK field-name difference for `total_bytes` names the concrete fallback: implementer inspects `aws_sdk_guardduty::types::Scan` and adjusts — that is not a placeholder, it's a targeted permission to compensate for SDK-version drift.

**3. Type consistency:** All collector struct names end in `Collector` and follow the pattern seen in `access_analyzer.rs`. `filename_prefix()` strings are exactly the JSON mapping keys used in Step 4 of each task and in Task 12's `evidence-list.md` rows. `factory.rs` `has()` keys are lowercase-hyphenated and mirror the collector's purpose (`iam-cred-report`, `tgw-peering`, `session-timeouts`, `ssm-allowlist`, `doc-repo-backup`, `guardduty-runtime`, `nfw-failclosed`, `guardduty-malware`, `ssm-automation`, `ami-default-creds`).

---

## Execution Handoff

Plan saved to `docs/superpowers/plans/2026-07-16-fedramp-aws-collectors.md`. Executing via superpowers:subagent-driven-development immediately per the parallel-execution mandate.
