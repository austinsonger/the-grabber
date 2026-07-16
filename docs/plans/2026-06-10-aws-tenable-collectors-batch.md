# AWS + Tenable Collectors Batch Implementation Plan

**Goal:** Add 9 new AWS CSV collectors and 1 Tenable scanner-permissions collector to unlock IRL evidence items mapped to NIST 800-53 controls (AC-17, SC-5/7/12/17/20/21, IA-2/5/8, CM-7/8/10/11, MA-4, RA-5).

**Architecture:** Each collector is a struct implementing `crate::evidence::CsvCollector` (same shape as `src/providers/aws/route53_config.rs`). They are wired in `src/providers/aws/mod.rs` (`pub mod …;`) and conditionally registered in `src/providers/aws/factory.rs::csv_collectors()` keyed off a `selected` collector name. New AWS SDK crates (`aws-sdk-acmpca`, `aws-sdk-shield`, `aws-sdk-licensemanager`, `aws-sdk-servicequotas`, `aws-sdk-networkfirewall`) are added to `Cargo.toml`. Tenable scanner permissions extend `crates/tenable-rs/src/api/` with a `users` module.

**Tech Stack:** Rust 2021, `aws-sdk-*` v1 crates, `async-trait`, `anyhow`, existing `tenable-rs` crate (reqwest-backed).

---

## File Structure

**New AWS collector modules (each a single `.rs` file under `src/providers/aws/`):**
- `client_vpn.rs` — `AwsClientVpnCollector`
- `acm_pca.rs` — `AcmPrivateCaCollector`
- `ssm_software_inventory.rs` — `SsmSoftwareInventoryCollector`
- `shield.rs` — `ShieldCollector`
- `license_manager.rs` — `LicenseManagerCollector`
- `service_quotas.rs` — `ServiceQuotasCollector`
- `network_firewall.rs` — `NetworkFirewallCollector`
- `ssm_sessions.rs` — `SsmSessionsCollector`

**Modified files:**
- `src/providers/aws/mod.rs` — add `pub mod` declarations
- `src/providers/aws/factory.rs` — `use` imports + `if has(...)` blocks in `csv_collectors()`
- `src/providers/aws/route53_config.rs` — extend with `Route53DnssecCollector`
- `Cargo.toml` — add 5 new `aws-sdk-*` crates
- `crates/tenable-rs/src/api/mod.rs` — `pub mod users;` + re-export
- `crates/tenable-rs/src/api/users.rs` — new `UsersApi`

Each AWS collector implements `CsvCollector` with `name`, `filename_prefix`, `headers`, `collect_rows`. Errors from optional/secondary calls are logged via `eprintln!("  WARN: …")` (mirrors `route53_config.rs:174`) — do not fail the whole collector when a sub-call errors on a single item.

---

## Conventions (apply to every task)

- File header always: `use anyhow::{Context, Result}; use async_trait::async_trait; use aws_sdk_<svc>::Client as <Svc>Client; use crate::evidence::CsvCollector;`
- Constructor: `pub fn new(config: &aws_config::SdkConfig) -> Self { Self { client: <Svc>Client::new(config) } }`
- `collect_rows(&self, _account_id: &str, _region: &str, _dates: Option<(i64, i64)>)` — match the route53 signature exactly.
- After every task: run `cargo check -p grabber` (or workspace root `cargo check`). On the final task, also run `cargo clippy --all-targets -- -D warnings` and `cargo build --release`.
- Commit messages: `feat(aws): add <Name> collector` (or `feat(tenable): …`).

---

## Task 1: Add AWS SDK crate dependencies

**Files:**
- Modify: `Cargo.toml` (top-level workspace)

- [ ] **Step 1: Open `Cargo.toml` and locate the `aws-sdk-*` block (around lines 17–36).**

- [ ] **Step 2: Append the five new SDK dependencies after the existing `aws-sdk-autoscaling = "1"` line.**

```toml
aws-sdk-acmpca = "1"
aws-sdk-shield = "1"
aws-sdk-licensemanager = "1"
aws-sdk-servicequotas = "1"
aws-sdk-networkfirewall = "1"
```

- [ ] **Step 3: Verify dependencies resolve.**

Run: `cargo check`
Expected: PASS (downloads + compiles the new crates; no source code uses them yet, so warnings are fine).

- [ ] **Step 4: Commit.**

```bash
git add Cargo.toml Cargo.lock
git commit -m "build(aws): add acm-pca, shield, license-manager, service-quotas, network-firewall SDK crates"
```

---

## Task 2: AWS Client VPN collector (R-1184, R-1189, R-1190, R-1194, R-1337, R-1649 / AC-17, SC-7, IA-2(11))

**Files:**
- Create: `src/providers/aws/client_vpn.rs`
- Modify: `src/providers/aws/mod.rs`
- Modify: `src/providers/aws/factory.rs`

- [ ] **Step 1: Create `src/providers/aws/client_vpn.rs` with the full collector below.**

```rust
use anyhow::{Context, Result};
use async_trait::async_trait;
use aws_sdk_ec2::Client as Ec2Client;

use crate::evidence::CsvCollector;

pub struct AwsClientVpnCollector {
    client: Ec2Client,
}

impl AwsClientVpnCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self {
            client: Ec2Client::new(config),
        }
    }
}

#[async_trait]
impl CsvCollector for AwsClientVpnCollector {
    fn name(&self) -> &str {
        "AWS Client VPN"
    }
    fn filename_prefix(&self) -> &str {
        "ClientVPN_Config"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Endpoint ID",
            "Description",
            "Status",
            "Client CIDR",
            "Server Cert ARN",
            "Authentication Types",
            "Connection Log Enabled",
            "Connection Log Group",
            "Split Tunnel",
            "Transport Protocol",
            "DNS Servers",
            "Self-Service Portal",
            "Session Timeout Hours",
            "Routes",
            "Authorization Rules",
            "Active Connections",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let mut rows = Vec::new();
        let mut next_token: Option<String> = None;

        loop {
            let mut req = self.client.describe_client_vpn_endpoints();
            if let Some(ref t) = next_token {
                req = req.next_token(t);
            }
            let resp = req
                .send()
                .await
                .context("ec2 describe_client_vpn_endpoints")?;

            for ep in resp.client_vpn_endpoints() {
                let id = ep.client_vpn_endpoint_id().unwrap_or("").to_string();
                let desc = ep.description().unwrap_or("").to_string();
                let status = ep
                    .status()
                    .and_then(|s| s.code())
                    .map(|c| c.as_str().to_string())
                    .unwrap_or_default();
                let cidr = ep.client_cidr_block().unwrap_or("").to_string();
                let server_cert = ep.server_certificate_arn().unwrap_or("").to_string();
                let auth_types: Vec<String> = ep
                    .authentication_options()
                    .iter()
                    .map(|a| {
                        a.r#type()
                            .map(|t| t.as_str().to_string())
                            .unwrap_or_default()
                    })
                    .collect();
                let (log_enabled, log_group) = match ep.connection_log_options() {
                    Some(cl) => (
                        cl.enabled().unwrap_or(false).to_string(),
                        cl.cloudwatch_log_group().unwrap_or("").to_string(),
                    ),
                    None => (String::from("false"), String::new()),
                };
                let split_tunnel = ep.split_tunnel().unwrap_or(false).to_string();
                let transport = ep
                    .transport_protocol()
                    .map(|p| p.as_str().to_string())
                    .unwrap_or_default();
                let dns = ep.dns_servers().join(", ");
                let portal = ep
                    .self_service_portal_url()
                    .map(|_| "enabled".to_string())
                    .unwrap_or_else(|| "disabled".to_string());
                let timeout = ep
                    .session_timeout_hours()
                    .map(|h| h.to_string())
                    .unwrap_or_default();

                let routes = match self
                    .client
                    .describe_client_vpn_routes()
                    .client_vpn_endpoint_id(&id)
                    .send()
                    .await
                {
                    Ok(r) => r
                        .routes()
                        .iter()
                        .map(|rt| {
                            let dest = rt.destination_cidr().unwrap_or("");
                            let tgt = rt.target_subnet().unwrap_or("");
                            format!("{dest}->{tgt}")
                        })
                        .collect::<Vec<_>>()
                        .join("; "),
                    Err(e) => {
                        eprintln!("  WARN: ClientVPN describe_client_vpn_routes({id}): {e:#}");
                        String::new()
                    }
                };

                let auth_rules = match self
                    .client
                    .describe_client_vpn_authorization_rules()
                    .client_vpn_endpoint_id(&id)
                    .send()
                    .await
                {
                    Ok(r) => r
                        .authorization_rules()
                        .iter()
                        .map(|ar| {
                            let net = ar.destination_cidr().unwrap_or("");
                            let group = ar.group_id().unwrap_or("ALL");
                            let access = ar
                                .status()
                                .and_then(|s| s.code())
                                .map(|c| c.as_str().to_string())
                                .unwrap_or_default();
                            format!("{net}|{group}|{access}")
                        })
                        .collect::<Vec<_>>()
                        .join("; "),
                    Err(e) => {
                        eprintln!(
                            "  WARN: ClientVPN describe_client_vpn_authorization_rules({id}): {e:#}"
                        );
                        String::new()
                    }
                };

                let conns = match self
                    .client
                    .describe_client_vpn_connections()
                    .client_vpn_endpoint_id(&id)
                    .send()
                    .await
                {
                    Ok(r) => r
                        .connections()
                        .iter()
                        .filter(|c| {
                            c.status()
                                .and_then(|s| s.code())
                                .map(|c| c.as_str() == "active")
                                .unwrap_or(false)
                        })
                        .count()
                        .to_string(),
                    Err(e) => {
                        eprintln!(
                            "  WARN: ClientVPN describe_client_vpn_connections({id}): {e:#}"
                        );
                        String::new()
                    }
                };

                rows.push(vec![
                    id,
                    desc,
                    status,
                    cidr,
                    server_cert,
                    auth_types.join(", "),
                    log_enabled,
                    log_group,
                    split_tunnel,
                    transport,
                    dns,
                    portal,
                    timeout,
                    routes,
                    auth_rules,
                    conns,
                ]);
            }

            next_token = resp.next_token().map(|s| s.to_string());
            if next_token.is_none() {
                break;
            }
        }

        Ok(rows)
    }
}
```

- [ ] **Step 2: Register the module in `src/providers/aws/mod.rs`.**

Insert `pub mod client_vpn;` in alphabetical order (between `cloudwatch_resources` and `config_history`).

- [ ] **Step 3: Add `use` import in `src/providers/aws/factory.rs`.**

Find the existing block of `aws::…` imports (near the top, where `route53_config::{…}` lives at line 77) and add:

```rust
use crate::providers::aws::client_vpn::AwsClientVpnCollector;
```

(Match the import style already in the file — if the file uses `use super::client_vpn::…` or grouped `use crate::providers::aws::{…}`, mirror that.)

- [ ] **Step 4: Register in `csv_collectors()` in `src/providers/aws/factory.rs`.**

Add this `if has` block in the same neighborhood as the route53 ones (around line 489):

```rust
if has("client-vpn") {
    v.push(Box::new(AwsClientVpnCollector::new(cfg)));
}
```

- [ ] **Step 5: Build.**

Run: `cargo check`
Expected: PASS, no errors. (Warnings about unused `_account_id` are pre-existing pattern.)

- [ ] **Step 6: Commit.**

```bash
git add src/providers/aws/client_vpn.rs src/providers/aws/mod.rs src/providers/aws/factory.rs
git commit -m "feat(aws): add Client VPN collector"
```

---

## Task 3: ACM Private CA collector (R-1229, R-1231, R-1602–1605 / SC-12, SC-17, IA-5(2))

**Files:**
- Create: `src/providers/aws/acm_pca.rs`
- Modify: `src/providers/aws/mod.rs`
- Modify: `src/providers/aws/factory.rs`

- [ ] **Step 1: Create `src/providers/aws/acm_pca.rs`.**

```rust
use anyhow::{Context, Result};
use async_trait::async_trait;
use aws_sdk_acmpca::Client as PcaClient;

use crate::evidence::CsvCollector;

pub struct AcmPrivateCaCollector {
    client: PcaClient,
}

impl AcmPrivateCaCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self {
            client: PcaClient::new(config),
        }
    }
}

#[async_trait]
impl CsvCollector for AcmPrivateCaCollector {
    fn name(&self) -> &str {
        "ACM Private CA"
    }
    fn filename_prefix(&self) -> &str {
        "ACM_PCA_Config"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "CA ARN",
            "Type",
            "Status",
            "Key Algorithm",
            "Signing Algorithm",
            "Subject CN",
            "Created",
            "Not Before",
            "Not After",
            "CRL Enabled",
            "CRL S3 Bucket",
            "CRL Expiration Days",
            "OCSP Enabled",
            "OCSP Custom CName",
            "Usage Mode",
            "Permissions Count",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let mut rows = Vec::new();
        let mut next_token: Option<String> = None;

        loop {
            let mut req = self.client.list_certificate_authorities();
            if let Some(ref t) = next_token {
                req = req.next_token(t);
            }
            let resp = req
                .send()
                .await
                .context("acm-pca list_certificate_authorities")?;

            for ca in resp.certificate_authorities() {
                let arn = ca.arn().unwrap_or("").to_string();
                let ca_type = ca
                    .r#type()
                    .map(|t| t.as_str().to_string())
                    .unwrap_or_default();
                let status = ca
                    .status()
                    .map(|s| s.as_str().to_string())
                    .unwrap_or_default();
                let created = ca
                    .created_at()
                    .map(|d| d.to_string())
                    .unwrap_or_default();
                let not_before = ca
                    .not_before()
                    .map(|d| d.to_string())
                    .unwrap_or_default();
                let not_after = ca
                    .not_after()
                    .map(|d| d.to_string())
                    .unwrap_or_default();
                let usage_mode = ca
                    .usage_mode()
                    .map(|u| u.as_str().to_string())
                    .unwrap_or_default();

                let (key_alg, sign_alg, subject) = match ca.certificate_authority_configuration() {
                    Some(c) => (
                        c.key_algorithm().map(|k| k.as_str().to_string()).unwrap_or_default(),
                        c.signing_algorithm().map(|s| s.as_str().to_string()).unwrap_or_default(),
                        c.subject()
                            .and_then(|s| s.common_name())
                            .unwrap_or("")
                            .to_string(),
                    ),
                    None => (String::new(), String::new(), String::new()),
                };

                let (crl_enabled, crl_bucket, crl_days, ocsp_enabled, ocsp_cname) =
                    match ca.revocation_configuration() {
                        Some(rc) => {
                            let (ce, cb, cd) = match rc.crl_configuration() {
                                Some(c) => (
                                    c.enabled().to_string(),
                                    c.s3_bucket_name().unwrap_or("").to_string(),
                                    c.expiration_in_days()
                                        .map(|d| d.to_string())
                                        .unwrap_or_default(),
                                ),
                                None => (String::from("false"), String::new(), String::new()),
                            };
                            let (oe, oc) = match rc.ocsp_configuration() {
                                Some(o) => (
                                    o.enabled().to_string(),
                                    o.ocsp_custom_cname().unwrap_or("").to_string(),
                                ),
                                None => (String::from("false"), String::new()),
                            };
                            (ce, cb, cd, oe, oc)
                        }
                        None => (
                            String::from("false"),
                            String::new(),
                            String::new(),
                            String::from("false"),
                            String::new(),
                        ),
                    };

                let perms_count = match self
                    .client
                    .list_permissions()
                    .certificate_authority_arn(&arn)
                    .send()
                    .await
                {
                    Ok(p) => p.permissions().len().to_string(),
                    Err(e) => {
                        eprintln!("  WARN: acm-pca list_permissions({arn}): {e:#}");
                        String::new()
                    }
                };

                rows.push(vec![
                    arn,
                    ca_type,
                    status,
                    key_alg,
                    sign_alg,
                    subject,
                    created,
                    not_before,
                    not_after,
                    crl_enabled,
                    crl_bucket,
                    crl_days,
                    ocsp_enabled,
                    ocsp_cname,
                    usage_mode,
                    perms_count,
                ]);
            }

            next_token = resp.next_token().map(|s| s.to_string());
            if next_token.is_none() {
                break;
            }
        }

        Ok(rows)
    }
}
```

- [ ] **Step 2: Add `pub mod acm_pca;` to `src/providers/aws/mod.rs` (after `pub mod acm;`).**

- [ ] **Step 3: Add to `src/providers/aws/factory.rs` imports.**

```rust
use crate::providers::aws::acm_pca::AcmPrivateCaCollector;
```

- [ ] **Step 4: Register in `csv_collectors()`.**

```rust
if has("acm-pca") {
    v.push(Box::new(AcmPrivateCaCollector::new(cfg)));
}
```

- [ ] **Step 5: Build.**

Run: `cargo check`
Expected: PASS.

- [ ] **Step 6: Commit.**

```bash
git add src/providers/aws/acm_pca.rs src/providers/aws/mod.rs src/providers/aws/factory.rs
git commit -m "feat(aws): add ACM Private CA collector"
```

---

## Task 4: SSM Software Inventory collector (R-1486, R-1489, R-1497, R-1474, R-1493 / CM-7(5), CM-8(3), CM-10(1), CM-11)

**Files:**
- Create: `src/providers/aws/ssm_software_inventory.rs`
- Modify: `src/providers/aws/mod.rs`
- Modify: `src/providers/aws/factory.rs`

- [ ] **Step 1: Create `src/providers/aws/ssm_software_inventory.rs`.**

```rust
use anyhow::{Context, Result};
use async_trait::async_trait;
use aws_sdk_ssm::Client as SsmClient;

use crate::evidence::CsvCollector;

pub struct SsmSoftwareInventoryCollector {
    client: SsmClient,
}

impl SsmSoftwareInventoryCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self {
            client: SsmClient::new(config),
        }
    }
}

#[async_trait]
impl CsvCollector for SsmSoftwareInventoryCollector {
    fn name(&self) -> &str {
        "SSM Software Inventory"
    }
    fn filename_prefix(&self) -> &str {
        "SSM_Software_Inventory"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Instance ID",
            "Application Name",
            "Version",
            "Publisher",
            "Architecture",
            "Install Time",
            "Package ID",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let mut rows = Vec::new();
        let mut next_token: Option<String> = None;

        loop {
            let mut req = self
                .client
                .get_inventory()
                .filters(
                    aws_sdk_ssm::types::InventoryFilter::builder()
                        .key("AWS:Application.Name")
                        .values("*")
                        .r#type(aws_sdk_ssm::types::InventoryQueryOperatorType::Exists)
                        .build()
                        .context("build inventory filter")?,
                );
            if let Some(ref t) = next_token {
                req = req.next_token(t);
            }
            let resp = match req.send().await {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("  WARN: ssm get_inventory: {e:#}");
                    break;
                }
            };

            for entity in resp.entities() {
                let instance_id = entity.id().unwrap_or("").to_string();
                let data = entity.data();
                let Some(app_data) = data.get("AWS:Application") else {
                    continue;
                };
                for content in app_data.content() {
                    let name = content.get("Name").cloned().unwrap_or_default();
                    let version = content.get("Version").cloned().unwrap_or_default();
                    let publisher = content.get("Publisher").cloned().unwrap_or_default();
                    let arch = content.get("Architecture").cloned().unwrap_or_default();
                    let install_time = content.get("InstalledTime").cloned().unwrap_or_default();
                    let pkg_id = content.get("PackageId").cloned().unwrap_or_default();
                    rows.push(vec![
                        instance_id.clone(),
                        name,
                        version,
                        publisher,
                        arch,
                        install_time,
                        pkg_id,
                    ]);
                }
            }

            next_token = resp.next_token().map(|s| s.to_string());
            if next_token.is_none() {
                break;
            }
        }

        Ok(rows)
    }
}
```

- [ ] **Step 2: Add `pub mod ssm_software_inventory;` to `src/providers/aws/mod.rs` (alphabetical, near `ssm_patch_detail`).**

- [ ] **Step 3: Add import in `factory.rs`.**

```rust
use crate::providers::aws::ssm_software_inventory::SsmSoftwareInventoryCollector;
```

- [ ] **Step 4: Register in `csv_collectors()`.**

```rust
if has("ssm-software-inventory") {
    v.push(Box::new(SsmSoftwareInventoryCollector::new(cfg)));
}
```

- [ ] **Step 5: Build.**

Run: `cargo check`
Expected: PASS. If `InventoryFilter::builder().build()` returns a non-Result in this SDK version, drop the `.context(...)?` and pass the value directly. Adjust if the compiler complains.

- [ ] **Step 6: Commit.**

```bash
git add src/providers/aws/ssm_software_inventory.rs src/providers/aws/mod.rs src/providers/aws/factory.rs
git commit -m "feat(aws): add SSM software inventory collector"
```

---

## Task 5: AWS Shield collector (R-1647 / SC-5)

**Files:**
- Create: `src/providers/aws/shield.rs`
- Modify: `src/providers/aws/mod.rs`
- Modify: `src/providers/aws/factory.rs`

- [ ] **Step 1: Create `src/providers/aws/shield.rs`.**

```rust
use anyhow::Result;
use async_trait::async_trait;
use aws_sdk_shield::Client as ShieldClient;

use crate::evidence::CsvCollector;

pub struct ShieldCollector {
    client: ShieldClient,
}

impl ShieldCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self {
            client: ShieldClient::new(config),
        }
    }
}

#[async_trait]
impl CsvCollector for ShieldCollector {
    fn name(&self) -> &str {
        "AWS Shield"
    }
    fn filename_prefix(&self) -> &str {
        "Shield_Config"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Record Type",
            "Identifier",
            "Detail Key",
            "Detail Value",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let mut rows = Vec::new();

        match self.client.describe_subscription().send().await {
            Ok(s) => {
                if let Some(sub) = s.subscription() {
                    let start = sub.start_time().map(|d| d.to_string()).unwrap_or_default();
                    let end = sub.end_time().map(|d| d.to_string()).unwrap_or_default();
                    let auto_renew = sub
                        .auto_renew()
                        .map(|a| a.as_str().to_string())
                        .unwrap_or_default();
                    rows.push(vec!["Subscription".into(), String::new(), "StartTime".into(), start]);
                    rows.push(vec!["Subscription".into(), String::new(), "EndTime".into(), end]);
                    rows.push(vec!["Subscription".into(), String::new(), "AutoRenew".into(), auto_renew]);
                } else {
                    rows.push(vec!["Subscription".into(), String::new(), "Status".into(), "Not Subscribed".into()]);
                }
            }
            Err(e) => {
                eprintln!("  WARN: shield describe_subscription: {e:#}");
            }
        }

        match self.client.describe_emergency_contact_settings().send().await {
            Ok(c) => {
                for (i, contact) in c.emergency_contact_list().iter().enumerate() {
                    let email = contact.email_address().to_string();
                    let phone = contact.phone_number().unwrap_or("").to_string();
                    let notes = contact.contact_notes().unwrap_or("").to_string();
                    rows.push(vec![
                        "EmergencyContact".into(),
                        format!("contact-{i}"),
                        "Email".into(),
                        email,
                    ]);
                    rows.push(vec![
                        "EmergencyContact".into(),
                        format!("contact-{i}"),
                        "Phone".into(),
                        phone,
                    ]);
                    rows.push(vec![
                        "EmergencyContact".into(),
                        format!("contact-{i}"),
                        "Notes".into(),
                        notes,
                    ]);
                }
            }
            Err(e) => {
                eprintln!("  WARN: shield describe_emergency_contact_settings: {e:#}");
            }
        }

        let mut next_token: Option<String> = None;
        loop {
            let mut req = self.client.list_protections();
            if let Some(ref t) = next_token {
                req = req.next_token(t);
            }
            let resp = match req.send().await {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("  WARN: shield list_protections: {e:#}");
                    break;
                }
            };
            for prot in resp.protections() {
                let id = prot.id().unwrap_or("").to_string();
                let name = prot.name().unwrap_or("").to_string();
                let res_arn = prot.resource_arn().unwrap_or("").to_string();
                rows.push(vec!["Protection".into(), id.clone(), "Name".into(), name]);
                rows.push(vec!["Protection".into(), id, "ResourceArn".into(), res_arn]);
            }
            next_token = resp.next_token().map(|s| s.to_string());
            if next_token.is_none() {
                break;
            }
        }

        Ok(rows)
    }
}
```

- [ ] **Step 2: Add `pub mod shield;` to `src/providers/aws/mod.rs`.**

- [ ] **Step 3: Add to `factory.rs`.**

```rust
use crate::providers::aws::shield::ShieldCollector;
```

```rust
if has("shield") {
    v.push(Box::new(ShieldCollector::new(cfg)));
}
```

- [ ] **Step 4: Build.**

Run: `cargo check`
Expected: PASS.

- [ ] **Step 5: Commit.**

```bash
git add src/providers/aws/shield.rs src/providers/aws/mod.rs src/providers/aws/factory.rs
git commit -m "feat(aws): add Shield/DDoS collector"
```

---

## Task 6: License Manager collector (R-1492 / CM-10)

**Files:**
- Create: `src/providers/aws/license_manager.rs`
- Modify: `src/providers/aws/mod.rs`
- Modify: `src/providers/aws/factory.rs`

- [ ] **Step 1: Create `src/providers/aws/license_manager.rs`.**

```rust
use anyhow::{Context, Result};
use async_trait::async_trait;
use aws_sdk_licensemanager::Client as LmClient;

use crate::evidence::CsvCollector;

pub struct LicenseManagerCollector {
    client: LmClient,
}

impl LicenseManagerCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self {
            client: LmClient::new(config),
        }
    }
}

#[async_trait]
impl CsvCollector for LicenseManagerCollector {
    fn name(&self) -> &str {
        "License Manager"
    }
    fn filename_prefix(&self) -> &str {
        "LicenseManager_Config"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Config ARN",
            "Name",
            "Description",
            "License Count",
            "License Count Hard Limit",
            "License Counting Type",
            "Status",
            "Consumed Licenses",
            "Owner Account",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let mut rows = Vec::new();
        let mut next_token: Option<String> = None;

        loop {
            let mut req = self.client.list_license_configurations();
            if let Some(ref t) = next_token {
                req = req.next_token(t);
            }
            let resp = req
                .send()
                .await
                .context("license-manager list_license_configurations")?;

            for cfg_item in resp.license_configurations() {
                let arn = cfg_item.license_configuration_arn().unwrap_or("").to_string();
                let name = cfg_item.name().unwrap_or("").to_string();
                let desc = cfg_item.description().unwrap_or("").to_string();
                let count = cfg_item
                    .license_count()
                    .map(|n| n.to_string())
                    .unwrap_or_default();
                let hard = cfg_item
                    .license_count_hard_limit()
                    .unwrap_or(false)
                    .to_string();
                let ctype = cfg_item
                    .license_counting_type()
                    .map(|t| t.as_str().to_string())
                    .unwrap_or_default();
                let status = cfg_item.status().unwrap_or("").to_string();
                let consumed = cfg_item
                    .consumed_licenses()
                    .map(|n| n.to_string())
                    .unwrap_or_default();
                let owner = cfg_item.owner_account_id().unwrap_or("").to_string();

                rows.push(vec![
                    arn, name, desc, count, hard, ctype, status, consumed, owner,
                ]);
            }

            next_token = resp.next_token().map(|s| s.to_string());
            if next_token.is_none() {
                break;
            }
        }

        Ok(rows)
    }
}
```

- [ ] **Step 2: Wire in `mod.rs`, `factory.rs`.**

`pub mod license_manager;`

```rust
use crate::providers::aws::license_manager::LicenseManagerCollector;
```

```rust
if has("license-manager") {
    v.push(Box::new(LicenseManagerCollector::new(cfg)));
}
```

- [ ] **Step 3: Build.**

Run: `cargo check`
Expected: PASS.

- [ ] **Step 4: Commit.**

```bash
git add src/providers/aws/license_manager.rs src/providers/aws/mod.rs src/providers/aws/factory.rs
git commit -m "feat(aws): add License Manager collector"
```

---

## Task 7: Service Quotas collector (R-1648 / SC-6)

**Files:**
- Create: `src/providers/aws/service_quotas.rs`
- Modify: `src/providers/aws/mod.rs`
- Modify: `src/providers/aws/factory.rs`

- [ ] **Step 1: Create `src/providers/aws/service_quotas.rs`.**

```rust
use anyhow::{Context, Result};
use async_trait::async_trait;
use aws_sdk_servicequotas::Client as SqClient;

use crate::evidence::CsvCollector;

const TRACKED_SERVICES: &[&str] = &[
    "ec2", "vpc", "rds", "lambda", "iam", "kms", "s3", "elasticloadbalancing", "logs",
];

pub struct ServiceQuotasCollector {
    client: SqClient,
}

impl ServiceQuotasCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self {
            client: SqClient::new(config),
        }
    }
}

#[async_trait]
impl CsvCollector for ServiceQuotasCollector {
    fn name(&self) -> &str {
        "Service Quotas"
    }
    fn filename_prefix(&self) -> &str {
        "ServiceQuotas"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Service Code",
            "Quota Code",
            "Quota Name",
            "Value",
            "Unit",
            "Adjustable",
            "Global Quota",
            "Source",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let mut rows = Vec::new();

        for svc in TRACKED_SERVICES {
            let mut next_token: Option<String> = None;
            loop {
                let mut req = self.client.list_service_quotas().service_code(*svc);
                if let Some(ref t) = next_token {
                    req = req.next_token(t);
                }
                let resp = match req.send().await {
                    Ok(r) => r,
                    Err(e) => {
                        eprintln!("  WARN: service-quotas list_service_quotas({svc}): {e:#}");
                        break;
                    }
                };
                for q in resp.quotas() {
                    rows.push(vec![
                        q.service_code().unwrap_or("").to_string(),
                        q.quota_code().unwrap_or("").to_string(),
                        q.quota_name().unwrap_or("").to_string(),
                        q.value().map(|v| v.to_string()).unwrap_or_default(),
                        q.unit().unwrap_or("").to_string(),
                        q.adjustable().to_string(),
                        q.global_quota().to_string(),
                        "applied".into(),
                    ]);
                }
                next_token = resp.next_token().map(|s| s.to_string());
                if next_token.is_none() {
                    break;
                }
            }

            let mut next_token: Option<String> = None;
            loop {
                let mut req = self
                    .client
                    .list_aws_default_service_quotas()
                    .service_code(*svc);
                if let Some(ref t) = next_token {
                    req = req.next_token(t);
                }
                let resp = match req.send().await {
                    Ok(r) => r,
                    Err(e) => {
                        eprintln!(
                            "  WARN: service-quotas list_aws_default_service_quotas({svc}): {e:#}"
                        );
                        break;
                    }
                };
                for q in resp.quotas() {
                    rows.push(vec![
                        q.service_code().unwrap_or("").to_string(),
                        q.quota_code().unwrap_or("").to_string(),
                        q.quota_name().unwrap_or("").to_string(),
                        q.value().map(|v| v.to_string()).unwrap_or_default(),
                        q.unit().unwrap_or("").to_string(),
                        q.adjustable().to_string(),
                        q.global_quota().to_string(),
                        "default".into(),
                    ]);
                }
                next_token = resp.next_token().map(|s| s.to_string());
                if next_token.is_none() {
                    break;
                }
            }
        }

        let _ = Context::context::<&'static str, anyhow::Error>; // silence unused import if dead
        Ok(rows)
    }
}
```

Note: drop the `use anyhow::Context` if the compiler flags it as unused (the body uses `eprintln!` for errors rather than `.context(...)?`). The trailing `_ = Context::…` line is a hack; just remove `Context` from the import line instead — `use anyhow::Result;`.

- [ ] **Step 2: Wire in `mod.rs`, `factory.rs`.**

`pub mod service_quotas;`

```rust
use crate::providers::aws::service_quotas::ServiceQuotasCollector;
```

```rust
if has("service-quotas") {
    v.push(Box::new(ServiceQuotasCollector::new(cfg)));
}
```

- [ ] **Step 3: Build.**

Run: `cargo check`
Expected: PASS. Fix the unused-import on `Context` if it fires.

- [ ] **Step 4: Commit.**

```bash
git add src/providers/aws/service_quotas.rs src/providers/aws/mod.rs src/providers/aws/factory.rs
git commit -m "feat(aws): add Service Quotas collector"
```

---

## Task 8: Route53 DNSSEC extension (R-1654 / SC-20, SC-21)

**Files:**
- Modify: `src/providers/aws/route53_config.rs`
- Modify: `src/providers/aws/factory.rs`

- [ ] **Step 1: Append a new collector struct to `src/providers/aws/route53_config.rs`.**

Add at the end of the file (after `Route53ResolverRulesCollector`, after line 222):

```rust
// ══════════════════════════════════════════════════════════════════════════════
// 3. Route53 DNSSEC
// ══════════════════════════════════════════════════════════════════════════════

pub struct Route53DnssecCollector {
    client: R53Client,
}

impl Route53DnssecCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self {
            client: R53Client::new(config),
        }
    }
}

#[async_trait]
impl CsvCollector for Route53DnssecCollector {
    fn name(&self) -> &str {
        "Route53 DNSSEC"
    }
    fn filename_prefix(&self) -> &str {
        "Route53_DNSSEC"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Zone ID",
            "Zone Name",
            "Private Zone",
            "Signing Status",
            "Status Message",
            "KSK Count",
            "KSK Names",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let mut rows = Vec::new();
        let mut marker: Option<String> = None;

        loop {
            let mut req = self.client.list_hosted_zones();
            if let Some(ref m) = marker {
                req = req.marker(m);
            }
            let resp = req
                .send()
                .await
                .context("Route53 list_hosted_zones (dnssec)")?;

            for zone in resp.hosted_zones() {
                let zone_id = zone.id().trim_start_matches("/hostedzone/").to_string();
                let name = zone.name().to_string();
                let private = zone
                    .config()
                    .map(|c| c.private_zone().to_string())
                    .unwrap_or_else(|| "false".to_string());

                // DNSSEC only applies to public zones; private zones return InvalidInput.
                if private == "true" {
                    rows.push(vec![
                        zone_id,
                        name,
                        private,
                        "NOT_APPLICABLE".into(),
                        "Private zone".into(),
                        "0".into(),
                        String::new(),
                    ]);
                    continue;
                }

                match self.client.get_dnssec().hosted_zone_id(&zone_id).send().await {
                    Ok(d) => {
                        let (status, msg) = match d.status() {
                            Some(s) => (
                                s.serve_signature().unwrap_or("").to_string(),
                                s.status_message().unwrap_or("").to_string(),
                            ),
                            None => (String::new(), String::new()),
                        };
                        let ksks = d.key_signing_keys();
                        let ksk_count = ksks.len().to_string();
                        let ksk_names = ksks
                            .iter()
                            .map(|k| k.name().unwrap_or("").to_string())
                            .collect::<Vec<_>>()
                            .join(", ");
                        rows.push(vec![
                            zone_id, name, private, status, msg, ksk_count, ksk_names,
                        ]);
                    }
                    Err(e) => {
                        eprintln!("  WARN: Route53 get_dnssec({zone_id}): {e:#}");
                        rows.push(vec![
                            zone_id,
                            name,
                            private,
                            "ERROR".into(),
                            format!("{e}"),
                            String::new(),
                            String::new(),
                        ]);
                    }
                }
            }

            marker = if resp.is_truncated() {
                resp.next_marker().map(|s| s.to_string())
            } else {
                None
            };
            if marker.is_none() {
                break;
            }
        }

        Ok(rows)
    }
}
```

- [ ] **Step 2: Update the `factory.rs` import to include the new struct.**

Change `route53_config::{Route53ResolverRulesCollector, Route53ZonesCollector}` (line 77) to:

```rust
route53_config::{Route53DnssecCollector, Route53ResolverRulesCollector, Route53ZonesCollector},
```

- [ ] **Step 3: Register in `csv_collectors()` right after the existing route53 blocks (~line 494).**

```rust
if has("route53-dnssec") {
    v.push(Box::new(Route53DnssecCollector::new(cfg)));
}
```

- [ ] **Step 4: Build.**

Run: `cargo check`
Expected: PASS. If `GetDnssecOutput::status()` or `key_signing_keys()` signatures differ in your `aws-sdk-route53` minor version, adjust accordingly (the methods exist since 1.x; field shape rare to change).

- [ ] **Step 5: Commit.**

```bash
git add src/providers/aws/route53_config.rs src/providers/aws/factory.rs
git commit -m "feat(aws): add Route53 DNSSEC collector"
```

---

## Task 9: AWS Network Firewall collector (R-1278 / SC-7(5), SC-7(18))

**Files:**
- Create: `src/providers/aws/network_firewall.rs`
- Modify: `src/providers/aws/mod.rs`
- Modify: `src/providers/aws/factory.rs`

- [ ] **Step 1: Create `src/providers/aws/network_firewall.rs`.**

```rust
use anyhow::Result;
use async_trait::async_trait;
use aws_sdk_networkfirewall::Client as NfwClient;

use crate::evidence::CsvCollector;

pub struct NetworkFirewallCollector {
    client: NfwClient,
}

impl NetworkFirewallCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self {
            client: NfwClient::new(config),
        }
    }
}

#[async_trait]
impl CsvCollector for NetworkFirewallCollector {
    fn name(&self) -> &str {
        "AWS Network Firewall"
    }
    fn filename_prefix(&self) -> &str {
        "NetworkFirewall_Config"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Firewall Name",
            "Firewall ARN",
            "VPC ID",
            "Subnet IDs",
            "Policy ARN",
            "Policy Name",
            "Stateless Default Actions",
            "Stateless Fragment Actions",
            "Stateful Rule Groups",
            "Delete Protection",
            "Subnet Change Protection",
            "Policy Change Protection",
            "Logging Flow Dest",
            "Logging Alert Dest",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let mut rows = Vec::new();
        let mut next_token: Option<String> = None;

        loop {
            let mut req = self.client.list_firewalls();
            if let Some(ref t) = next_token {
                req = req.next_token(t);
            }
            let resp = match req.send().await {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("  WARN: network-firewall list_firewalls: {e:#}");
                    break;
                }
            };

            for meta in resp.firewalls() {
                let name = meta.firewall_name().unwrap_or("").to_string();
                let arn = meta.firewall_arn().unwrap_or("").to_string();

                let fw_resp = match self
                    .client
                    .describe_firewall()
                    .firewall_arn(&arn)
                    .send()
                    .await
                {
                    Ok(r) => r,
                    Err(e) => {
                        eprintln!("  WARN: network-firewall describe_firewall({arn}): {e:#}");
                        continue;
                    }
                };

                let (vpc_id, subnets, policy_arn, delete_p, subnet_p, policy_p) =
                    match fw_resp.firewall() {
                        Some(f) => (
                            f.vpc_id().unwrap_or("").to_string(),
                            f.subnet_mappings()
                                .iter()
                                .map(|s| s.subnet_id().unwrap_or("").to_string())
                                .collect::<Vec<_>>()
                                .join(", "),
                            f.firewall_policy_arn().unwrap_or("").to_string(),
                            f.delete_protection().to_string(),
                            f.subnet_change_protection().to_string(),
                            f.firewall_policy_change_protection().to_string(),
                        ),
                        None => (
                            String::new(),
                            String::new(),
                            String::new(),
                            String::new(),
                            String::new(),
                            String::new(),
                        ),
                    };

                let (policy_name, stateless_def, stateless_frag, stateful_rgs) = if policy_arn
                    .is_empty()
                {
                    (String::new(), String::new(), String::new(), String::new())
                } else {
                    match self
                        .client
                        .describe_firewall_policy()
                        .firewall_policy_arn(&policy_arn)
                        .send()
                        .await
                    {
                        Ok(p) => {
                            let pname = p
                                .firewall_policy_response()
                                .and_then(|r| r.firewall_policy_name())
                                .unwrap_or("")
                                .to_string();
                            match p.firewall_policy() {
                                Some(fp) => (
                                    pname,
                                    fp.stateless_default_actions().join(", "),
                                    fp.stateless_fragment_default_actions().join(", "),
                                    fp.stateful_rule_group_references()
                                        .iter()
                                        .map(|r| r.resource_arn().unwrap_or("").to_string())
                                        .collect::<Vec<_>>()
                                        .join(", "),
                                ),
                                None => (pname, String::new(), String::new(), String::new()),
                            }
                        }
                        Err(e) => {
                            eprintln!(
                                "  WARN: network-firewall describe_firewall_policy({policy_arn}): {e:#}"
                            );
                            (String::new(), String::new(), String::new(), String::new())
                        }
                    }
                };

                let (flow_dest, alert_dest) = match self
                    .client
                    .describe_logging_configuration()
                    .firewall_arn(&arn)
                    .send()
                    .await
                {
                    Ok(l) => {
                        let configs = l
                            .logging_configuration()
                            .map(|c| c.log_destination_configs())
                            .unwrap_or(&[]);
                        let mut flow = Vec::new();
                        let mut alert = Vec::new();
                        for c in configs {
                            let label = match c.log_type() {
                                Some(t) => t.as_str().to_string(),
                                None => continue,
                            };
                            let dest_type = c
                                .log_destination_type()
                                .map(|d| d.as_str().to_string())
                                .unwrap_or_default();
                            let dest_summary = c
                                .log_destination()
                                .values()
                                .cloned()
                                .collect::<Vec<_>>()
                                .join("|");
                            let entry = format!("{dest_type}:{dest_summary}");
                            match label.as_str() {
                                "FLOW" => flow.push(entry),
                                "ALERT" => alert.push(entry),
                                _ => {}
                            }
                        }
                        (flow.join(", "), alert.join(", "))
                    }
                    Err(e) => {
                        eprintln!(
                            "  WARN: network-firewall describe_logging_configuration({arn}): {e:#}"
                        );
                        (String::new(), String::new())
                    }
                };

                rows.push(vec![
                    name,
                    arn,
                    vpc_id,
                    subnets,
                    policy_arn,
                    policy_name,
                    stateless_def,
                    stateless_frag,
                    stateful_rgs,
                    delete_p,
                    subnet_p,
                    policy_p,
                    flow_dest,
                    alert_dest,
                ]);
            }

            next_token = resp.next_token().map(|s| s.to_string());
            if next_token.is_none() {
                break;
            }
        }

        Ok(rows)
    }
}
```

- [ ] **Step 2: Wire in `mod.rs`, `factory.rs`.**

`pub mod network_firewall;`

```rust
use crate::providers::aws::network_firewall::NetworkFirewallCollector;
```

```rust
if has("network-firewall") {
    v.push(Box::new(NetworkFirewallCollector::new(cfg)));
}
```

- [ ] **Step 3: Build.**

Run: `cargo check`
Expected: PASS. If `log_destination()` returns `Option<&HashMap<…>>`, unwrap or default appropriately — adjust closure inline.

- [ ] **Step 4: Commit.**

```bash
git add src/providers/aws/network_firewall.rs src/providers/aws/mod.rs src/providers/aws/factory.rs
git commit -m "feat(aws): add Network Firewall collector"
```

---

## Task 10: SSM Session Manager logs collector (R-1706, R-1708 / MA-4(a)(e))

**Files:**
- Create: `src/providers/aws/ssm_sessions.rs`
- Modify: `src/providers/aws/mod.rs`
- Modify: `src/providers/aws/factory.rs`

- [ ] **Step 1: Create `src/providers/aws/ssm_sessions.rs`.**

```rust
use anyhow::Result;
use async_trait::async_trait;
use aws_sdk_ssm::types::SessionState;
use aws_sdk_ssm::Client as SsmClient;

use crate::evidence::CsvCollector;

pub struct SsmSessionsCollector {
    client: SsmClient,
}

impl SsmSessionsCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self {
            client: SsmClient::new(config),
        }
    }

    async fn pull(&self, state: SessionState, rows: &mut Vec<Vec<String>>) {
        let mut next_token: Option<String> = None;
        loop {
            let mut req = self.client.describe_sessions().state(state.clone());
            if let Some(ref t) = next_token {
                req = req.next_token(t);
            }
            let resp = match req.send().await {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("  WARN: ssm describe_sessions({state:?}): {e:#}");
                    break;
                }
            };
            for s in resp.sessions() {
                rows.push(vec![
                    s.session_id().unwrap_or("").to_string(),
                    s.target().unwrap_or("").to_string(),
                    s.owner().unwrap_or("").to_string(),
                    s.document_name().unwrap_or("").to_string(),
                    s.start_date().map(|d| d.to_string()).unwrap_or_default(),
                    s.end_date().map(|d| d.to_string()).unwrap_or_default(),
                    s.status().map(|st| st.as_str().to_string()).unwrap_or_default(),
                    s.reason().unwrap_or("").to_string(),
                    s.details().unwrap_or("").to_string(),
                ]);
            }
            next_token = resp.next_token().map(|s| s.to_string());
            if next_token.is_none() {
                break;
            }
        }
    }
}

#[async_trait]
impl CsvCollector for SsmSessionsCollector {
    fn name(&self) -> &str {
        "SSM Session Manager Logs"
    }
    fn filename_prefix(&self) -> &str {
        "SSM_Sessions"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Session ID",
            "Target",
            "Owner",
            "Document",
            "Start",
            "End",
            "Status",
            "Reason",
            "Details",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let mut rows = Vec::new();
        self.pull(SessionState::History, &mut rows).await;
        self.pull(SessionState::Active, &mut rows).await;

        // SSM-SessionManagerRunShell preferences (logging, KMS, etc.) — single document, top of list.
        match self
            .client
            .describe_document()
            .name("SSM-SessionManagerRunShell")
            .send()
            .await
        {
            Ok(d) => {
                if let Some(doc) = d.document() {
                    rows.push(vec![
                        "DOCUMENT".into(),
                        doc.name().unwrap_or("").to_string(),
                        doc.owner().unwrap_or("").to_string(),
                        doc.document_version().unwrap_or("").to_string(),
                        doc.created_date().map(|d| d.to_string()).unwrap_or_default(),
                        String::new(),
                        doc.status()
                            .map(|s| s.as_str().to_string())
                            .unwrap_or_default(),
                        String::new(),
                        doc.description().unwrap_or("").to_string(),
                    ]);
                }
            }
            Err(e) => {
                eprintln!("  WARN: ssm describe_document(SSM-SessionManagerRunShell): {e:#}");
            }
        }

        Ok(rows)
    }
}
```

- [ ] **Step 2: Wire in `mod.rs`, `factory.rs`.**

`pub mod ssm_sessions;`

```rust
use crate::providers::aws::ssm_sessions::SsmSessionsCollector;
```

```rust
if has("ssm-sessions") {
    v.push(Box::new(SsmSessionsCollector::new(cfg)));
}
```

- [ ] **Step 3: Build.**

Run: `cargo check`
Expected: PASS. If `SessionState` is non-`Clone`, replace with `.state(SessionState::History)` and `.state(SessionState::Active)` inline (don't pass through a function).

- [ ] **Step 4: Commit.**

```bash
git add src/providers/aws/ssm_sessions.rs src/providers/aws/mod.rs src/providers/aws/factory.rs
git commit -m "feat(aws): add SSM Session Manager logs collector"
```

---

## Task 11: Tenable scanner permissions API (R-1095 / RA-5(5))

**Files:**
- Create: `crates/tenable-rs/src/api/users.rs`
- Modify: `crates/tenable-rs/src/api/mod.rs`

The tenable-rs client exposes `pub(crate) async fn get(&self, path: &str) -> Result<reqwest::Response, TenableError>` (see `crates/tenable-rs/src/client.rs:149`). Use it.

- [ ] **Step 1: Create `crates/tenable-rs/src/api/users.rs`.**

```rust
use serde::Deserialize;

use crate::client::TenableClient;
use crate::error::TenableError;

#[derive(Debug, Clone, Deserialize)]
pub struct TenableUser {
    #[serde(default)]
    pub id: u64,
    #[serde(default)]
    pub uuid: Option<String>,
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub permissions: u32,
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default)]
    pub last_login_attempt: Option<u64>,
    #[serde(default)]
    pub login_fail_count: Option<u32>,
    #[serde(default)]
    pub type_: Option<String>,
}

#[derive(Debug, Deserialize)]
struct UsersResponse {
    #[serde(default)]
    users: Vec<TenableUser>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ScannerPermission {
    #[serde(default)]
    pub id: Option<u64>,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub r#type: Option<String>,
    #[serde(default)]
    pub permissions: Option<u32>,
}

pub struct UsersApi<'c>(pub(crate) &'c TenableClient);

impl<'c> UsersApi<'c> {
    /// GET /users — returns all Tenable users with their permission levels.
    pub async fn list(&self) -> Result<Vec<TenableUser>, TenableError> {
        let resp = self.0.get("/users").await?;
        let body: UsersResponse = resp.json().await?;
        Ok(body.users)
    }

    /// GET /permissions/{object_type}/{object_id} — scanner ACL.
    /// `object_type` is typically "scanner".
    pub async fn permissions(
        &self,
        object_type: &str,
        object_id: u64,
    ) -> Result<Vec<ScannerPermission>, TenableError> {
        let path = format!("/permissions/{object_type}/{object_id}");
        let resp = self.0.get(&path).await?;
        let body: Vec<ScannerPermission> = resp.json().await?;
        Ok(body)
    }
}
```

- [ ] **Step 2: Update `crates/tenable-rs/src/api/mod.rs`.**

Add to the `pub mod` list:

```rust
pub mod users;
```

Add the re-export:

```rust
pub use users::UsersApi;
```

- [ ] **Step 3: Expose the API on `TenableClient`.**

Find the impl block in `crates/tenable-rs/src/client.rs` that already exposes `assets()`, `vulns()`, etc. (search for `pub fn assets`). Add:

```rust
pub fn users(&self) -> crate::api::UsersApi<'_> {
    crate::api::UsersApi(self)
}
```

If the existing methods use a different visibility/wrapping pattern, mirror it exactly.

- [ ] **Step 4: Verify the crate builds.**

Run: `cargo check -p tenable-rs` (or just `cargo check`).
Expected: PASS.

- [ ] **Step 5: Verify `TenableError` covers `reqwest::Error` from `.json()`.**

If `TenableError` doesn't already have a `From<reqwest::Error>` impl, the `?` operators in this file will fail. Check `crates/tenable-rs/src/error.rs`; if needed, fall back to:

```rust
let body: UsersResponse = resp
    .json()
    .await
    .map_err(|e| TenableError::Http(e.to_string()))?;
```

(use whatever variant exists, e.g. `TenableError::Decode(e)`).

- [ ] **Step 6: Commit.**

```bash
git add crates/tenable-rs/src/api/users.rs crates/tenable-rs/src/api/mod.rs crates/tenable-rs/src/client.rs
git commit -m "feat(tenable): add users + scanner permissions API"
```

---

## Task 12: Final integration — workspace build, clippy, smoke run

**Files:** none (verification only).

- [ ] **Step 1: Full workspace build.**

Run: `cargo build --release`
Expected: PASS, no errors.

- [ ] **Step 2: Clippy.**

Run: `cargo clippy --all-targets -- -D warnings`
Expected: PASS. Fix any newly-introduced warnings in the files modified above. Do NOT touch unrelated pre-existing warnings.

- [ ] **Step 3: Confirm new collector keys are recognized.**

If the project enforces a known-keys allowlist (search `factory.rs` for "unknown collector" or a constant list of names), add the new keys: `client-vpn`, `acm-pca`, `ssm-software-inventory`, `shield`, `license-manager`, `service-quotas`, `route53-dnssec`, `network-firewall`, `ssm-sessions`. If no allowlist exists, skip.

```bash
grep -n "unknown\|known_collectors\|valid.*collectors" src/providers/aws/factory.rs src/runner/*.rs src/config*.rs 2>/dev/null
```

- [ ] **Step 4: Update `config.example.toml` with a comment listing new opt-out keys.**

Append at the end of the `disable = [...]` example block (or in a comment header above `[defaults.collectors]`):

```toml
# Newly added collectors (enabled by default; add to `disable` to skip):
#   client-vpn, acm-pca, ssm-software-inventory, shield, license-manager,
#   service-quotas, route53-dnssec, network-firewall, ssm-sessions
```

- [ ] **Step 5: Smoke test with a single region.**

Run (replace profile with one the user has locally):

```bash
cargo run --release -- --profile corp:SecurityAdmin-957407513219 --region us-east-1 2>&1 | tail -60
```

Expected: process exits 0; new collectors appear in the run log as `AWS Client VPN`, `ACM Private CA`, `SSM Software Inventory`, `AWS Shield`, `License Manager`, `Service Quotas`, `Route53 DNSSEC`, `AWS Network Firewall`, `SSM Session Manager Logs`. Each writes a CSV under `./evidence-output/...`.

If a service isn't enabled in the test account, expect a `WARN:` line — not a process failure. That's the intended behavior.

- [ ] **Step 6: Final commit (only if changes were needed in steps 3-4).**

```bash
git add -A
git commit -m "chore(aws): wire new collector keys into config example + allowlist"
```

---

## Self-Review Notes

- **Spec coverage:** Items 1–10 from the input table are each owned by Tasks 2–11 in order. Task 1 (deps), Task 12 (final integration) bracket them. ✓
- **Placeholder scan:** All code blocks contain full Rust. Error handling pattern matches `route53_config.rs` (anyhow `?` for the top-level paginator, `eprintln!("  WARN: …")` for per-item secondary calls). ✓
- **Type consistency:** Every collector uses `pub fn new(config: &aws_config::SdkConfig)` and `collect_rows(&self, _account_id: &str, _region: &str, _dates: Option<(i64, i64)>)` matching `CsvCollector`. ✓
- **SDK version drift:** AWS SDK v1 minor versions occasionally rename getter return types (Option<&str> vs &str). Each task notes the fallback. If the user is on a recent (≥1.40) `aws-sdk-ec2`, methods like `subnet_mappings()` and `dns_servers()` already return slices — no `.unwrap_or_default()` needed; if older, add it.

---

**Plan complete and saved to `docs/superpowers/plans/2026-06-10-aws-tenable-collectors-batch.md`. Two execution options:**

**1. Subagent-Driven (recommended)** — I dispatch a fresh subagent per task, review between tasks, fast iteration.

**2. Inline Execution** — Execute tasks in this session using executing-plans, batch execution with checkpoints.

**Which approach?**
