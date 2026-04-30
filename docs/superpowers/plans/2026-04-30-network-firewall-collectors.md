# Network Firewall Collectors Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add three `CsvCollector` implementations for AWS Network Firewall (firewall instances, policies, and rule groups) to feed FedRAMP SC-5/SC-7 evidence into the existing inventory pipeline.

**Architecture:** Follows the vpc.rs / waf.rs two-phase pattern — paginate a list API to get ARNs, then describe each resource for full detail. All three collectors live in a new `src/network_firewall.rs` file sharing one `NfwClient`. They register via the `wants()` dispatch in `main.rs` under keys `"nfw"`, `"nfw-policy"`, and `"nfw-rule-groups"`.

**Tech Stack:** Rust, `aws-sdk-networkfirewall = "1"`, `async_trait`, `anyhow`

**FedRAMP mapping:** SC-5 (DoS protection — firewall instances guard VPC boundaries), SC-7 (boundary protection — policies + rule groups define stateful/stateless traffic controls).

---

## File Structure

| Action | Path | Responsibility |
|--------|------|----------------|
| Create | `src/network_firewall.rs` | Three `CsvCollector` structs: `NetworkFirewallCollector`, `NetworkFirewallPolicyCollector`, `NetworkFirewallRuleGroupCollector` |
| Modify | `Cargo.toml` | Add `aws-sdk-networkfirewall = "1"` |
| Modify | `src/main.rs` | Add `mod network_firewall;`, three `use` imports, three `if wants(...)` blocks |

---

## Task 1: Add the AWS SDK dependency

**Files:**
- Modify: `Cargo.toml` (after `aws-sdk-wafv2 = "1"` line, around line 19)

- [ ] **Step 1: Add the crate**

Open `Cargo.toml` and add after the `aws-sdk-wafv2 = "1"` line:

```toml
aws-sdk-networkfirewall = "1"
```

- [ ] **Step 2: Verify dependency resolves**

```bash
cd /Users/austin-songer/code/grabber
cargo fetch 2>&1 | tail -5
```

Expected: no errors, crate appears in `~/.cargo/registry`.

- [ ] **Step 3: Commit**

```bash
git add Cargo.toml Cargo.lock
git commit -m "chore(deps): add aws-sdk-networkfirewall crate"
```

---

## Task 2: Implement `NetworkFirewallCollector` (firewall instances)

**Files:**
- Create: `src/network_firewall.rs`

Collects one row per firewall: name, ARN, VPC, subnets, attached policy, status, and delete-protection flag. Two-phase: `list_firewalls` → `describe_firewall` for each ARN.

- [ ] **Step 1: Create `src/network_firewall.rs` with the firewall collector**

```rust
use anyhow::{Context, Result};
use async_trait::async_trait;
use aws_sdk_networkfirewall::Client as NfwClient;

use crate::evidence::CsvCollector;

// ---------------------------------------------------------------------------
// Network Firewall — Firewall Instances
// ---------------------------------------------------------------------------

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
        "Network Firewalls"
    }
    fn filename_prefix(&self) -> &str {
        "Network_Firewalls"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Firewall Name",
            "Firewall ARN",
            "VPC ID",
            "Subnets",
            "Policy ARN",
            "Status",
            "Delete Protection",
            "Region",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let mut rows = Vec::new();
        let mut next_token: Option<String> = None;
        let mut firewall_arns: Vec<String> = Vec::new();

        loop {
            let mut req = self.client.list_firewalls();
            if let Some(ref t) = next_token {
                req = req.next_token(t);
            }
            let resp = req.send().await.context("nfw list_firewalls")?;
            for fw in resp.firewalls() {
                if let Some(arn) = fw.firewall_arn() {
                    firewall_arns.push(arn.to_string());
                }
            }
            next_token = resp.next_token().map(|s| s.to_string());
            if next_token.is_none() {
                break;
            }
        }

        for arn in &firewall_arns {
            let resp = match self
                .client
                .describe_firewall()
                .firewall_arn(arn)
                .send()
                .await
            {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("  WARN: nfw describe_firewall {arn}: {e:#}");
                    continue;
                }
            };

            let fw = match resp.firewall() {
                Some(f) => f,
                None => continue,
            };

            let name = fw.firewall_name().unwrap_or("").to_string();
            let fw_arn = fw.firewall_arn().unwrap_or("").to_string();
            let vpc_id = fw.vpc_id().unwrap_or("").to_string();
            let subnets: Vec<&str> = fw
                .subnet_mappings()
                .iter()
                .map(|s| s.subnet_id())
                .collect();
            let subnets_str = subnets.join(", ");
            let policy_arn = fw.firewall_policy_arn().unwrap_or("").to_string();
            let status = resp
                .firewall_status()
                .and_then(|s| s.status())
                .map(|s| s.as_str().to_string())
                .unwrap_or_default();
            let delete_protection = if fw.delete_protection() { "Yes" } else { "No" }.to_string();

            rows.push(vec![
                name,
                fw_arn,
                vpc_id,
                subnets_str,
                policy_arn,
                status,
                delete_protection,
                region.to_string(),
            ]);
        }

        Ok(rows)
    }
}
```

- [ ] **Step 2: Verify it compiles (file only, no registration yet)**

```bash
cd /Users/austin-songer/code/grabber
cargo check 2>&1 | grep -E "error|warning: unused" | head -20
```

Expected: errors about `dead_code` (module not declared yet) but no type errors from the collector itself. If there are type errors, check `.unwrap_or("")` vs `.to_string()` on non-Option fields (some SDK fields in v1 return `&str` directly — remove `.unwrap_or("")` if the compiler says "expected `&str`, found `Option<&str>`").

---

## Task 3: Add `NetworkFirewallPolicyCollector` to `network_firewall.rs`

**Files:**
- Modify: `src/network_firewall.rs`

Collects one row per firewall policy: name, ARN, stateless/stateful rule group references (formatted as `priority:arn` and `arn` respectively), and default actions.

- [ ] **Step 1: Append the policy collector to `src/network_firewall.rs`**

```rust
// ---------------------------------------------------------------------------
// Network Firewall — Firewall Policies
// ---------------------------------------------------------------------------

pub struct NetworkFirewallPolicyCollector {
    client: NfwClient,
}

impl NetworkFirewallPolicyCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self {
            client: NfwClient::new(config),
        }
    }
}

#[async_trait]
impl CsvCollector for NetworkFirewallPolicyCollector {
    fn name(&self) -> &str {
        "Network Firewall Policies"
    }
    fn filename_prefix(&self) -> &str {
        "Network_Firewall_Policies"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Policy Name",
            "Policy ARN",
            "Stateless Rule Groups",
            "Stateful Rule Groups",
            "Default Stateless Actions",
            "Fragment Default Actions",
            "Region",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let mut rows = Vec::new();
        let mut next_token: Option<String> = None;
        let mut policy_arns: Vec<String> = Vec::new();

        loop {
            let mut req = self.client.list_firewall_policies();
            if let Some(ref t) = next_token {
                req = req.next_token(t);
            }
            let resp = req.send().await.context("nfw list_firewall_policies")?;
            for p in resp.firewall_policies() {
                if let Some(arn) = p.arn() {
                    policy_arns.push(arn.to_string());
                }
            }
            next_token = resp.next_token().map(|s| s.to_string());
            if next_token.is_none() {
                break;
            }
        }

        for arn in &policy_arns {
            let resp = match self
                .client
                .describe_firewall_policy()
                .firewall_policy_arn(arn)
                .send()
                .await
            {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("  WARN: nfw describe_firewall_policy {arn}: {e:#}");
                    continue;
                }
            };

            let meta = resp.firewall_policy_response();
            let policy_name = meta.firewall_policy_name().to_string();
            let policy_arn = meta.firewall_policy_arn().to_string();

            let (stateless_rgs, stateful_rgs, default_actions, frag_actions) =
                match resp.firewall_policy() {
                    Some(fp) => {
                        let stateless: Vec<String> = fp
                            .stateless_rule_group_references()
                            .iter()
                            .map(|r| format!("{}:{}", r.priority(), r.resource_arn()))
                            .collect();
                        let stateful: Vec<String> = fp
                            .stateful_rule_group_references()
                            .iter()
                            .map(|r| r.resource_arn().to_string())
                            .collect();
                        let defaults = fp.stateless_default_actions().join(", ");
                        let frags = fp.stateless_fragment_default_actions().join(", ");
                        (stateless.join(" | "), stateful.join(" | "), defaults, frags)
                    }
                    None => (
                        String::new(),
                        String::new(),
                        String::new(),
                        String::new(),
                    ),
                };

            rows.push(vec![
                policy_name,
                policy_arn,
                stateless_rgs,
                stateful_rgs,
                default_actions,
                frag_actions,
                region.to_string(),
            ]);
        }

        Ok(rows)
    }
}
```

- [ ] **Step 2: Verify the file still compiles cleanly**

```bash
cargo check 2>&1 | grep "error" | head -20
```

Expected: no errors in `network_firewall.rs` (still unregistered module, so may warn about dead code).

---

## Task 4: Add `NetworkFirewallRuleGroupCollector` to `network_firewall.rs`

**Files:**
- Modify: `src/network_firewall.rs`

Collects one row per customer-managed rule group (both STATEFUL and STATELESS): name, ARN, type, capacity, status, description, and association count.

- [ ] **Step 1: Append the rule group collector to `src/network_firewall.rs`**

```rust
// ---------------------------------------------------------------------------
// Network Firewall — Rule Groups
// ---------------------------------------------------------------------------

pub struct NetworkFirewallRuleGroupCollector {
    client: NfwClient,
}

impl NetworkFirewallRuleGroupCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self {
            client: NfwClient::new(config),
        }
    }
}

#[async_trait]
impl CsvCollector for NetworkFirewallRuleGroupCollector {
    fn name(&self) -> &str {
        "Network Firewall Rule Groups"
    }
    fn filename_prefix(&self) -> &str {
        "Network_Firewall_Rule_Groups"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Rule Group Name",
            "Rule Group ARN",
            "Type",
            "Capacity",
            "Status",
            "Associations",
            "Description",
            "Region",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let mut rows = Vec::new();
        let mut next_token: Option<String> = None;
        let mut rg_arns: Vec<String> = Vec::new();

        loop {
            let mut req = self.client.list_rule_groups();
            if let Some(ref t) = next_token {
                req = req.next_token(t);
            }
            let resp = req.send().await.context("nfw list_rule_groups")?;
            for rg in resp.rule_groups() {
                if let Some(arn) = rg.arn() {
                    rg_arns.push(arn.to_string());
                }
            }
            next_token = resp.next_token().map(|s| s.to_string());
            if next_token.is_none() {
                break;
            }
        }

        for arn in &rg_arns {
            let resp = match self
                .client
                .describe_rule_group()
                .rule_group_arn(arn)
                .send()
                .await
            {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("  WARN: nfw describe_rule_group {arn}: {e:#}");
                    continue;
                }
            };

            let rg = resp.rule_group_response();
            let name = rg.rule_group_name().to_string();
            let rg_arn = rg.rule_group_arn().to_string();
            let rg_type = rg
                .type_()
                .map(|t| t.as_str().to_string())
                .unwrap_or_default();
            let capacity = rg
                .capacity()
                .map(|c| c.to_string())
                .unwrap_or_default();
            let status = rg
                .rule_group_status()
                .map(|s| s.as_str().to_string())
                .unwrap_or_default();
            let associations = rg
                .number_of_associations()
                .map(|n| n.to_string())
                .unwrap_or_default();
            let description = rg.description().unwrap_or("").to_string();

            rows.push(vec![
                name,
                rg_arn,
                rg_type,
                capacity,
                status,
                associations,
                description,
                region.to_string(),
            ]);
        }

        Ok(rows)
    }
}
```

- [ ] **Step 2: Verify file compiles**

```bash
cargo check 2>&1 | grep "error" | head -20
```

Expected: no errors from `network_firewall.rs`.

---

## Task 5: Register all three collectors in `main.rs`

**Files:**
- Modify: `src/main.rs`

Three changes: (1) declare the module, (2) import the three structs, (3) add `if wants(...)` blocks in the CSV collectors section.

- [ ] **Step 1: Add `mod network_firewall;` to the module list**

In `src/main.rs`, find the alphabetically-sorted `mod` block near the top (around lines 59-88). Add between `mod network_gateways;` and `mod org_config;`:

```rust
mod network_firewall;
```

- [ ] **Step 2: Add `use` imports**

Near line 216 where the networking `use` statements live (alongside `VpcCollector`, `WafCollector`, etc.), add:

```rust
use crate::network_firewall::{
    NetworkFirewallCollector, NetworkFirewallPolicyCollector, NetworkFirewallRuleGroupCollector,
};
```

- [ ] **Step 3: Add `if wants(...)` blocks in the CSV collectors section**

In the `// Network` section of `main.rs` (around line 1208, after `igw` and `nat-gateways` blocks), add three blocks:

```rust
    // Network Firewall (SC-5 / SC-7)
    if wants("nfw") {
        csv_collectors.push(Box::new(NetworkFirewallCollector::new(&config)));
    }
    if wants("nfw-policy") {
        csv_collectors.push(Box::new(NetworkFirewallPolicyCollector::new(&config)));
    }
    if wants("nfw-rule-groups") {
        csv_collectors.push(Box::new(NetworkFirewallRuleGroupCollector::new(&config)));
    }
```

- [ ] **Step 4: Full build to catch any remaining type errors**

```bash
cargo build 2>&1 | grep -E "^error" | head -30
```

Expected: clean build with no errors. If the compiler rejects `.unwrap_or("")` on a non-Option field (because some NFW SDK fields return `&str` not `Option<&str>`), remove the `.unwrap_or("")` and call `.to_string()` directly on `&str`.

- [ ] **Step 5: Commit**

```bash
git add src/network_firewall.rs src/main.rs Cargo.toml Cargo.lock
git commit -m "feat(network_firewall): add collectors for firewalls, policies, and rule groups (SC-5/SC-7)"
```

---

## Verification

### Build check (always)
```bash
cargo build
```

### Smoke test with `--collectors` filter (requires an AWS account with Network Firewall deployed)
```bash
# Run only the firewall collectors, skip others
cargo run -- --collectors nfw,nfw-policy,nfw-rule-groups

# Verify CSV files appear in the configured output_dir
ls -lh <output_dir>/*Network_Firewall*
```

### Full default run (no `--collectors` flag — all three collectors are included automatically)
```bash
cargo run
```

### If the account has no Network Firewall resources
Expected output per collector: `collected 0 rows` (or equivalent). No crash — empty rows are valid.

### IAM permissions needed
The executing role must have:
```json
{
  "Effect": "Allow",
  "Action": [
    "network-firewall:ListFirewalls",
    "network-firewall:DescribeFirewall",
    "network-firewall:ListFirewallPolicies",
    "network-firewall:DescribeFirewallPolicy",
    "network-firewall:ListRuleGroups",
    "network-firewall:DescribeRuleGroup"
  ],
  "Resource": "*"
}
```
