# Inventory Log Services Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add six log-service asset types — CloudWatch Logs log groups, CloudWatch Logs cross-account destinations, VPC Flow Logs, Route 53 Resolver query log configs, OpenSearch domains, and MSK clusters — to the AWS inventory feature.

**Architecture:** Each asset type follows the established inventory pattern exactly: a key constant + `INVENTORY_ITEMS` entry in `src/inventory_core.rs`, an `async fn collect_*` in a module under `src/inventory_orchestrator/`, an SDK client field + a `match` arm in `src/inventory_orchestrator/mod.rs`, and a `--<name>` boolean flag in `src/cli.rs` wired into `resolve_inventory_types`. Two new module files group the work by responsibility: `logging.rs` (log producers and log pipelines — CloudWatch Logs, VPC Flow Logs, Resolver query logs) and `log_analytics.rs` (log sinks that are themselves clusters — OpenSearch, MSK). No TUI code changes are needed: the wizard's inventory list is rendered from `INVENTORY_ITEMS` at `App::new()` time (`src/tui/app/mod.rs:411`), so a new entry appears automatically in the picker, the confirm screen, and the CLI validator.

**Tech Stack:** Rust 2021, `tokio`, `anyhow`, `async-trait`, `chrono`, AWS SDK for Rust (`aws-sdk-cloudwatchlogs`, `aws-sdk-ec2`, `aws-sdk-route53resolver` — all already dependencies; `aws-sdk-opensearch` and `aws-sdk-kafka` — added by this plan).

## Global Constraints

- **No new unit tests.** This project's standing preference is production code only when executing a plan, and the inventory subsystem has no existing test module to extend. Verification for every task is: `cargo fmt`, `cargo check`, the scoped clippy check below, and — where AWS credentials are available — one live `--inventory` smoke run. Do not write `#[cfg(test)]` blocks.
- **Clippy is scoped to the files you touch — do not chase the baseline.** `cargo clippy -- -D warnings` **already fails on `main`** with 48 pre-existing errors that have nothing to do with this plan (measured at `9ecfa14`), so "clippy is clean" is not an achievable gate and CLAUDE.md's blanket version of that rule does not currently hold. Two of those pre-existing lints live in files this plan touches and are **not yours to fix**:
  - `src/inventory_orchestrator/security_services.rs:374` — deprecated `aws_sdk_guardduty` `data_sources`
  - `src/inventory_core.rs:172` — `function tag_value is never used`

  The gate for every task is instead: **your changes introduce no new lint.** Check it with

  ```bash
  cargo clippy --quiet --message-format=short 2>&1 | grep -E "src/(inventory_core|cli)\.rs|src/inventory_orchestrator/"
  ```

  Expected output: exactly the two baseline lines above and nothing else. Any third line pointing into a file you edited is yours — fix it. Note that `pub fn` does **not** exempt an item from `dead_code` in this binary crate (that is why `tag_value` is flagged), so never add a helper in one task that is only called in a later one.
- **A `PostToolUse` hook runs `cargo check` after every file write.** Therefore: always create a child module file *before* adding its `mod` declaration to `src/inventory_orchestrator/mod.rs`. Writing `mod logging;` first leaves the tree uncompilable and the hook will fail.
- **Stay on whatever branch is currently checked out** (`main` as of this plan's execution). This project uses a trunk-based workflow: do not create a feature branch and do not open a worktree, even if a skill or convention suggests one.
- **Commits** are authored as `Austin Songer <asonger.pixel@gmail.com>`. No co-author trailers, no "Generated with" lines.
- **Errors:** `anyhow::Result` / `anyhow::Context` only. No `unwrap()` or `expect()` in production code. Attach `.context("<Service> <api_call>")` to the primary list/describe call so a failure names the API. Per-item secondary calls (tags, per-resource describes) **soft-fail**: `eprintln!` the error and substitute an empty value, never propagate — one AccessDenied on one resource must not lose the other rows.
- **Pagination:** use `.into_paginator().items().send().try_collect().await` where the operation has a paginator (verified present for `describe_log_groups`, `describe_destinations`, `describe_flow_logs`, `list_resolver_query_log_configs`, `list_resolver_query_log_config_associations`, `list_clusters_v2`). `opensearch::list_domain_names` is not paginated — a single `send()` is correct there.
- **Clients are constructed only in `InventoryCollector::new`** from the injected `&aws_config::SdkConfig`. Collector functions receive `&Client` references.
- **Rows are built with `RowBuilder`** and stay on the canonical 14-column schema. Never add a column.
- **`Comments` field key order is fixed** exactly as written in each task, so the CSV diffs cleanly between runs (mapping-spec convention #4).
- **`Virtual` is always `"Yes"`** for these cloud-managed resources, and `sw_vendor` is always `"Amazon Web Services"`.
- Imports grouped std → external crates → `crate::*`, blank line between groups.

## File Structure

| File | Change | Responsibility |
|---|---|---|
| `src/inventory_core.rs` | Modify | Six new `ASSET_KEY_*` constants + six `INVENTORY_ITEMS` entries; new shared `function_from_tag_map` helper. |
| `src/inventory_orchestrator/logging.rs` | Create | Collectors for `log-group`, `log-destination`, `vpc-flow-log`, `resolver-query-log`. |
| `src/inventory_orchestrator/log_analytics.rs` | Create | Collectors for `opensearch-domain`, `msk-cluster`. |
| `src/inventory_orchestrator/mod.rs` | Modify | Two `mod` declarations, six client fields, six `match` arms. |
| `src/inventory_orchestrator/network_fabric.rs` | Modify | Widen `ec2_arn` and `fabric_function` from private to `pub(super)` so `logging.rs` can reuse them. |
| `src/cli.rs` | Modify | Six `--<name>` flags + six `resolve_inventory_types` arms. |
| `Cargo.toml` | Modify | Add `aws-sdk-opensearch = "1"` and `aws-sdk-kafka = "1"`. |
| `evidence-list.md`, `docs/cli-reference.md`, `README.md` | Modify | Document the new asset types. |

## Field Mapping Spec (§25–§30)

Sections continue the numbering in `docs/superpowers/plans/2026-07-17-aws-inventory-expansion-mapping.md` (which ends at §24, WAF WebACL). Code comments in the new modules reference these numbers.

### §25 CloudWatch Logs Log Group
- **Key:** `log-group` · **Flag:** `--log-groups` · **SDK:** `aws-sdk-cloudwatchlogs` → `describe_log_groups` (paginated) + per-group `list_tags_for_resource` and `describe_subscription_filters`.

| Column | Value |
|---|---|
| unique_id | `log_group_arn` (the form **without** the trailing `:*`); fall back to `arn` with `:*` trimmed |
| public | Always `"No"` |
| location | `"<region>"` |
| asset_type | `"CloudWatch Logs Log Group"` |
| sw_name_ver | `"Amazon CloudWatch Logs"` |
| vlan_network_id | Empty |
| function | `Purpose`/`App`/`Role`/`Function` tag → else `log_group_name` |
| comments | `LogGroupName, RetentionInDays, StoredBytes, KmsKeyId, DataProtectionStatus, LogGroupClass, MetricFilterCount, SubscriptionFilters, CreationTime` |

`RetentionInDays` renders as `Never expire` when unset (that is what an absent retention means in CloudWatch Logs, and it is the AU-11 fact an auditor is looking for). `SubscriptionFilters` is a `; `-joined list of `<FilterName> -> <DestinationArn>`.

### §26 CloudWatch Logs Destination
- **Key:** `log-destination` · **Flag:** `--log-destinations` · **SDK:** `aws-sdk-cloudwatchlogs` → `describe_destinations` (paginated).

| Column | Value |
|---|---|
| unique_id | `arn` |
| public | Always `"No"` |
| location | `"<region>"` |
| asset_type | `"CloudWatch Logs Destination"` |
| sw_name_ver | `"Amazon CloudWatch Logs (cross-account destination)"` |
| vlan_network_id | Empty |
| function | `destination_name` (destinations carry no tags) |
| comments | `DestinationName, TargetArn, RoleArn, AccessPolicyPresent, CreationTime` |

`AccessPolicyPresent` is `true`/`false` — the policy body itself is not emitted, since it is a multi-line JSON document that would wreck the CSV and is already collected by the evidence-side CloudWatch collectors.

### §27 VPC Flow Log
- **Key:** `vpc-flow-log` · **Flag:** `--vpc-flow-logs` · **SDK:** `aws-sdk-ec2` → `describe_flow_logs` (paginated).

| Column | Value |
|---|---|
| unique_id | Synthesised: `arn:aws:ec2:<region>:<account>:vpc-flow-log/<flow_log_id>` (convention #1 — EC2 does not return an ARN for flow logs) |
| public | Always `"No"` |
| location | `"<region>"` |
| asset_type | `"VPC Flow Log"` |
| sw_name_ver | `"Amazon VPC Flow Logs"` |
| vlan_network_id | `"VPC: <resource_id>"` when `resource_id` starts with `vpc-`, else `"Resource: <resource_id>"` (flow logs also attach to subnets and ENIs) |
| function | `fabric_function(tags)` — Purpose/App/Role/Function tag → `Name` tag → empty |
| comments | `ResourceId, TrafficType, LogDestinationType, LogDestination, LogGroupName, FlowLogStatus, DeliverLogsStatus, DeliverLogsErrorMessage, MaxAggregationInterval, LogFormat, FileFormat, HiveCompatiblePartitions, PerHourPartition, DeliverLogsPermissionArn, CreationTime` |

### §28 Route 53 Resolver Query Log Config
- **Key:** `resolver-query-log` · **Flag:** `--resolver-query-logs` · **SDK:** `aws-sdk-route53resolver` → `list_resolver_query_log_configs` (paginated) + per-config `list_resolver_query_log_config_associations` (paginated, filtered).

| Column | Value |
|---|---|
| unique_id | `arn` |
| public | Always `"No"` |
| location | `"<region>"` |
| asset_type | `"Route 53 Resolver Query Log Config"` |
| sw_name_ver | `"Amazon Route 53 Resolver Query Logging"` |
| vlan_network_id | `", "`-joined associated VPC ids (the association `resource_id`s) |
| function | `name` |
| comments | `Name, Status, ShareStatus, OwnerId, DestinationArn, AssociationCount, AssociatedResources, CreationTime` |

Shared-in configs (`ShareStatus: SHARED_WITH_ME`) are kept — they are in force on this account's VPCs and are therefore in scope.

### §29 OpenSearch Domain
- **Key:** `opensearch-domain` · **Flag:** `--opensearch` · **SDK:** `aws-sdk-opensearch` → `list_domain_names` (unpaginated) + per-domain `describe_domain` and `list_tags`.

| Column | Value |
|---|---|
| unique_id | `arn` |
| public | `"Yes"` when `vpc_options` is absent (a public-access domain reachable from the internet), else `"No"` |
| dns_url | `endpoint`; when absent (VPC domains publish a map) the `vpc` entry of `endpoints` |
| location | `"<region>"` |
| asset_type | `"OpenSearch Domain"` |
| hw_make_model | `"AWS OpenSearch <instance_type> x<instance_count>"` |
| sw_name_ver | `engine_version` (already formatted `OpenSearch_2.11` / `Elasticsearch_7.10`), else `"Amazon OpenSearch Service"` |
| vlan_network_id | `"VPC: <vpc_id>, Subnets: <ids>"`, else empty |
| function | `Purpose`/`App`/`Role`/`Function` tag → else `domain_name` |
| comments | `DomainId, EngineVersion, InstanceType, InstanceCount, DedicatedMasterEnabled, ZoneAwarenessEnabled, EbsEnabled, EbsVolumeType, EbsVolumeSize, EncryptionAtRest, EncryptionAtRestKmsKeyId, NodeToNodeEncryption, EnforceHTTPS, TLSSecurityPolicy, AdvancedSecurityEnabled, LogPublishing, SecurityGroupIds, Processing` |

`LogPublishing` is a `; `-joined list of `<LogType>=<enabled>` — the AU-2/AU-12 fact for a domain that is itself a log sink.

### §30 MSK Cluster
- **Key:** `msk-cluster` · **Flag:** `--msk` · **SDK:** `aws-sdk-kafka` → `list_clusters_v2` (paginated). One row per cluster, provisioned and serverless alike.

| Column | Value |
|---|---|
| unique_id | `cluster_arn` |
| public | `"Yes"` when provisioned `broker_node_group_info.connectivity_info.public_access.type == "SERVICE_PROVIDED_EIPS"`, else `"No"` |
| location | `"<region>"` |
| asset_type | `"MSK Cluster"` |
| hw_make_model | `"AWS MSK <instance_type> x<number_of_broker_nodes>"` for provisioned; `"AWS MSK Serverless"` for serverless |
| sw_name_ver | `"Apache Kafka <kafka_version>"`, else `"Amazon MSK"` |
| vlan_network_id | `"Subnets: <client_subnets>"` (provisioned) or `"Subnets: <vpc_configs subnet ids>"` (serverless) |
| function | `Purpose`/`App`/`Role`/`Function` tag → else `cluster_name` |
| comments | `ClusterName, ClusterType, State, KafkaVersion, NumberOfBrokerNodes, StorageMode, EncryptionAtRestKmsKeyId, EncryptionInTransitClientBroker, EncryptionInClusterEnabled, ClientAuthentication, EnhancedMonitoring, BrokerLogs, SecurityGroups, CreationTime` |

`ClientAuthentication` is a `; `-joined list drawn from `SASL/IAM`, `SASL/SCRAM`, `TLS`, `Unauthenticated` (only the enabled ones). `BrokerLogs` is a `; `-joined list of the enabled destinations: `CloudWatch: <log group>`, `Firehose: <stream>`, `S3: <bucket>/<prefix>`.

---

### Task 1: Shared tag helper + CloudWatch Logs Log Group (`log-group`)

**Files:**
- Modify: `src/inventory_core.rs` (add `ASSET_KEY_LOG_GROUP`, an `INVENTORY_ITEMS` entry, and `function_from_tag_map`)
- Create: `src/inventory_orchestrator/logging.rs`
- Modify: `src/inventory_orchestrator/mod.rs`
- Modify: `src/cli.rs`

**Interfaces:**
- Consumes: `crate::inventory_core::RowBuilder` (existing).
- Produces:
  - `pub fn crate::inventory_core::function_from_tag_map(tags: &std::collections::HashMap<String, String>) -> String` — used again in Task 6.
  - `pub const crate::inventory_core::ASSET_KEY_LOG_GROUP: &str = "log-group"`.
  - `pub(super) async fn logging::collect_log_groups(c: &aws_sdk_cloudwatchlogs::Client, region: &str) -> anyhow::Result<Vec<Vec<String>>>`.
  - `pub(super) fn logging::millis_to_rfc3339(millis: Option<i64>) -> String` — used again in Task 2.
  - The `logging` module itself, declared in `mod.rs` — Tasks 2, 3, and 4 add functions to it.

- [ ] **Step 1: Add the shared tag-map helper to `src/inventory_core.rs`**

Append after `tag_value` (which ends at line 176, immediately before the `normalize_s3_region` doc comment):

```rust
/// Tag-first `Function`-column derivation for services whose tags come back as
/// a `HashMap<String, String>` (CloudWatch Logs, MSK) rather than the
/// `Vec<Tag>` shape the other collectors see. Same key precedence as the
/// `Vec<Tag>` helpers: Purpose → App → Role → Function, each in Titlecase then
/// lowercase.
pub fn function_from_tag_map(tags: &std::collections::HashMap<String, String>) -> String {
    for key in [
        "Purpose", "App", "Role", "Function", "purpose", "app", "role",
    ] {
        match tags.get(key) {
            Some(v) if !v.is_empty() => return v.clone(),
            _ => {}
        }
    }
    String::new()
}
```

The `match` guard rather than nested `if let` + `if` is deliberate — the nested form trips `clippy::collapsible_if`, and this crate builds with `-D warnings`.

- [ ] **Step 2: Add the asset key constant and `INVENTORY_ITEMS` entry**

In `src/inventory_core.rs`, add after `ASSET_KEY_WAF_WEBACL` (line 50):

```rust
pub const ASSET_KEY_LOG_GROUP: &str = "log-group";
```

and add as the last entry of `INVENTORY_ITEMS`, after `(ASSET_KEY_WAF_WEBACL, "WAF WebACL"),`:

```rust
    (ASSET_KEY_LOG_GROUP, "CloudWatch Logs Log Group"),
```

- [ ] **Step 3: Create `src/inventory_orchestrator/logging.rs`**

This is the whole file for this task. Tasks 2–4 append to it.

```rust
use std::collections::HashMap;

use anyhow::{Context, Result};
use aws_sdk_cloudwatchlogs::Client as CloudWatchLogsClient;

use crate::inventory_core::{function_from_tag_map, RowBuilder};

// ---------------------------------------------------------------------------
// Logging services — mapping doc §25 (CloudWatch Logs Log Group), §26
// (CloudWatch Logs Destination), §27 (VPC Flow Log), §28 (Route 53 Resolver
// Query Log Config).
//
// These are the log *producers* and log *pipelines*. Log sinks that are
// themselves clusters (OpenSearch, MSK) live in log_analytics.rs.
// ---------------------------------------------------------------------------

/// Beyond this many log groups in a single region, the two per-group
/// enrichment calls (`list_tags_for_resource` + `describe_subscription_filters`)
/// are skipped. Every log group still gets a row — only the tag-derived
/// `Function` value and the `SubscriptionFilters` comment go empty, and the
/// skip is reported on stderr rather than passing silently. Accounts that use
/// Lambda heavily routinely carry thousands of auto-created log groups; two
/// extra serial API calls each would dominate the inventory run and invite
/// CloudWatch Logs throttling.
const LOG_GROUP_ENRICH_LIMIT: usize = 500;

/// CloudWatch Logs reports timestamps as epoch **milliseconds**, unlike the
/// SDK `DateTime` values the other inventory collectors see.
pub(super) fn millis_to_rfc3339(millis: Option<i64>) -> String {
    millis
        .and_then(chrono::DateTime::<chrono::Utc>::from_timestamp_millis)
        .map(|d| d.to_rfc3339())
        .unwrap_or_default()
}

/// Soft-failing tag lookup. Note the resource ARN must be the form *without*
/// the trailing `:*` — the tagging APIs reject the `:*` variant.
async fn log_group_tags(c: &CloudWatchLogsClient, arn: &str) -> HashMap<String, String> {
    match c.list_tags_for_resource().resource_arn(arn).send().await {
        Ok(r) => r.tags().cloned().unwrap_or_default(),
        Err(e) => {
            eprintln!("cloudwatchlogs list_tags_for_resource failed for {arn}: {e}");
            HashMap::new()
        }
    }
}

/// Soft-failing `<FilterName> -> <DestinationArn>` summary for one log group.
/// This is the log-forwarding fact auditors ask for (AU-6): where does this log
/// group's data go. There is no bulk API — it is one call per log group.
async fn log_group_subscriptions(c: &CloudWatchLogsClient, log_group_name: &str) -> String {
    match c
        .describe_subscription_filters()
        .log_group_name(log_group_name)
        .send()
        .await
    {
        Ok(r) => r
            .subscription_filters()
            .iter()
            .map(|f| {
                format!(
                    "{} -> {}",
                    f.filter_name().unwrap_or(""),
                    f.destination_arn().unwrap_or("")
                )
            })
            .collect::<Vec<_>>()
            .join("; "),
        Err(e) => {
            eprintln!(
                "cloudwatchlogs describe_subscription_filters failed for {log_group_name}: {e}"
            );
            String::new()
        }
    }
}

pub(super) async fn collect_log_groups(
    c: &CloudWatchLogsClient,
    region: &str,
) -> Result<Vec<Vec<String>>> {
    let groups = c
        .describe_log_groups()
        .into_paginator()
        .items()
        .send()
        .try_collect()
        .await
        .context("CloudWatch Logs describe_log_groups")?;

    let enrich_count = groups.len().min(LOG_GROUP_ENRICH_LIMIT);
    if groups.len() > LOG_GROUP_ENRICH_LIMIT {
        eprintln!(
            "    [inventory] log-group: {} log groups in {region}; tag and \
             subscription-filter enrichment applied to the first {LOG_GROUP_ENRICH_LIMIT} only",
            groups.len()
        );
    }

    let mut rows = Vec::with_capacity(groups.len());
    for (idx, group) in groups.iter().enumerate() {
        let Some(name) = group.log_group_name() else {
            continue;
        };

        // `arn()` carries a trailing ":*"; `log_group_arn()` is the same ARN
        // without it. The tagging APIs only accept the ":*"-free form, so use
        // it for both the unique id and the tag lookup. Older API responses
        // may omit log_group_arn entirely — trim arn() in that case.
        let arn = match group.log_group_arn() {
            Some(a) => a.to_string(),
            None => group
                .arn()
                .unwrap_or_default()
                .trim_end_matches(":*")
                .to_string(),
        };
        if arn.is_empty() {
            continue;
        }

        let retention = group
            .retention_in_days()
            .map(|d| d.to_string())
            .unwrap_or_else(|| "Never expire".to_string());
        let stored_bytes = group.stored_bytes().unwrap_or_default().to_string();
        let kms_key_id = group.kms_key_id().unwrap_or("").to_string();
        let data_protection = group
            .data_protection_status()
            .map(|s| s.as_str().to_string())
            .unwrap_or_default();
        let log_group_class = group
            .log_group_class()
            .map(|c| c.as_str().to_string())
            .unwrap_or_default();
        let metric_filter_count = group.metric_filter_count().unwrap_or_default().to_string();
        let creation_time = millis_to_rfc3339(group.creation_time());

        let (tags, subscription_filters) = if idx < enrich_count {
            (
                log_group_tags(c, &arn).await,
                log_group_subscriptions(c, name).await,
            )
        } else {
            (HashMap::new(), String::new())
        };

        let function = {
            let tag_function = function_from_tag_map(&tags);
            if tag_function.is_empty() {
                name.to_string()
            } else {
                tag_function
            }
        };

        let comments = format!(
            "LogGroupName: {name} | RetentionInDays: {retention} | \
             StoredBytes: {stored_bytes} | KmsKeyId: {kms_key_id} | \
             DataProtectionStatus: {data_protection} | LogGroupClass: {log_group_class} | \
             MetricFilterCount: {metric_filter_count} | \
             SubscriptionFilters: {subscription_filters} | CreationTime: {creation_time}"
        );

        rows.push(
            RowBuilder::new()
                .unique_id(&arn)
                .virtual_flag("Yes")
                .public("No")
                .location(region)
                .asset_type("CloudWatch Logs Log Group")
                .sw_vendor("Amazon Web Services")
                .sw_name_ver("Amazon CloudWatch Logs")
                .function(function)
                .comments(comments)
                .build(),
        );
    }

    Ok(rows)
}
```

- [ ] **Step 4: Declare the module and wire the collector in `src/inventory_orchestrator/mod.rs`**

Four edits. Do them in one write so the hook's `cargo check` sees a consistent file.

1. Module declaration — add `mod logging;` to the `mod` block (lines 9–16), keeping alphabetical order. Do **not** declare `mod log_analytics;` yet; that file is created in Task 5 and declaring it early leaves the tree uncompilable:

```rust
mod data_services;
mod logging;
mod messaging;
```

2. SDK client import — add to the `use aws_sdk_*` block, alphabetically after `aws_sdk_config`:

```rust
use aws_sdk_cloudwatchlogs::Client as CloudWatchLogsClient;
```

3. Struct field + constructor line. Add to `InventoryCollector` after `config_svc: ConfigClient,`:

```rust
    cwlogs: CloudWatchLogsClient,
```

and in `InventoryCollector::new` after `config_svc: ConfigClient::new(config),`:

```rust
            cwlogs: CloudWatchLogsClient::new(config),
```

4. Key import + match arm. Add `ASSET_KEY_LOG_GROUP` to the `crate::inventory_core::{...}` import list, and add this arm immediately before the `other =>` fallback arm:

```rust
                ASSET_KEY_LOG_GROUP => logging::collect_log_groups(&self.cwlogs, &region).await,
```

- [ ] **Step 5: Add the CLI flag in `src/cli.rs`**

After the `inv_waf` field (which ends at line 263, just before the `// ------- POA&M mode -------` comment):

```rust
    /// Inventory: include CloudWatch Logs Log Groups.
    #[arg(long = "log-groups", default_value_t = false)]
    pub inv_log_groups: bool,
```

and in `resolve_inventory_types`, after the `if cli.inv_waf { ... }` block:

```rust
    if cli.inv_log_groups {
        selected.push("log-group".to_string());
    }
```

- [ ] **Step 6: Format, lint, and check**

```bash
cargo fmt
cargo check
cargo clippy --quiet --message-format=short 2>&1 | grep -E "src/(inventory_core|cli)\.rs|src/inventory_orchestrator/"
```

Expected: `cargo fmt` and `cargo check` succeed, and the clippy grep prints only the two documented baseline lines.

- [ ] **Step 7: Verify the type is reachable from both entry points**

```bash
cargo run -- --inventory --help 2>&1 | grep -- "--log-groups"
```

Expected: the flag and its help text appear. The TUI list needs no check — it is built from `INVENTORY_ITEMS`.

- [ ] **Step 8: Commit**

```bash
git add src/inventory_core.rs src/inventory_orchestrator/logging.rs src/inventory_orchestrator/mod.rs src/cli.rs
git commit -m "feat(inventory): add CloudWatch Logs log group asset type"
```

---

### Task 2: CloudWatch Logs Destination (`log-destination`)

**Files:**
- Modify: `src/inventory_core.rs`
- Modify: `src/inventory_orchestrator/logging.rs` (append)
- Modify: `src/inventory_orchestrator/mod.rs`
- Modify: `src/cli.rs`

**Interfaces:**
- Consumes: `logging::millis_to_rfc3339` and the `CloudWatchLogsClient` field `self.cwlogs` from Task 1.
- Produces: `pub const crate::inventory_core::ASSET_KEY_LOG_DESTINATION: &str = "log-destination"`; `pub(super) async fn logging::collect_log_destinations(c: &aws_sdk_cloudwatchlogs::Client, region: &str) -> anyhow::Result<Vec<Vec<String>>>`.

- [ ] **Step 1: Add the key constant and `INVENTORY_ITEMS` entry**

In `src/inventory_core.rs`, after `ASSET_KEY_LOG_GROUP`:

```rust
pub const ASSET_KEY_LOG_DESTINATION: &str = "log-destination";
```

and as the new last `INVENTORY_ITEMS` entry:

```rust
    (ASSET_KEY_LOG_DESTINATION, "CloudWatch Logs Destination"),
```

- [ ] **Step 2: Append the collector to `src/inventory_orchestrator/logging.rs`**

```rust
// ---------------------------------------------------------------------------
// CloudWatch Logs Destinations — mapping doc §26
//
// A destination is the cross-account receiving end of a subscription filter:
// account A's log group forwards to account B's destination, which fans out to
// a Kinesis stream or Firehose. Destinations carry no tags and no per-item
// describe call, so this is a single paginated list.
// ---------------------------------------------------------------------------

pub(super) async fn collect_log_destinations(
    c: &CloudWatchLogsClient,
    region: &str,
) -> Result<Vec<Vec<String>>> {
    let destinations = c
        .describe_destinations()
        .into_paginator()
        .items()
        .send()
        .try_collect()
        .await
        .context("CloudWatch Logs describe_destinations")?;

    let mut rows = Vec::with_capacity(destinations.len());
    for dest in &destinations {
        let Some(arn) = dest.arn() else {
            continue;
        };

        let destination_name = dest.destination_name().unwrap_or("").to_string();
        let target_arn = dest.target_arn().unwrap_or("").to_string();
        let role_arn = dest.role_arn().unwrap_or("").to_string();
        // The policy body is a multi-line JSON document — recording only its
        // presence keeps the CSV usable. The full policy is already captured by
        // the evidence-side CloudWatch collectors.
        let access_policy_present = dest.access_policy().is_some().to_string();
        let creation_time = millis_to_rfc3339(dest.creation_time());

        let comments = format!(
            "DestinationName: {destination_name} | TargetArn: {target_arn} | \
             RoleArn: {role_arn} | AccessPolicyPresent: {access_policy_present} | \
             CreationTime: {creation_time}"
        );

        rows.push(
            RowBuilder::new()
                .unique_id(arn)
                .virtual_flag("Yes")
                .public("No")
                .location(region)
                .asset_type("CloudWatch Logs Destination")
                .sw_vendor("Amazon Web Services")
                .sw_name_ver("Amazon CloudWatch Logs (cross-account destination)")
                .function(destination_name)
                .comments(comments)
                .build(),
        );
    }

    Ok(rows)
}
```

- [ ] **Step 3: Wire the match arm in `src/inventory_orchestrator/mod.rs`**

Add `ASSET_KEY_LOG_DESTINATION` to the `crate::inventory_core::{...}` import list and this arm before `other =>`:

```rust
                ASSET_KEY_LOG_DESTINATION => {
                    logging::collect_log_destinations(&self.cwlogs, &region).await
                }
```

No new client field — Task 1 already added `cwlogs`.

- [ ] **Step 4: Add the CLI flag in `src/cli.rs`**

After the `inv_log_groups` field:

```rust
    /// Inventory: include CloudWatch Logs cross-account Destinations.
    #[arg(long = "log-destinations", default_value_t = false)]
    pub inv_log_destinations: bool,
```

and in `resolve_inventory_types`, after the `inv_log_groups` block:

```rust
    if cli.inv_log_destinations {
        selected.push("log-destination".to_string());
    }
```

- [ ] **Step 5: Format, lint, and check**

```bash
cargo fmt
cargo check
cargo clippy --quiet --message-format=short 2>&1 | grep -E "src/(inventory_core|cli)\.rs|src/inventory_orchestrator/"
```

Expected: `cargo fmt` and `cargo check` succeed, and the clippy grep prints only the two documented baseline lines.

- [ ] **Step 6: Commit**

```bash
git add src/inventory_core.rs src/inventory_orchestrator/logging.rs src/inventory_orchestrator/mod.rs src/cli.rs
git commit -m "feat(inventory): add CloudWatch Logs destination asset type"
```

---

### Task 3: VPC Flow Log (`vpc-flow-log`)

**Files:**
- Modify: `src/inventory_orchestrator/network_fabric.rs:709` and `:716` (widen two helpers to `pub(super)`)
- Modify: `src/inventory_core.rs`
- Modify: `src/inventory_orchestrator/logging.rs` (append)
- Modify: `src/inventory_orchestrator/mod.rs`
- Modify: `src/cli.rs`

**Interfaces:**
- Consumes: the existing `Ec2Client` field `self.ec2` in `InventoryCollector` (already present — used by `compute::collect_ec2_instances`, `storage::collect_ebs_volumes`, and `network_fabric::collect_vpc_network`); the `account_id` parameter of `collect_rows`.
- Produces: `pub(super) fn network_fabric::ec2_arn(account_id: &str, region: &str, resource_type: &str, id: &str) -> String`; `pub(super) fn network_fabric::fabric_function(tags: &[aws_sdk_ec2::types::Tag]) -> String`; `pub const crate::inventory_core::ASSET_KEY_VPC_FLOW_LOG: &str = "vpc-flow-log"`; `pub(super) fn logging::smithy_dt_to_rfc3339(dt: Option<&aws_sdk_ec2::primitives::DateTime>) -> String` (used again in Task 6); `pub(super) async fn logging::collect_vpc_flow_logs(c: &aws_sdk_ec2::Client, account_id: &str, region: &str) -> anyhow::Result<Vec<Vec<String>>>`.

- [ ] **Step 1: Widen the two EC2 helpers in `src/inventory_orchestrator/network_fabric.rs`**

Change:

```rust
fn ec2_arn(account_id: &str, region: &str, resource_type: &str, id: &str) -> String {
```

to:

```rust
pub(super) fn ec2_arn(account_id: &str, region: &str, resource_type: &str, id: &str) -> String {
```

and:

```rust
fn fabric_function(tags: &[aws_sdk_ec2::types::Tag]) -> String {
```

to:

```rust
pub(super) fn fabric_function(tags: &[aws_sdk_ec2::types::Tag]) -> String {
```

Flow logs are EC2 sub-resources with no ARN of their own and the same Name-tag-heavy tagging habits as the rest of the network fabric, so reusing both helpers keeps the ARN synthesis (convention #1) and the `Function` fallback identical instead of forking a second copy.

- [ ] **Step 2: Add the key constant and `INVENTORY_ITEMS` entry**

In `src/inventory_core.rs`, after `ASSET_KEY_LOG_DESTINATION`:

```rust
pub const ASSET_KEY_VPC_FLOW_LOG: &str = "vpc-flow-log";
```

and as the new last `INVENTORY_ITEMS` entry:

```rust
    (ASSET_KEY_VPC_FLOW_LOG, "VPC Flow Log"),
```

- [ ] **Step 3: Append the collector to `src/inventory_orchestrator/logging.rs`**

Add to the import block at the top of the file:

```rust
use aws_sdk_ec2::Client as Ec2Client;
```

and:

```rust
use super::network_fabric::{ec2_arn, fabric_function};
```

(place the `super::` import in the `crate::*` group, after the `crate::inventory_core` line).

Then append:

```rust
// ---------------------------------------------------------------------------
// VPC Flow Logs — mapping doc §27
//
// Flow logs attach to a VPC, a subnet, or a single ENI, and deliver either to
// CloudWatch Logs or to S3. EC2 returns no ARN for them, so the unique id is
// synthesised per convention #1 (same as VPC/subnet/IGW/NAT/TGW attachment).
// ---------------------------------------------------------------------------

/// Converts an SDK `DateTime` to RFC3339, matching the `dt_to_rfc3339` helpers
/// in `secrets.rs` and `security_services.rs`. Every AWS SDK crate re-exports
/// the same underlying `aws_smithy_types::DateTime` as
/// `crate::primitives::DateTime`, so naming the EC2 path here lets one helper
/// serve both the flow-log and (Task 6) MSK call sites without adding a direct
/// `aws-smithy-types` dependency — that crate is only a transitive dependency
/// here and cannot be named in a signature.
pub(super) fn smithy_dt_to_rfc3339(dt: Option<&aws_sdk_ec2::primitives::DateTime>) -> String {
    dt.and_then(|d| chrono::DateTime::<chrono::Utc>::from_timestamp(d.secs(), 0))
        .map(|c| c.to_rfc3339())
        .unwrap_or_default()
}

pub(super) async fn collect_vpc_flow_logs(
    c: &Ec2Client,
    account_id: &str,
    region: &str,
) -> Result<Vec<Vec<String>>> {
    let flow_logs = c
        .describe_flow_logs()
        .into_paginator()
        .items()
        .send()
        .try_collect()
        .await
        .context("EC2 describe_flow_logs")?;

    let mut rows = Vec::with_capacity(flow_logs.len());
    for fl in &flow_logs {
        let Some(flow_log_id) = fl.flow_log_id() else {
            continue;
        };
        let arn = ec2_arn(account_id, region, "vpc-flow-log", flow_log_id);

        let resource_id = fl.resource_id().unwrap_or("").to_string();
        let traffic_type = fl
            .traffic_type()
            .map(|t| t.as_str().to_string())
            .unwrap_or_default();
        let log_destination_type = fl
            .log_destination_type()
            .map(|t| t.as_str().to_string())
            .unwrap_or_default();
        let log_destination = fl.log_destination().unwrap_or("").to_string();
        let log_group_name = fl.log_group_name().unwrap_or("").to_string();
        let flow_log_status = fl.flow_log_status().unwrap_or("").to_string();
        let deliver_logs_status = fl.deliver_logs_status().unwrap_or("").to_string();
        let deliver_logs_error = fl.deliver_logs_error_message().unwrap_or("").to_string();
        let max_aggregation_interval = fl
            .max_aggregation_interval()
            .map(|i| i.to_string())
            .unwrap_or_default();
        // The log format is a space-separated ${field} template; the pipe
        // separator used between Comments keys can't appear inside it.
        let log_format = fl.log_format().unwrap_or("").to_string();
        let (file_format, hive_partitions, per_hour_partition) = match fl.destination_options() {
            Some(o) => (
                o.file_format()
                    .map(|f| f.as_str().to_string())
                    .unwrap_or_default(),
                o.hive_compatible_partitions()
                    .map(|b| b.to_string())
                    .unwrap_or_default(),
                o.per_hour_partition()
                    .map(|b| b.to_string())
                    .unwrap_or_default(),
            ),
            None => (String::new(), String::new(), String::new()),
        };
        let deliver_logs_permission_arn =
            fl.deliver_logs_permission_arn().unwrap_or("").to_string();
        let creation_time = smithy_dt_to_rfc3339(fl.creation_time());

        // Flow logs attach to VPCs, subnets, and ENIs alike — label which.
        let vlan_network_id = if resource_id.starts_with("vpc-") {
            format!("VPC: {resource_id}")
        } else if resource_id.is_empty() {
            String::new()
        } else {
            format!("Resource: {resource_id}")
        };

        let comments = format!(
            "ResourceId: {resource_id} | TrafficType: {traffic_type} | \
             LogDestinationType: {log_destination_type} | LogDestination: {log_destination} | \
             LogGroupName: {log_group_name} | FlowLogStatus: {flow_log_status} | \
             DeliverLogsStatus: {deliver_logs_status} | \
             DeliverLogsErrorMessage: {deliver_logs_error} | \
             MaxAggregationInterval: {max_aggregation_interval} | LogFormat: {log_format} | \
             FileFormat: {file_format} | HiveCompatiblePartitions: {hive_partitions} | \
             PerHourPartition: {per_hour_partition} | \
             DeliverLogsPermissionArn: {deliver_logs_permission_arn} | \
             CreationTime: {creation_time}"
        );

        rows.push(
            RowBuilder::new()
                .unique_id(&arn)
                .virtual_flag("Yes")
                .public("No")
                .location(region)
                .asset_type("VPC Flow Log")
                .sw_vendor("Amazon Web Services")
                .sw_name_ver("Amazon VPC Flow Logs")
                .vlan_network_id(vlan_network_id)
                .function(fabric_function(fl.tags()))
                .comments(comments)
                .build(),
        );
    }

    Ok(rows)
}
```

- [ ] **Step 4: Wire the match arm in `src/inventory_orchestrator/mod.rs`**

Add `ASSET_KEY_VPC_FLOW_LOG` to the `crate::inventory_core::{...}` import list and this arm before `other =>`:

```rust
                ASSET_KEY_VPC_FLOW_LOG => {
                    logging::collect_vpc_flow_logs(&self.ec2, account_id, &region).await
                }
```

No new client field — `ec2` already exists.

- [ ] **Step 5: Add the CLI flag in `src/cli.rs`**

After the `inv_log_destinations` field:

```rust
    /// Inventory: include VPC Flow Logs.
    #[arg(long = "vpc-flow-logs", default_value_t = false)]
    pub inv_vpc_flow_logs: bool,
```

and in `resolve_inventory_types`, after the `inv_log_destinations` block:

```rust
    if cli.inv_vpc_flow_logs {
        selected.push("vpc-flow-log".to_string());
    }
```

- [ ] **Step 6: Format, lint, and check**

```bash
cargo fmt
cargo check
cargo clippy --quiet --message-format=short 2>&1 | grep -E "src/(inventory_core|cli)\.rs|src/inventory_orchestrator/"
```

Expected: `cargo fmt` and `cargo check` succeed, and the clippy grep prints only the two documented baseline lines. If clippy warns `dead_code` on `fabric_function` or `ec2_arn`, that means the `use super::network_fabric::...` import was omitted — add it.

- [ ] **Step 7: Commit**

```bash
git add src/inventory_core.rs src/inventory_orchestrator/logging.rs src/inventory_orchestrator/network_fabric.rs src/inventory_orchestrator/mod.rs src/cli.rs
git commit -m "feat(inventory): add VPC flow log asset type"
```

---

### Task 4: Route 53 Resolver Query Log Config (`resolver-query-log`)

**Files:**
- Modify: `src/inventory_core.rs`
- Modify: `src/inventory_orchestrator/logging.rs` (append)
- Modify: `src/inventory_orchestrator/mod.rs`
- Modify: `src/cli.rs`

**Interfaces:**
- Consumes: the `logging` module from Task 1.
- Produces: `pub const crate::inventory_core::ASSET_KEY_RESOLVER_QUERY_LOG: &str = "resolver-query-log"`; `pub(super) async fn logging::collect_resolver_query_logs(c: &aws_sdk_route53resolver::Client, region: &str) -> anyhow::Result<Vec<Vec<String>>>`.

- [ ] **Step 1: Add the key constant and `INVENTORY_ITEMS` entry**

In `src/inventory_core.rs`, after `ASSET_KEY_VPC_FLOW_LOG`:

```rust
pub const ASSET_KEY_RESOLVER_QUERY_LOG: &str = "resolver-query-log";
```

and as the new last `INVENTORY_ITEMS` entry:

```rust
    (
        ASSET_KEY_RESOLVER_QUERY_LOG,
        "Route 53 Resolver Query Log Config",
    ),
```

- [ ] **Step 2: Append the collector to `src/inventory_orchestrator/logging.rs`**

Add to the external-crate import group at the top of the file:

```rust
use aws_sdk_route53resolver::types::Filter as ResolverFilter;
use aws_sdk_route53resolver::Client as Route53ResolverClient;
```

Then append:

```rust
// ---------------------------------------------------------------------------
// Route 53 Resolver Query Log Configs — mapping doc §28
//
// A query log config is the DNS-query logging pipeline: one config, N VPC
// associations, one destination (CloudWatch Logs group, S3 bucket, or Firehose
// stream). Configs shared into this account (ShareStatus SHARED_WITH_ME) are
// kept — they are in force on this account's VPCs and so are in scope.
// ---------------------------------------------------------------------------

/// Soft-failing list of VPC (or other resource) ids associated with one query
/// log config. `association_count` on the config tells us how many there are
/// but not which — only this call does.
async fn resolver_query_log_associations(c: &Route53ResolverClient, config_id: &str) -> Vec<String> {
    let filter = ResolverFilter::builder()
        .name("ResolverQueryLogConfigId")
        .values(config_id)
        .build();

    match c
        .list_resolver_query_log_config_associations()
        .filters(filter)
        .into_paginator()
        .items()
        .send()
        .try_collect()
        .await
    {
        Ok(associations) => associations
            .iter()
            .filter_map(|a| a.resource_id().map(|s| s.to_string()))
            .collect(),
        Err(e) => {
            eprintln!(
                "route53resolver list_resolver_query_log_config_associations failed for \
                 {config_id}: {e}"
            );
            Vec::new()
        }
    }
}

pub(super) async fn collect_resolver_query_logs(
    c: &Route53ResolverClient,
    region: &str,
) -> Result<Vec<Vec<String>>> {
    let configs = c
        .list_resolver_query_log_configs()
        .into_paginator()
        .items()
        .send()
        .try_collect()
        .await
        .context("Route53Resolver list_resolver_query_log_configs")?;

    let mut rows = Vec::with_capacity(configs.len());
    for config in &configs {
        let Some(arn) = config.arn() else {
            continue;
        };

        let name = config.name().unwrap_or("").to_string();
        let status = config
            .status()
            .map(|s| s.as_str().to_string())
            .unwrap_or_default();
        let share_status = config
            .share_status()
            .map(|s| s.as_str().to_string())
            .unwrap_or_default();
        let owner_id = config.owner_id().unwrap_or("").to_string();
        let destination_arn = config.destination_arn().unwrap_or("").to_string();
        let association_count = config.association_count().to_string();
        let creation_time = config.creation_time().unwrap_or("").to_string();

        let associated = match config.id() {
            Some(id) => resolver_query_log_associations(c, id).await,
            None => Vec::new(),
        };
        let associated_resources = associated.join(", ");

        let comments = format!(
            "Name: {name} | Status: {status} | ShareStatus: {share_status} | \
             OwnerId: {owner_id} | DestinationArn: {destination_arn} | \
             AssociationCount: {association_count} | \
             AssociatedResources: {associated_resources} | CreationTime: {creation_time}"
        );

        rows.push(
            RowBuilder::new()
                .unique_id(arn)
                .virtual_flag("Yes")
                .public("No")
                .location(region)
                .asset_type("Route 53 Resolver Query Log Config")
                .sw_vendor("Amazon Web Services")
                .sw_name_ver("Amazon Route 53 Resolver Query Logging")
                .vlan_network_id(associated_resources)
                .function(name)
                .comments(comments)
                .build(),
        );
    }

    Ok(rows)
}
```

- [ ] **Step 3: Wire the client and match arm in `src/inventory_orchestrator/mod.rs`**

1. Import, alphabetically after `aws_sdk_redshift`:

```rust
use aws_sdk_route53resolver::Client as Route53ResolverClient;
```

2. Struct field after `redshift: RedshiftClient,`:

```rust
    route53resolver: Route53ResolverClient,
```

3. Constructor line after `redshift: RedshiftClient::new(config),`:

```rust
            route53resolver: Route53ResolverClient::new(config),
```

4. Add `ASSET_KEY_RESOLVER_QUERY_LOG` to the `crate::inventory_core::{...}` import list and this arm before `other =>`:

```rust
                ASSET_KEY_RESOLVER_QUERY_LOG => {
                    logging::collect_resolver_query_logs(&self.route53resolver, &region).await
                }
```

- [ ] **Step 4: Add the CLI flag in `src/cli.rs`**

After the `inv_vpc_flow_logs` field:

```rust
    /// Inventory: include Route 53 Resolver Query Log Configs.
    #[arg(long = "resolver-query-logs", default_value_t = false)]
    pub inv_resolver_query_logs: bool,
```

and in `resolve_inventory_types`, after the `inv_vpc_flow_logs` block:

```rust
    if cli.inv_resolver_query_logs {
        selected.push("resolver-query-log".to_string());
    }
```

- [ ] **Step 5: Format, lint, and check**

```bash
cargo fmt
cargo check
cargo clippy --quiet --message-format=short 2>&1 | grep -E "src/(inventory_core|cli)\.rs|src/inventory_orchestrator/"
```

Expected: `cargo fmt` and `cargo check` succeed, and the clippy grep prints only the two documented baseline lines.

- [ ] **Step 6: Commit**

```bash
git add src/inventory_core.rs src/inventory_orchestrator/logging.rs src/inventory_orchestrator/mod.rs src/cli.rs
git commit -m "feat(inventory): add Route 53 Resolver query log config asset type"
```

---

### Task 5: OpenSearch Domain (`opensearch-domain`)

**Files:**
- Modify: `Cargo.toml`
- Create: `src/inventory_orchestrator/log_analytics.rs`
- Modify: `src/inventory_core.rs`
- Modify: `src/inventory_orchestrator/mod.rs`
- Modify: `src/cli.rs`

**Interfaces:**
- Consumes: `crate::inventory_core::{function_from_tag_map, RowBuilder}` from Task 1.
- Produces: `pub const crate::inventory_core::ASSET_KEY_OPENSEARCH_DOMAIN: &str = "opensearch-domain"`; `pub(super) async fn log_analytics::collect_opensearch_domains(c: &aws_sdk_opensearch::Client, region: &str) -> anyhow::Result<Vec<Vec<String>>>`; the `log_analytics` module, which Task 6 appends to.

- [ ] **Step 1: Add the dependency to `Cargo.toml`**

Add to `[dependencies]`, next to the other `aws-sdk-*` lines:

```toml
aws-sdk-opensearch = "1"
```

- [ ] **Step 2: Add the key constant and `INVENTORY_ITEMS` entry**

In `src/inventory_core.rs`, after `ASSET_KEY_RESOLVER_QUERY_LOG`:

```rust
pub const ASSET_KEY_OPENSEARCH_DOMAIN: &str = "opensearch-domain";
```

and as the new last `INVENTORY_ITEMS` entry:

```rust
    (ASSET_KEY_OPENSEARCH_DOMAIN, "OpenSearch Domain"),
```

- [ ] **Step 3: Create `src/inventory_orchestrator/log_analytics.rs`**

```rust
use std::collections::HashMap;

use anyhow::{Context, Result};
use aws_sdk_opensearch::types::DomainStatus;
use aws_sdk_opensearch::Client as OpenSearchClient;

use crate::inventory_core::{function_from_tag_map, RowBuilder};

// ---------------------------------------------------------------------------
// Log analytics sinks — mapping doc §29 (OpenSearch Domain), §30 (MSK Cluster)
//
// These are the clustered destinations logs land in, as opposed to the log
// producers and pipelines in logging.rs. They are inventoried as compute-like
// assets (instance type, node count, VPC placement) *and* as log sinks (which
// log types they publish, where broker logs go).
// ---------------------------------------------------------------------------

/// Soft-failing tag lookup. OpenSearch returns `Vec<Tag>` with infallible
/// `key()`/`value()` accessors (unlike Secrets Manager's `Option<&str>` pair),
/// so fold it into the shared `HashMap` shape.
async fn opensearch_tags(c: &OpenSearchClient, arn: &str) -> HashMap<String, String> {
    match c.list_tags().arn(arn).send().await {
        Ok(r) => r
            .tag_list()
            .iter()
            .map(|t| (t.key().to_string(), t.value().to_string()))
            .collect(),
        Err(e) => {
            eprintln!("opensearch list_tags failed for {arn}: {e}");
            HashMap::new()
        }
    }
}

/// `<LogType>=<enabled>` pairs, sorted for stable CSV diffs. This is the AU-2 /
/// AU-12 fact for a domain that is itself a log sink: is it logging its own
/// audit, application, and slow-query activity?
fn log_publishing_summary(status: &DomainStatus) -> String {
    let Some(options) = status.log_publishing_options() else {
        return String::new();
    };
    let mut entries: Vec<String> = options
        .iter()
        .map(|(log_type, option)| {
            format!(
                "{}={}",
                log_type.as_str(),
                option.enabled().unwrap_or(false)
            )
        })
        .collect();
    entries.sort();
    entries.join("; ")
}

pub(super) async fn collect_opensearch_domains(
    c: &OpenSearchClient,
    region: &str,
) -> Result<Vec<Vec<String>>> {
    // list_domain_names is a single unpaginated call returning names only.
    let listed = c
        .list_domain_names()
        .send()
        .await
        .context("OpenSearch list_domain_names")?;

    let mut rows = Vec::new();
    for info in listed.domain_names() {
        let Some(domain_name) = info.domain_name() else {
            continue;
        };

        // Soft-fail per domain: one domain mid-delete or in another partition
        // must not lose the rest.
        let status = match c.describe_domain().domain_name(domain_name).send().await {
            Ok(r) => r.domain_status().cloned(),
            Err(e) => {
                eprintln!("opensearch describe_domain failed for {domain_name}: {e}");
                None
            }
        };
        let Some(status) = status else {
            continue;
        };

        let arn = status.arn().to_string();
        let domain_id = status.domain_id().to_string();
        let engine_version = status.engine_version().unwrap_or("").to_string();

        let (instance_type, instance_count, dedicated_master, zone_awareness) =
            match status.cluster_config() {
                Some(cfg) => (
                    cfg.instance_type()
                        .map(|t| t.as_str().to_string())
                        .unwrap_or_default(),
                    cfg.instance_count().unwrap_or_default().to_string(),
                    cfg.dedicated_master_enabled()
                        .unwrap_or(false)
                        .to_string(),
                    cfg.zone_awareness_enabled().unwrap_or(false).to_string(),
                ),
                None => (
                    String::new(),
                    String::new(),
                    String::new(),
                    String::new(),
                ),
            };

        let (ebs_enabled, ebs_volume_type, ebs_volume_size) = match status.ebs_options() {
            Some(o) => (
                o.ebs_enabled().unwrap_or(false).to_string(),
                o.volume_type()
                    .map(|v| v.as_str().to_string())
                    .unwrap_or_default(),
                o.volume_size().map(|s| s.to_string()).unwrap_or_default(),
            ),
            None => (String::new(), String::new(), String::new()),
        };

        let (encryption_at_rest, encryption_kms_key_id) = match status.encryption_at_rest_options()
        {
            Some(o) => (
                o.enabled().unwrap_or(false).to_string(),
                o.kms_key_id().unwrap_or("").to_string(),
            ),
            None => (String::new(), String::new()),
        };
        let node_to_node_encryption = status
            .node_to_node_encryption_options()
            .and_then(|o| o.enabled())
            .unwrap_or(false)
            .to_string();

        let (enforce_https, tls_policy) = match status.domain_endpoint_options() {
            Some(o) => (
                o.enforce_https().unwrap_or(false).to_string(),
                o.tls_security_policy()
                    .map(|p| p.as_str().to_string())
                    .unwrap_or_default(),
            ),
            None => (String::new(), String::new()),
        };
        let advanced_security = status
            .advanced_security_options()
            .and_then(|o| o.enabled())
            .unwrap_or(false)
            .to_string();

        // A domain with no vpc_options is a public-access domain: its endpoint
        // resolves on the internet and is guarded only by the access policy.
        let vpc = status.vpc_options();
        let public = if vpc.is_some() { "No" } else { "Yes" };
        let vlan_network_id = match vpc {
            Some(v) => format!(
                "VPC: {}, Subnets: {}",
                v.vpc_id().unwrap_or(""),
                v.subnet_ids().join(" ")
            ),
            None => String::new(),
        };
        let security_group_ids = vpc
            .map(|v| v.security_group_ids().join(" "))
            .unwrap_or_default();

        // VPC domains return no top-level `endpoint`; they publish a map whose
        // "vpc" key holds the reachable host.
        let dns_url = match status.endpoint() {
            Some(e) => e.to_string(),
            None => status
                .endpoints()
                .and_then(|m| m.get("vpc"))
                .cloned()
                .unwrap_or_default(),
        };

        let processing = status.processing().unwrap_or(false).to_string();
        let log_publishing = log_publishing_summary(&status);

        let tags = opensearch_tags(c, &arn).await;
        let function = {
            let tag_function = function_from_tag_map(&tags);
            if tag_function.is_empty() {
                domain_name.to_string()
            } else {
                tag_function
            }
        };

        let hw_make_model = if instance_type.is_empty() {
            String::new()
        } else {
            format!("AWS OpenSearch {instance_type} x{instance_count}")
        };
        let sw_name_ver = if engine_version.is_empty() {
            "Amazon OpenSearch Service".to_string()
        } else {
            engine_version.clone()
        };

        let comments = format!(
            "DomainId: {domain_id} | EngineVersion: {engine_version} | \
             InstanceType: {instance_type} | InstanceCount: {instance_count} | \
             DedicatedMasterEnabled: {dedicated_master} | \
             ZoneAwarenessEnabled: {zone_awareness} | EbsEnabled: {ebs_enabled} | \
             EbsVolumeType: {ebs_volume_type} | EbsVolumeSize: {ebs_volume_size} | \
             EncryptionAtRest: {encryption_at_rest} | \
             EncryptionAtRestKmsKeyId: {encryption_kms_key_id} | \
             NodeToNodeEncryption: {node_to_node_encryption} | EnforceHTTPS: {enforce_https} | \
             TLSSecurityPolicy: {tls_policy} | AdvancedSecurityEnabled: {advanced_security} | \
             LogPublishing: {log_publishing} | SecurityGroupIds: {security_group_ids} | \
             Processing: {processing}"
        );

        rows.push(
            RowBuilder::new()
                .unique_id(&arn)
                .virtual_flag("Yes")
                .public(public)
                .dns_url(dns_url)
                .location(region)
                .asset_type("OpenSearch Domain")
                .hw_make_model(hw_make_model)
                .sw_vendor("Amazon Web Services")
                .sw_name_ver(sw_name_ver)
                .vlan_network_id(vlan_network_id)
                .function(function)
                .comments(comments)
                .build(),
        );
    }

    Ok(rows)
}
```

- [ ] **Step 4: Declare the module and wire the collector in `src/inventory_orchestrator/mod.rs`**

1. Module declaration, alphabetically in the `mod` block:

```rust
mod log_analytics;
mod logging;
```

2. Import, alphabetically after `aws_sdk_lambda`:

```rust
use aws_sdk_opensearch::Client as OpenSearchClient;
```

3. Struct field after `lambda: LambdaClient,`:

```rust
    opensearch: OpenSearchClient,
```

4. Constructor line after `lambda: LambdaClient::new(config),`:

```rust
            opensearch: OpenSearchClient::new(config),
```

5. Add `ASSET_KEY_OPENSEARCH_DOMAIN` to the `crate::inventory_core::{...}` import list and this arm before `other =>`:

```rust
                ASSET_KEY_OPENSEARCH_DOMAIN => {
                    log_analytics::collect_opensearch_domains(&self.opensearch, &region).await
                }
```

- [ ] **Step 5: Add the CLI flag in `src/cli.rs`**

After the `inv_resolver_query_logs` field:

```rust
    /// Inventory: include OpenSearch Domains.
    #[arg(long = "opensearch", default_value_t = false)]
    pub inv_opensearch: bool,
```

and in `resolve_inventory_types`, after the `inv_resolver_query_logs` block:

```rust
    if cli.inv_opensearch {
        selected.push("opensearch-domain".to_string());
    }
```

- [ ] **Step 6: Format, lint, and check**

```bash
cargo fmt
cargo check
cargo clippy --quiet --message-format=short 2>&1 | grep -E "src/(inventory_core|cli)\.rs|src/inventory_orchestrator/"
```

Expected: `cargo fmt` and `cargo check` succeed, and the clippy grep prints only the two documented baseline lines. The first `cargo check` downloads and compiles `aws-sdk-opensearch` — allow a minute.

- [ ] **Step 7: Commit**

```bash
git add Cargo.toml Cargo.lock src/inventory_core.rs src/inventory_orchestrator/log_analytics.rs src/inventory_orchestrator/mod.rs src/cli.rs
git commit -m "feat(inventory): add OpenSearch domain asset type"
```

---

### Task 6: MSK Cluster (`msk-cluster`)

**Files:**
- Modify: `Cargo.toml`
- Modify: `src/inventory_orchestrator/log_analytics.rs` (append)
- Modify: `src/inventory_core.rs`
- Modify: `src/inventory_orchestrator/mod.rs`
- Modify: `src/cli.rs`

**Interfaces:**
- Consumes: `crate::inventory_core::{function_from_tag_map, RowBuilder}` from Task 1; `super::logging::smithy_dt_to_rfc3339` from Task 1; the `log_analytics` module from Task 5.
- Produces: `pub const crate::inventory_core::ASSET_KEY_MSK_CLUSTER: &str = "msk-cluster"`; `pub(super) async fn log_analytics::collect_msk_clusters(c: &aws_sdk_kafka::Client, region: &str) -> anyhow::Result<Vec<Vec<String>>>`.

- [ ] **Step 1: Add the dependency to `Cargo.toml`**

Add to `[dependencies]`:

```toml
aws-sdk-kafka = "1"
```

- [ ] **Step 2: Add the key constant and `INVENTORY_ITEMS` entry**

In `src/inventory_core.rs`, after `ASSET_KEY_OPENSEARCH_DOMAIN`:

```rust
pub const ASSET_KEY_MSK_CLUSTER: &str = "msk-cluster";
```

and as the new last `INVENTORY_ITEMS` entry:

```rust
    (ASSET_KEY_MSK_CLUSTER, "MSK Cluster (Kafka)"),
```

- [ ] **Step 3: Append the collector to `src/inventory_orchestrator/log_analytics.rs`**

Add to the external-crate import group:

```rust
use aws_sdk_kafka::types::{ClientAuthentication, Cluster, LoggingInfo};
use aws_sdk_kafka::Client as KafkaClient;
```

and to the `crate::*` group:

```rust
use super::logging::smithy_dt_to_rfc3339;
```

Then append:

```rust
// ---------------------------------------------------------------------------
// MSK Clusters — mapping doc §30
//
// `list_clusters_v2` covers both provisioned and serverless clusters in one
// paginated call and returns tags inline, so no per-cluster describe or tag
// call is needed. The two shapes carry disjoint config (`provisioned` vs
// `serverless`), so every field read below tolerates either being absent.
// ---------------------------------------------------------------------------

/// `; `-joined list of the enabled client-auth mechanisms. Unauthenticated
/// access is the finding an auditor is looking for, so it is reported
/// explicitly rather than by omission.
fn client_auth_summary(auth: Option<&ClientAuthentication>) -> String {
    let Some(auth) = auth else {
        return String::new();
    };
    let mut modes: Vec<&str> = Vec::new();
    if let Some(sasl) = auth.sasl() {
        if sasl.iam().and_then(|i| i.enabled()).unwrap_or(false) {
            modes.push("SASL/IAM");
        }
        if sasl.scram().and_then(|s| s.enabled()).unwrap_or(false) {
            modes.push("SASL/SCRAM");
        }
    }
    if auth.tls().and_then(|t| t.enabled()).unwrap_or(false) {
        modes.push("TLS");
    }
    if auth
        .unauthenticated()
        .and_then(|u| u.enabled())
        .unwrap_or(false)
    {
        modes.push("Unauthenticated");
    }
    modes.join("; ")
}

/// `; `-joined list of the enabled broker-log destinations. An MSK cluster is
/// itself a log pipeline, so where its own broker logs go is in scope. The
/// `.filter(...)` form keeps each check a single `if let` — the nested
/// `if let` + `if` version trips `clippy::collapsible_if` under `-D warnings`.
fn broker_logs_summary(logging_info: Option<&LoggingInfo>) -> String {
    let Some(broker_logs) = logging_info.and_then(|l| l.broker_logs()) else {
        return String::new();
    };
    let mut sinks: Vec<String> = Vec::new();
    if let Some(cw) = broker_logs
        .cloud_watch_logs()
        .filter(|c| c.enabled().unwrap_or(false))
    {
        sinks.push(format!("CloudWatch: {}", cw.log_group().unwrap_or("")));
    }
    if let Some(fh) = broker_logs
        .firehose()
        .filter(|f| f.enabled().unwrap_or(false))
    {
        sinks.push(format!("Firehose: {}", fh.delivery_stream().unwrap_or("")));
    }
    if let Some(s3) = broker_logs.s3().filter(|s| s.enabled().unwrap_or(false)) {
        sinks.push(format!(
            "S3: {}/{}",
            s3.bucket().unwrap_or(""),
            s3.prefix().unwrap_or("")
        ));
    }
    sinks.join("; ")
}

/// Provisioned brokers can be given public IPs; serverless cannot. Anything
/// other than `SERVICE_PROVIDED_EIPS` (including the literal `DISABLED`) is
/// private.
fn msk_public(cluster: &Cluster) -> &'static str {
    let public_access_type = cluster
        .provisioned()
        .and_then(|p| p.broker_node_group_info())
        .and_then(|b| b.connectivity_info())
        .and_then(|c| c.public_access())
        .and_then(|p| p.r#type())
        .unwrap_or("");
    if public_access_type == "SERVICE_PROVIDED_EIPS" {
        "Yes"
    } else {
        "No"
    }
}

pub(super) async fn collect_msk_clusters(
    c: &KafkaClient,
    region: &str,
) -> Result<Vec<Vec<String>>> {
    let clusters = c
        .list_clusters_v2()
        .into_paginator()
        .items()
        .send()
        .try_collect()
        .await
        .context("MSK list_clusters_v2")?;

    let mut rows = Vec::with_capacity(clusters.len());
    for cluster in &clusters {
        let Some(arn) = cluster.cluster_arn() else {
            continue;
        };

        let cluster_name = cluster.cluster_name().unwrap_or("").to_string();
        let cluster_type = cluster
            .cluster_type()
            .map(|t| t.as_str().to_string())
            .unwrap_or_default();
        let state = cluster
            .state()
            .map(|s| s.as_str().to_string())
            .unwrap_or_default();
        let creation_time = smithy_dt_to_rfc3339(cluster.creation_time());

        let provisioned = cluster.provisioned();
        let broker_info = provisioned.and_then(|p| p.broker_node_group_info());

        let instance_type = broker_info
            .and_then(|b| b.instance_type())
            .unwrap_or("")
            .to_string();
        let broker_count = provisioned
            .and_then(|p| p.number_of_broker_nodes())
            .map(|n| n.to_string())
            .unwrap_or_default();
        let kafka_version = provisioned
            .and_then(|p| p.current_broker_software_info())
            .and_then(|i| i.kafka_version())
            .unwrap_or("")
            .to_string();
        let storage_mode = provisioned
            .and_then(|p| p.storage_mode())
            .map(|m| m.as_str().to_string())
            .unwrap_or_default();
        let enhanced_monitoring = provisioned
            .and_then(|p| p.enhanced_monitoring())
            .map(|m| m.as_str().to_string())
            .unwrap_or_default();

        let encryption_info = provisioned.and_then(|p| p.encryption_info());
        let encryption_kms_key_id = encryption_info
            .and_then(|e| e.encryption_at_rest())
            .and_then(|e| e.data_volume_kms_key_id())
            .unwrap_or("")
            .to_string();
        let encryption_client_broker = encryption_info
            .and_then(|e| e.encryption_in_transit())
            .and_then(|e| e.client_broker())
            .map(|b| b.as_str().to_string())
            .unwrap_or_default();
        let encryption_in_cluster = encryption_info
            .and_then(|e| e.encryption_in_transit())
            .and_then(|e| e.in_cluster())
            .map(|b| b.to_string())
            .unwrap_or_default();

        // Client auth and subnets live under `provisioned` for provisioned
        // clusters and under `serverless` for serverless ones.
        let serverless = cluster.serverless();
        let client_authentication = match provisioned.and_then(|p| p.client_authentication()) {
            Some(auth) => client_auth_summary(Some(auth)),
            None => serverless
                .and_then(|s| s.client_authentication())
                .and_then(|a| a.sasl())
                .map(|sasl| {
                    if sasl.iam().and_then(|i| i.enabled()).unwrap_or(false) {
                        "SASL/IAM".to_string()
                    } else {
                        String::new()
                    }
                })
                .unwrap_or_default(),
        };

        let subnets = match broker_info {
            Some(b) => b.client_subnets().join(" "),
            None => serverless
                .map(|s| {
                    s.vpc_configs()
                        .iter()
                        .flat_map(|v| v.subnet_ids().iter().cloned())
                        .collect::<Vec<_>>()
                        .join(" ")
                })
                .unwrap_or_default(),
        };
        let security_groups = match broker_info {
            Some(b) => b.security_groups().join(" "),
            None => serverless
                .map(|s| {
                    s.vpc_configs()
                        .iter()
                        .flat_map(|v| v.security_group_ids().iter().cloned())
                        .collect::<Vec<_>>()
                        .join(" ")
                })
                .unwrap_or_default(),
        };
        let vlan_network_id = if subnets.is_empty() {
            String::new()
        } else {
            format!("Subnets: {subnets}")
        };

        let broker_logs = broker_logs_summary(provisioned.and_then(|p| p.logging_info()));

        let tags = cluster.tags().cloned().unwrap_or_default();
        let function = {
            let tag_function = function_from_tag_map(&tags);
            if tag_function.is_empty() {
                cluster_name.clone()
            } else {
                tag_function
            }
        };

        let hw_make_model = if instance_type.is_empty() {
            "AWS MSK Serverless".to_string()
        } else {
            format!("AWS MSK {instance_type} x{broker_count}")
        };
        let sw_name_ver = if kafka_version.is_empty() {
            "Amazon MSK".to_string()
        } else {
            format!("Apache Kafka {kafka_version}")
        };

        let comments = format!(
            "ClusterName: {cluster_name} | ClusterType: {cluster_type} | State: {state} | \
             KafkaVersion: {kafka_version} | NumberOfBrokerNodes: {broker_count} | \
             StorageMode: {storage_mode} | \
             EncryptionAtRestKmsKeyId: {encryption_kms_key_id} | \
             EncryptionInTransitClientBroker: {encryption_client_broker} | \
             EncryptionInClusterEnabled: {encryption_in_cluster} | \
             ClientAuthentication: {client_authentication} | \
             EnhancedMonitoring: {enhanced_monitoring} | BrokerLogs: {broker_logs} | \
             SecurityGroups: {security_groups} | CreationTime: {creation_time}"
        );

        rows.push(
            RowBuilder::new()
                .unique_id(arn)
                .virtual_flag("Yes")
                .public(msk_public(cluster))
                .location(region)
                .asset_type("MSK Cluster")
                .hw_make_model(hw_make_model)
                .sw_vendor("Amazon Web Services")
                .sw_name_ver(sw_name_ver)
                .vlan_network_id(vlan_network_id)
                .function(function)
                .comments(comments)
                .build(),
        );
    }

    Ok(rows)
}
```

- [ ] **Step 4: Wire the client and match arm in `src/inventory_orchestrator/mod.rs`**

1. Import, alphabetically after `aws_sdk_guardduty`:

```rust
use aws_sdk_kafka::Client as KafkaClient;
```

2. Struct field after `guardduty: GuardDutyClient,`:

```rust
    kafka: KafkaClient,
```

3. Constructor line after `guardduty: GuardDutyClient::new(config),`:

```rust
            kafka: KafkaClient::new(config),
```

4. Add `ASSET_KEY_MSK_CLUSTER` to the `crate::inventory_core::{...}` import list and this arm before `other =>`:

```rust
                ASSET_KEY_MSK_CLUSTER => {
                    log_analytics::collect_msk_clusters(&self.kafka, &region).await
                }
```

- [ ] **Step 5: Add the CLI flag in `src/cli.rs`**

After the `inv_opensearch` field:

```rust
    /// Inventory: include MSK (Kafka) Clusters.
    #[arg(long = "msk", default_value_t = false)]
    pub inv_msk: bool,
```

and in `resolve_inventory_types`, after the `inv_opensearch` block:

```rust
    if cli.inv_msk {
        selected.push("msk-cluster".to_string());
    }
```

- [ ] **Step 6: Format, lint, and check**

```bash
cargo fmt
cargo check
cargo clippy --quiet --message-format=short 2>&1 | grep -E "src/(inventory_core|cli)\.rs|src/inventory_orchestrator/"
```

Expected: `cargo fmt` and `cargo check` succeed, and the clippy grep prints only the two documented baseline lines. The first `cargo check` compiles `aws-sdk-kafka`.

- [ ] **Step 7: Verify all six flags and keys are registered**

```bash
cargo run -- --inventory --help 2>&1 | grep -E -- "--log-groups|--log-destinations|--vpc-flow-logs|--resolver-query-logs|--opensearch|--msk"
```

Expected: six lines.

```bash
cargo run -- --inventory --inventory-types log-group,log-destination,vpc-flow-log,resolver-query-log,opensearch-domain,msk-cluster --region us-east-1 2>&1 | head -30
```

Expected (with credentials): per-type row counts on stderr and no `unknown asset type key` warnings. Without credentials: a credential error, which still proves key resolution happened — an `unknown asset type key '<key>' — skipped` line means a match arm was missed.

- [ ] **Step 8: Commit**

```bash
git add Cargo.toml Cargo.lock src/inventory_core.rs src/inventory_orchestrator/log_analytics.rs src/inventory_orchestrator/mod.rs src/cli.rs
git commit -m "feat(inventory): add MSK cluster asset type"
```

---

### Task 7: Documentation

**Files:**
- Modify: `evidence-list.md` (Supported Asset Types table + the `Asset Inventory asset types` count in the Summary table)
- Modify: `docs/cli-reference.md` (both inventory tables, at ~line 186 and ~line 635)
- Modify: `README.md:307` (the `--inventory-types` row)
- Modify: `docs/superpowers/plans/2026-07-17-aws-inventory-expansion-mapping.md` (append §25–§30)

**Interfaces:**
- Consumes: the six asset keys and labels from Tasks 1–6.
- Produces: nothing consumed by code.

> **Known pre-existing drift, deliberately not fixed here:** these docs describe only the original 8 asset types, while `INVENTORY_ITEMS` already carried 27 before this plan. This task adds the 6 new log-service types and corrects the counts; a full reconciliation of the other 19 missing rows is a separate cleanup and is out of scope.

- [ ] **Step 1: Add the new rows to `evidence-list.md`**

Append to the `### Supported Asset Types` table, after the `container` row:

```markdown
| `log-group` | CloudWatch Logs Log Group | `AWS_Inventory` | Retention, KMS key, stored bytes, metric/subscription filters; enrichment capped at 500 groups per region |
| `log-destination` | CloudWatch Logs Destination | `AWS_Inventory` | Cross-account log destinations; target ARN and role |
| `vpc-flow-log` | VPC Flow Log | `AWS_Inventory` | Traffic type, destination (CW Logs or S3), delivery status, aggregation interval |
| `resolver-query-log` | Route 53 Resolver Query Log Config | `AWS_Inventory` | DNS query logging destination + associated VPCs |
| `opensearch-domain` | OpenSearch Domain | `AWS_Inventory` | Cluster config, encryption, HTTPS/TLS policy, log publishing |
| `msk-cluster` | MSK Cluster (Kafka) | `AWS_Inventory` | Provisioned and serverless; encryption, client auth, broker log destinations |
```

In the Summary table, change:

```markdown
| Asset Inventory asset types (Inventory feature) | 8 |
```

to:

```markdown
| Asset Inventory asset types (Inventory feature) | 33 |
```

(27 pre-existing entries + the 6 added by this plan. Confirm the number rather than trusting it:

```bash
grep -c "^pub const ASSET_KEY_" src/inventory_core.rs
```

Expected: `33`. Every key has exactly one `pub const` line and exactly one `INVENTORY_ITEMS` entry, so this count is the asset-type count.)

In the `### AWS Services Covered` list, add `Kafka (MSK)` and `OpenSearch` in alphabetical position.

- [ ] **Step 2: Add the new rows to `docs/cli-reference.md`**

In the first table (~line 186), after the `--containers` row:

```markdown
| `--log-groups` | CloudWatch Logs Log Groups | `log-group` |
| `--log-destinations` | CloudWatch Logs Destinations | `log-destination` |
| `--vpc-flow-logs` | VPC Flow Logs | `vpc-flow-log` |
| `--resolver-query-logs` | Route 53 Resolver Query Log Configs | `resolver-query-log` |
| `--opensearch` | OpenSearch Domains | `opensearch-domain` |
| `--msk` | MSK (Kafka) Clusters | `msk-cluster` |
```

In the second table (~line 635), after the `--containers` row:

```markdown
| `--log-groups` | `log-group` | CloudWatch Logs log groups |
| `--log-destinations` | `log-destination` | CloudWatch Logs cross-account destinations |
| `--vpc-flow-logs` | `vpc-flow-log` | VPC flow logs (VPC, subnet, and ENI scope) |
| `--resolver-query-logs` | `resolver-query-log` | Route 53 Resolver DNS query log configs |
| `--opensearch` | `opensearch-domain` | OpenSearch Service domains |
| `--msk` | `msk-cluster` | MSK clusters (provisioned + serverless) |
```

Also fix the two "all 8 types" phrases near line 180 and line 631 to "all types".

- [ ] **Step 3: Update `README.md:307`**

Replace the `--inventory-types` row's example list with one that includes the log services:

```markdown
| `--inventory-types` | all types | Comma-separated asset-type keys, e.g. `kms-key,s3-bucket,ec2-instance,log-group,vpc-flow-log,opensearch-domain,msk-cluster`. See `INVENTORY_ITEMS` in `src/inventory_core.rs` for the full list |
```

- [ ] **Step 4: Append §25–§30 to the mapping spec**

Copy the six mapping tables from the **Field Mapping Spec (§25–§30)** section of this plan verbatim into `docs/superpowers/plans/2026-07-17-aws-inventory-expansion-mapping.md`, under a new `### Logging services` heading placed after the `### Security services ...` section, so the `mapping doc §NN` comments in `logging.rs` and `log_analytics.rs` resolve.

- [ ] **Step 5: Commit**

```bash
git add evidence-list.md docs/cli-reference.md README.md docs/superpowers/plans/2026-07-17-aws-inventory-expansion-mapping.md
git commit -m "docs(inventory): document log-service asset types"
```

---

## Post-implementation verification

- [ ] `cargo fmt --check` clean
- [ ] Scoped clippy check prints only the two documented baseline lines (see Global Constraints) — no new lint in any edited file
- [ ] `cargo build --release` succeeds
- [ ] `cargo test` still passes (no tests added, but the workspace must stay green)
- [ ] `cargo run -- --inventory --help` lists all six new flags
- [ ] TUI check: `cargo run`, choose the Inventory feature, confirm the six new labels appear in the asset-type picker and can be selected
- [ ] With credentials: `cargo run -- --inventory --log-groups --vpc-flow-logs --opensearch --msk --region us-east-1` writes an `AWS_Inventory-*.csv` whose `Asset Type` column contains the new labels and whose `Comments` keys appear in the documented order
