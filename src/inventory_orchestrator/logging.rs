use std::collections::HashMap;

use anyhow::{Context, Result};
use aws_sdk_cloudwatchlogs::Client as CloudWatchLogsClient;
use aws_sdk_ec2::Client as Ec2Client;

use super::network_fabric::{ec2_arn, fabric_function};
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
/// serve both the flow-log and MSK call sites without adding a direct
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
