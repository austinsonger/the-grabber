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
