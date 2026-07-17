use std::collections::HashMap;

use anyhow::{Context, Result};
use aws_sdk_eventbridge::Client as EventBridgeClient;
use aws_sdk_firehose::Client as FirehoseClient;
use aws_sdk_kinesis::Client as KinesisClient;
use aws_sdk_sns::Client as SnsClient;
use aws_sdk_sqs::types::QueueAttributeName;
use aws_sdk_sqs::Client as SqsClient;

use crate::inventory_core::RowBuilder;

// ---------------------------------------------------------------------------
// SNS Topics — mapping doc §8
// ---------------------------------------------------------------------------

/// Tag-first Function-column derivation for SNS topics. Same Purpose/App/
/// Role/Function convention as `storage::function_from_ec2_tags`; SNS's
/// `Tag::key()`/`value()` both return plain `&str` (not `Option<&str>`),
/// matching the EFS/DynamoDB accessor shape.
fn function_from_sns_tags(tags: &[aws_sdk_sns::types::Tag]) -> String {
    tags.iter()
        .find(|t| {
            matches!(
                t.key(),
                "Purpose" | "App" | "Role" | "Function" | "purpose" | "app" | "role"
            )
        })
        .map(|t| t.value())
        .unwrap_or("")
        .to_string()
}

pub(super) async fn collect_sns_topics(client: &SnsClient, region: &str) -> Result<Vec<Vec<String>>> {
    let mut rows = Vec::new();
    let mut next_token: Option<String> = None;

    loop {
        let mut req = client.list_topics();
        if let Some(ref t) = next_token {
            req = req.next_token(t);
        }
        let resp = req.send().await.context("SNS list_topics")?;

        for topic in resp.topics() {
            let Some(arn) = topic.topic_arn() else {
                continue;
            };

            let attrs = match client.get_topic_attributes().topic_arn(arn).send().await {
                Ok(r) => r.attributes().cloned().unwrap_or_default(),
                Err(e) => {
                    eprintln!("sns get_topic_attributes failed for {arn}: {e}");
                    HashMap::new()
                }
            };
            let get = |k: &str| attrs.get(k).cloned().unwrap_or_default();

            let display_name = get("DisplayName");
            let subscriptions_confirmed = get("SubscriptionsConfirmed");
            let subscriptions_pending = get("SubscriptionsPending");
            let kms_master_key_id = get("KmsMasterKeyId");
            let content_based_dedup = get("ContentBasedDeduplication");
            let fifo_topic = get("FifoTopic");
            let tracing_config = get("TracingConfig");
            let delivery_policy_summary: String = get("DeliveryPolicy").chars().take(100).collect();
            let policy = get("Policy");

            let is_public = policy_looks_public(&policy);
            let is_fifo = arn.ends_with(".fifo");
            let asset_type = if is_fifo {
                "SNS Topic (FIFO)".to_string()
            } else {
                "SNS Topic".to_string()
            };

            // list_tags_for_resource may fail (e.g. missing permission) —
            // soft-fail to an empty Function rather than aborting the topic.
            let function = match client.list_tags_for_resource().resource_arn(arn).send().await {
                Ok(r) => function_from_sns_tags(r.tags()),
                Err(e) => {
                    eprintln!("sns list_tags_for_resource failed for {arn}: {e}");
                    String::new()
                }
            };

            let comments = format!(
                "DisplayName: {display_name} | SubscriptionsConfirmed: {subscriptions_confirmed} | \
                 SubscriptionsPending: {subscriptions_pending} | KmsMasterKeyId: {kms_master_key_id} | \
                 ContentBasedDeduplication: {content_based_dedup} | FifoTopic: {fifo_topic} | \
                 TracingConfig: {tracing_config} | DeliveryPolicy: {delivery_policy_summary}"
            );

            rows.push(
                RowBuilder::new()
                    .unique_id(arn)
                    .virtual_flag("Yes")
                    .public(if is_public { "Yes" } else { "No" })
                    .location(region)
                    .asset_type(asset_type)
                    .sw_vendor("Amazon Web Services")
                    .sw_name_ver("Amazon SNS")
                    .function(function)
                    .comments(comments)
                    .build(),
            );
        }

        next_token = resp.next_token().map(|s| s.to_string());
        if next_token.is_none() {
            break;
        }
    }

    Ok(rows)
}

// ---------------------------------------------------------------------------
// SQS Queues — mapping doc §9
// ---------------------------------------------------------------------------

/// Tag-first Function-column derivation for SQS queues. `list_queue_tags`
/// returns tags as a plain `HashMap<String, String>` (no dedicated `Tag`
/// type) — same shape as `apigateway::function_from_apigw_tags` — so lookups
/// are direct key gets rather than an iterator search.
fn function_from_sqs_tags(tags: Option<&HashMap<String, String>>) -> String {
    let Some(tags) = tags else {
        return String::new();
    };
    ["Purpose", "App", "Role", "Function", "purpose", "app", "role"]
        .iter()
        .find_map(|k| tags.get(*k).cloned())
        .unwrap_or_default()
}

pub(super) async fn collect_sqs_queues(client: &SqsClient, region: &str) -> Result<Vec<Vec<String>>> {
    let mut rows = Vec::new();
    let mut next_token: Option<String> = None;

    loop {
        let mut req = client.list_queues();
        if let Some(ref t) = next_token {
            req = req.next_token(t);
        }
        let resp = req.send().await.context("SQS list_queues")?;

        for url in resp.queue_urls() {
            let attrs = match client
                .get_queue_attributes()
                .queue_url(url)
                .attribute_names(QueueAttributeName::All)
                .send()
                .await
            {
                Ok(r) => r.attributes().cloned().unwrap_or_default(),
                Err(e) => {
                    eprintln!("sqs get_queue_attributes failed for {url}: {e}");
                    HashMap::new()
                }
            };
            let get = |k: QueueAttributeName| attrs.get(&k).cloned().unwrap_or_default();

            let arn = get(QueueAttributeName::QueueArn);
            if arn.is_empty() {
                // No ARN in attributes (soft-fail above, or an oddly-shaped
                // response) — nothing to key the row on, skip it.
                eprintln!("sqs queue {url} has no QueueArn attribute; skipping");
                continue;
            }

            let policy = get(QueueAttributeName::Policy);
            let kms_master_key_id = get(QueueAttributeName::KmsMasterKeyId);
            let sqs_managed_sse_enabled = get(QueueAttributeName::SqsManagedSseEnabled);
            let visibility_timeout = get(QueueAttributeName::VisibilityTimeout);
            let message_retention_period = get(QueueAttributeName::MessageRetentionPeriod);
            let maximum_message_size = get(QueueAttributeName::MaximumMessageSize);
            let delay_seconds = get(QueueAttributeName::DelaySeconds);
            let content_based_dedup = get(QueueAttributeName::ContentBasedDeduplication);
            let fifo_queue = get(QueueAttributeName::FifoQueue);
            let redrive_policy = get(QueueAttributeName::RedrivePolicy);

            // Best-effort parse of the nested JSON string; leave empty on
            // any parse failure or missing key rather than propagating.
            let dlq_arn = if redrive_policy.is_empty() {
                String::new()
            } else {
                serde_json::from_str::<serde_json::Value>(&redrive_policy)
                    .ok()
                    .and_then(|v| {
                        v.get("deadLetterTargetArn")
                            .and_then(|x| x.as_str())
                            .map(str::to_string)
                    })
                    .unwrap_or_default()
            };

            let is_public = policy_looks_public(&policy);
            let is_fifo = url.ends_with(".fifo");
            let asset_type = if is_fifo { "SQS Queue (FIFO)" } else { "SQS Queue" };

            let function = match client.list_queue_tags().queue_url(url).send().await {
                Ok(r) => function_from_sqs_tags(r.tags()),
                Err(e) => {
                    eprintln!("sqs list_queue_tags failed for {url}: {e}");
                    String::new()
                }
            };

            let comments = format!(
                "QueueUrl: {url} | KmsMasterKeyId: {kms_master_key_id} | \
                 SqsManagedSseEnabled: {sqs_managed_sse_enabled} | VisibilityTimeout: {visibility_timeout} | \
                 MessageRetentionPeriod: {message_retention_period} | \
                 MaximumMessageSize: {maximum_message_size} | DelaySeconds: {delay_seconds} | \
                 ContentBasedDeduplication: {content_based_dedup} | FifoQueue: {fifo_queue} | \
                 RedrivePolicy.deadLetterTargetArn: {dlq_arn}"
            );

            rows.push(
                RowBuilder::new()
                    .unique_id(&arn)
                    .virtual_flag("Yes")
                    .public(if is_public { "Yes" } else { "No" })
                    .location(region)
                    .asset_type(asset_type)
                    .sw_vendor("Amazon Web Services")
                    .sw_name_ver("Amazon SQS")
                    .function(function)
                    .comments(comments)
                    .build(),
            );
        }

        next_token = resp.next_token().map(|s| s.to_string());
        if next_token.is_none() {
            break;
        }
    }

    Ok(rows)
}

// ---------------------------------------------------------------------------
// Kinesis Data Streams — mapping doc §10
// ---------------------------------------------------------------------------

/// Tag-first Function-column derivation for Kinesis Data Streams. Kinesis's
/// `Tag::key()` returns `&str` and `Tag::value()` returns `Option<&str>` —
/// same convention as `storage::function_from_ec2_tags`.
fn function_from_kinesis_tags(tags: &[aws_sdk_kinesis::types::Tag]) -> String {
    tags.iter()
        .find(|t| {
            matches!(
                t.key(),
                "Purpose" | "App" | "Role" | "Function" | "purpose" | "app" | "role"
            )
        })
        .and_then(|t| t.value())
        .unwrap_or("")
        .to_string()
}

pub(super) async fn collect_kinesis_streams(
    client: &KinesisClient,
    region: &str,
) -> Result<Vec<Vec<String>>> {
    let mut rows = Vec::new();
    let mut exclusive_start: Option<String> = None;

    loop {
        let mut req = client.list_streams();
        if let Some(ref s) = exclusive_start {
            req = req.exclusive_start_stream_name(s);
        }
        let resp = req.send().await.context("Kinesis list_streams")?;

        for name in resp.stream_names() {
            let summary = match client.describe_stream_summary().stream_name(name).send().await {
                Ok(r) => r.stream_description_summary().cloned(),
                Err(e) => {
                    eprintln!("kinesis describe_stream_summary failed for {name}: {e}");
                    None
                }
            };
            let Some(summary) = summary else {
                continue;
            };

            let arn = summary.stream_arn().to_string();
            let stream_status = summary.stream_status().as_str().to_string();
            let stream_mode = summary
                .stream_mode_details()
                .map(|m| m.stream_mode().as_str())
                .unwrap_or("")
                .to_string();
            let open_shard_count = summary.open_shard_count().to_string();
            let retention_hours = summary.retention_period_hours().to_string();
            let encryption_type = summary
                .encryption_type()
                .map(|e| e.as_str())
                .unwrap_or("")
                .to_string();
            let kms_key_id = summary.key_id().unwrap_or("").to_string();
            let enhanced_monitoring: String = summary
                .enhanced_monitoring()
                .iter()
                .flat_map(|m| m.shard_level_metrics())
                .map(|m| m.as_str())
                .collect::<Vec<_>>()
                .join(", ");

            let function = match client.list_tags_for_stream().stream_name(name).send().await {
                Ok(r) => function_from_kinesis_tags(r.tags()),
                Err(e) => {
                    eprintln!("kinesis list_tags_for_stream failed for {name}: {e}");
                    String::new()
                }
            };

            let comments = format!(
                "StreamStatus: {stream_status} | StreamMode: {stream_mode} | \
                 OpenShardCount: {open_shard_count} | RetentionPeriodHours: {retention_hours} | \
                 EncryptionType: {encryption_type} | KmsKeyId: {kms_key_id} | \
                 EnhancedMonitoring: {enhanced_monitoring}"
            );

            rows.push(
                RowBuilder::new()
                    .unique_id(&arn)
                    .virtual_flag("Yes")
                    .public("No")
                    .location(region)
                    .asset_type("Kinesis Data Stream")
                    .sw_vendor("Amazon Web Services")
                    .sw_name_ver("Amazon Kinesis Data Streams")
                    .function(function)
                    .comments(comments)
                    .build(),
            );
        }

        exclusive_start = if resp.has_more_streams() {
            resp.stream_names().last().cloned()
        } else {
            None
        };
        if exclusive_start.is_none() {
            break;
        }
    }

    Ok(rows)
}

// ---------------------------------------------------------------------------
// Kinesis Firehose Delivery Streams — mapping doc §11
// ---------------------------------------------------------------------------

/// Tag-first Function-column derivation for Firehose delivery streams. Same
/// convention as `function_from_kinesis_tags`; Firehose's `Tag::key()`/
/// `value()` accessor shapes match Kinesis's exactly.
fn function_from_firehose_tags(tags: &[aws_sdk_firehose::types::Tag]) -> String {
    tags.iter()
        .find(|t| {
            matches!(
                t.key(),
                "Purpose" | "App" | "Role" | "Function" | "purpose" | "app" | "role"
            )
        })
        .and_then(|t| t.value())
        .unwrap_or("")
        .to_string()
}

/// Walks a Firehose destination's flavour-specific description struct (only
/// one is ever populated per destination) and returns
/// `(DestinationType, DestinationArn, CloudWatchLoggingEnabled)`. Checked in
/// mapping-doc §11 order: S3, Redshift, Elasticsearch, HTTP endpoint,
/// OpenSearch Service, Splunk, Snowflake. Falls through to all-empty when
/// none of these match (e.g. a destination flavour added after this SDK
/// version, or Iceberg/OpenSearch-Serverless which the mapping doc doesn't
/// enumerate).
fn firehose_destination_info(
    dest: &aws_sdk_firehose::types::DestinationDescription,
) -> (String, String, String) {
    fn cw_logging(opts: Option<&aws_sdk_firehose::types::CloudWatchLoggingOptions>) -> String {
        opts.and_then(|c| c.enabled())
            .map(|b| b.to_string())
            .unwrap_or_default()
    }

    if let Some(s3) = dest.s3_destination_description() {
        return (
            "S3".to_string(),
            s3.bucket_arn().to_string(),
            cw_logging(s3.cloud_watch_logging_options()),
        );
    }
    if let Some(rs) = dest.redshift_destination_description() {
        return (
            "Redshift".to_string(),
            rs.cluster_jdbcurl().to_string(),
            cw_logging(rs.cloud_watch_logging_options()),
        );
    }
    if let Some(es) = dest.elasticsearch_destination_description() {
        return (
            "Elasticsearch".to_string(),
            es.domain_arn().unwrap_or("").to_string(),
            cw_logging(es.cloud_watch_logging_options()),
        );
    }
    if let Some(http) = dest.http_endpoint_destination_description() {
        let url = http
            .endpoint_configuration()
            .and_then(|e| e.url())
            .unwrap_or("")
            .to_string();
        return ("HTTP endpoint".to_string(), url, cw_logging(http.cloud_watch_logging_options()));
    }
    if let Some(os) = dest.amazonopensearchservice_destination_description() {
        return (
            "OpenSearch Service".to_string(),
            os.domain_arn().unwrap_or("").to_string(),
            cw_logging(os.cloud_watch_logging_options()),
        );
    }
    if let Some(sp) = dest.splunk_destination_description() {
        return (
            "Splunk".to_string(),
            sp.hec_endpoint().unwrap_or("").to_string(),
            cw_logging(sp.cloud_watch_logging_options()),
        );
    }
    if let Some(sf) = dest.snowflake_destination_description() {
        return (
            "Snowflake".to_string(),
            sf.account_url().unwrap_or("").to_string(),
            cw_logging(sf.cloud_watch_logging_options()),
        );
    }

    (String::new(), String::new(), String::new())
}

pub(super) async fn collect_firehose_streams(
    client: &FirehoseClient,
    region: &str,
) -> Result<Vec<Vec<String>>> {
    let mut rows = Vec::new();
    let mut exclusive_start: Option<String> = None;

    loop {
        let mut req = client.list_delivery_streams();
        if let Some(ref s) = exclusive_start {
            req = req.exclusive_start_delivery_stream_name(s);
        }
        let resp = req.send().await.context("Firehose list_delivery_streams")?;

        for name in resp.delivery_stream_names() {
            let description = match client
                .describe_delivery_stream()
                .delivery_stream_name(name)
                .send()
                .await
            {
                Ok(r) => r.delivery_stream_description().cloned(),
                Err(e) => {
                    eprintln!("firehose describe_delivery_stream failed for {name}: {e}");
                    None
                }
            };
            let Some(desc) = description else {
                continue;
            };

            let arn = desc.delivery_stream_arn().to_string();
            let status = desc.delivery_stream_status().as_str().to_string();
            let stream_type = desc.delivery_stream_type().as_str().to_string();
            let source_kinesis_arn = desc
                .source()
                .and_then(|s| s.kinesis_stream_source_description())
                .and_then(|k| k.kinesis_stream_arn())
                .unwrap_or("")
                .to_string();
            let encryption_kms_key_arn = desc
                .delivery_stream_encryption_configuration()
                .and_then(|e| e.key_arn())
                .unwrap_or("")
                .to_string();

            let (destination_type, destination_arn, cw_logging_enabled) = desc
                .destinations()
                .first()
                .map(firehose_destination_info)
                .unwrap_or_default();

            let function = match client
                .list_tags_for_delivery_stream()
                .delivery_stream_name(name)
                .send()
                .await
            {
                Ok(r) => function_from_firehose_tags(r.tags()),
                Err(e) => {
                    eprintln!("firehose list_tags_for_delivery_stream failed for {name}: {e}");
                    String::new()
                }
            };

            let comments = format!(
                "DeliveryStreamStatus: {status} | DeliveryStreamType: {stream_type} | \
                 SourceKinesisArn: {source_kinesis_arn} | DestinationType: {destination_type} | \
                 DestinationArn: {destination_arn} | EncryptionKmsKeyArn: {encryption_kms_key_arn} | \
                 CloudWatchLoggingEnabled: {cw_logging_enabled}"
            );

            rows.push(
                RowBuilder::new()
                    .unique_id(&arn)
                    .virtual_flag("Yes")
                    .public("No")
                    .location(region)
                    .asset_type("Kinesis Firehose Delivery Stream")
                    .sw_vendor("Amazon Web Services")
                    .sw_name_ver("Amazon Kinesis Data Firehose")
                    .function(function)
                    .comments(comments)
                    .build(),
            );
        }

        exclusive_start = if resp.has_more_delivery_streams() {
            resp.delivery_stream_names().last().cloned()
        } else {
            None
        };
        if exclusive_start.is_none() {
            break;
        }
    }

    Ok(rows)
}

// ---------------------------------------------------------------------------
// EventBridge — mapping doc §12 (Bus) + §13 (Rule)
// ---------------------------------------------------------------------------

/// Tag-first Function-column derivation for EventBridge buses. EventBridge's
/// `Tag::key()`/`value()` both return plain `&str` — same shape as
/// `function_from_sns_tags`.
fn function_from_eventbridge_tags(tags: &[aws_sdk_eventbridge::types::Tag]) -> String {
    tags.iter()
        .find(|t| {
            matches!(
                t.key(),
                "Purpose" | "App" | "Role" | "Function" | "purpose" | "app" | "role"
            )
        })
        .map(|t| t.value())
        .unwrap_or("")
        .to_string()
}

pub(super) async fn collect_eventbridge(
    client: &EventBridgeClient,
    region: &str,
) -> Result<Vec<Vec<String>>> {
    let mut rows = Vec::new();
    rows.extend(collect_eventbridge_buses(client, region).await.unwrap_or_default());
    rows.extend(collect_eventbridge_rules(client, region).await.unwrap_or_default());
    Ok(rows)
}

async fn collect_eventbridge_buses(
    client: &EventBridgeClient,
    region: &str,
) -> Result<Vec<Vec<String>>> {
    let mut rows = Vec::new();
    let mut next_token: Option<String> = None;

    loop {
        let mut req = client.list_event_buses();
        if let Some(ref t) = next_token {
            req = req.next_token(t);
        }
        let resp = req.send().await.context("EventBridge list_event_buses")?;

        for bus in resp.event_buses() {
            let Some(arn) = bus.arn() else {
                continue;
            };
            let name = bus.name().unwrap_or("").to_string();
            let policy = bus.policy().unwrap_or("").to_string();
            let is_public = policy_looks_public(&policy);
            let policy_summary: String = policy.chars().take(200).collect();

            // `list_event_buses` doesn't return KmsKeyIdentifier or
            // DeadLetterConfig (only `describe_event_bus` does) — one extra
            // soft-failing call per bus, same pattern as
            // `data_services::collect_redshift_clusters`'s secondary calls.
            let (kms_key_identifier, dead_letter_arn) =
                match client.describe_event_bus().name(&name).send().await {
                    Ok(r) => (
                        r.kms_key_identifier().unwrap_or("").to_string(),
                        r.dead_letter_config()
                            .and_then(|d| d.arn())
                            .unwrap_or("")
                            .to_string(),
                    ),
                    Err(e) => {
                        eprintln!("eventbridge describe_event_bus failed for {name}: {e}");
                        (String::new(), String::new())
                    }
                };

            let function = match client.list_tags_for_resource().resource_arn(arn).send().await {
                Ok(r) => function_from_eventbridge_tags(r.tags()),
                Err(e) => {
                    eprintln!("eventbridge list_tags_for_resource failed for {arn}: {e}");
                    String::new()
                }
            };

            // Buses have no ENABLED/DISABLED concept in the EventBridge API
            // (only Rules do) — State is left empty per the "not applicable"
            // convention rather than guessed.
            let comments = format!(
                "Name: {name} | PolicySummary: {policy_summary} | \
                 KmsKeyIdentifier: {kms_key_identifier} | DeadLetterConfig.Arn: {dead_letter_arn} | \
                 State: "
            );

            rows.push(
                RowBuilder::new()
                    .unique_id(arn)
                    .virtual_flag("Yes")
                    .public(if is_public { "Yes" } else { "No" })
                    .location(region)
                    .asset_type("EventBridge Event Bus")
                    .sw_vendor("Amazon Web Services")
                    .sw_name_ver("Amazon EventBridge")
                    .function(function)
                    .comments(comments)
                    .build(),
            );
        }

        next_token = resp.next_token().map(|s| s.to_string());
        if next_token.is_none() {
            break;
        }
    }

    Ok(rows)
}

/// Lists every event bus name in the region, paged via `next_token`.
/// Soft-fails to an empty list on error (logged) — used only to drive the
/// per-bus rule listing below, so a failure here just means no rules get
/// enumerated rather than aborting the whole collector.
async fn list_event_bus_names(client: &EventBridgeClient) -> Vec<String> {
    let mut names = Vec::new();
    let mut next_token: Option<String> = None;

    loop {
        let mut req = client.list_event_buses();
        if let Some(ref t) = next_token {
            req = req.next_token(t);
        }
        let resp = match req.send().await {
            Ok(r) => r,
            Err(e) => {
                eprintln!("eventbridge list_event_buses (for rules) failed: {e}");
                break;
            }
        };

        for bus in resp.event_buses() {
            if let Some(name) = bus.name() {
                names.push(name.to_string());
            }
        }

        next_token = resp.next_token().map(|s| s.to_string());
        if next_token.is_none() {
            break;
        }
    }

    names
}

async fn collect_eventbridge_rules(
    client: &EventBridgeClient,
    region: &str,
) -> Result<Vec<Vec<String>>> {
    let mut rows = Vec::new();
    let bus_names = list_event_bus_names(client).await;

    for bus_name in bus_names {
        let mut next_token: Option<String> = None;

        loop {
            let mut req = client.list_rules().event_bus_name(&bus_name);
            if let Some(ref t) = next_token {
                req = req.next_token(t);
            }
            let resp = match req.send().await {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("eventbridge list_rules failed for bus {bus_name}: {e}");
                    break;
                }
            };

            for rule in resp.rules() {
                let Some(arn) = rule.arn() else {
                    continue;
                };
                let name = rule.name().unwrap_or("").to_string();
                let state = rule.state().map(|s| s.as_str()).unwrap_or("").to_string();
                let schedule_expression = rule.schedule_expression().unwrap_or("").to_string();
                let event_pattern: String =
                    rule.event_pattern().unwrap_or("").chars().take(200).collect();

                let targets = match client
                    .list_targets_by_rule()
                    .rule(&name)
                    .event_bus_name(&bus_name)
                    .send()
                    .await
                {
                    Ok(r) => r.targets().to_vec(),
                    Err(e) => {
                        eprintln!("eventbridge list_targets_by_rule failed for rule {name}: {e}");
                        Vec::new()
                    }
                };
                let target_count = targets.len();
                let target_arns = targets.iter().map(|t| t.arn()).collect::<Vec<_>>().join(", ");

                let function = match client.list_tags_for_resource().resource_arn(arn).send().await
                {
                    Ok(r) => {
                        let tag_function = function_from_eventbridge_tags(r.tags());
                        if tag_function.is_empty() {
                            rule.description().unwrap_or("").to_string()
                        } else {
                            tag_function
                        }
                    }
                    Err(e) => {
                        eprintln!("eventbridge list_tags_for_resource failed for {arn}: {e}");
                        rule.description().unwrap_or("").to_string()
                    }
                };

                let comments = format!(
                    "BusName: {bus_name} | State: {state} | ScheduleExpression: {schedule_expression} | \
                     EventPattern: {event_pattern} | TargetCount: {target_count} | \
                     TargetArns: {target_arns}"
                );

                rows.push(
                    RowBuilder::new()
                        .unique_id(arn)
                        .virtual_flag("Yes")
                        .public("No")
                        .location(region)
                        .asset_type("EventBridge Rule")
                        .sw_vendor("Amazon Web Services")
                        .sw_name_ver("Amazon EventBridge")
                        .function(function)
                        .comments(comments)
                        .build(),
                );
            }

            next_token = resp.next_token().map(|s| s.to_string());
            if next_token.is_none() {
                break;
            }
        }
    }

    Ok(rows)
}

// ---------------------------------------------------------------------------
// Shared: resource-policy public-detection
// ---------------------------------------------------------------------------

/// Heuristic: an IAM resource policy is "public" if any Allow statement has
/// Principal="*" (or Principal.AWS="*") and no Condition narrowing it. Used
/// by SNS/SQS/EventBridge Bus for the Public column. Conservative — a
/// policy with a Condition is treated as non-public even if the Condition
/// doesn't actually narrow access.
fn policy_looks_public(policy_json: &str) -> bool {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(policy_json) else { return false; };
    let Some(stmts) = v.get("Statement").and_then(|s| s.as_array()) else { return false; };
    for stmt in stmts {
        if stmt.get("Effect").and_then(|e| e.as_str()) != Some("Allow") { continue; }
        let principal = stmt.get("Principal");
        let is_star = match principal {
            Some(serde_json::Value::String(s)) => s == "*",
            Some(serde_json::Value::Object(o)) => o.values().any(|v| {
                v.as_str() == Some("*")
                    || v.as_array().is_some_and(|a| a.iter().any(|x| x.as_str() == Some("*")))
            }),
            _ => false,
        };
        let has_condition = stmt.get("Condition").is_some();
        if is_star && !has_condition {
            return true;
        }
    }
    false
}
