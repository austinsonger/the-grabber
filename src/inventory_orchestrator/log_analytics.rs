use std::collections::HashMap;

use anyhow::{Context, Result};
use aws_sdk_kafka::types::{ClientAuthentication, Cluster, LoggingInfo};
use aws_sdk_kafka::Client as KafkaClient;
use aws_sdk_opensearch::types::DomainStatus;
use aws_sdk_opensearch::Client as OpenSearchClient;

use super::logging::smithy_dt_to_rfc3339;
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
                    cfg.dedicated_master_enabled().unwrap_or(false).to_string(),
                    cfg.zone_awareness_enabled().unwrap_or(false).to_string(),
                ),
                None => (String::new(), String::new(), String::new(), String::new()),
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
/// `if let` + `if` version trips `clippy::collapsible_if`.
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
