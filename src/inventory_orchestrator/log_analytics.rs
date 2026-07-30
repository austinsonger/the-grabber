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
