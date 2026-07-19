use anyhow::{Context, Result};
use aws_sdk_cloudtrail::Client as CloudTrailClient;
use aws_sdk_config::Client as ConfigClient;
use aws_sdk_guardduty::Client as GuardDutyClient;
use aws_sdk_securityhub::Client as SecurityHubClient;
use aws_sdk_wafv2::Client as Wafv2Client;
use std::collections::HashMap;

use crate::inventory_core::RowBuilder;

// ---------------------------------------------------------------------------
// Security Services — mapping doc §20-24
//
// Five independent collectors for account/region-scoped security tooling:
// CloudTrail Trail, Config Recorder, GuardDuty Detector, Security Hub Hub,
// WAF WebACL. Unlike network_fabric.rs these aren't fanned out from one
// entry point — mod.rs calls each collector directly per selected asset key.
// ---------------------------------------------------------------------------

/// Converts an SDK `DateTime` to RFC3339, matching the `dt_to_rfc3339`
/// pattern used for Secrets Manager timestamps in `secrets.rs`. Every AWS
/// SDK crate re-exports the same underlying `aws_smithy_types::DateTime` as
/// `crate::primitives::DateTime` (see e.g. `aws-sdk-cloudtrail/src/primitives.rs`),
/// so borrowing that path here lets this one helper serve both the
/// CloudTrail and Config call sites without depending on `aws-smithy-types`
/// directly (it's only a transitive dependency of this crate).
fn dt_to_rfc3339(dt: Option<&aws_sdk_cloudtrail::primitives::DateTime>) -> String {
    dt.and_then(|d| chrono::DateTime::<chrono::Utc>::from_timestamp(d.secs(), 0))
        .map(|c| c.to_rfc3339())
        .unwrap_or_default()
}

// ---------------------------------------------------------------------------
// CloudTrail Trail — §20
// ---------------------------------------------------------------------------

/// Tag-first Function-column derivation for CloudTrail trails.
/// `Tag::key()`/`value()` return `&str`/`Option<&str>` — same shape as
/// EFS/FSx's tag types in `storage.rs`. Trails have no description field,
/// so unlike Secrets Manager there is no fallback — empty when untagged.
fn function_from_cloudtrail_tags(tags: &[aws_sdk_cloudtrail::types::Tag]) -> String {
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

pub(super) async fn collect_cloudtrail_trails(
    client: &CloudTrailClient,
    region: &str,
) -> Result<Vec<Vec<String>>> {
    let mut rows = Vec::new();

    // `describe_trails` defaults to including "shadow trails" — multi-region
    // trails replicated into every region they cover. Without
    // `include_shadow_trails(false)` an --all-regions run would emit one row
    // per multi-region trail *per region*, all sharing the same trail_arn.
    // Passing `false` restricts each trail to appearing once, in its home
    // region.
    let resp = client
        .describe_trails()
        .include_shadow_trails(false)
        .send()
        .await
        .context("CloudTrail describe_trails")?;

    for trail in resp.trail_list() {
        let Some(trail_arn) = trail.trail_arn() else {
            continue;
        };

        let home_region = trail.home_region().unwrap_or(region);
        let is_multi_region = trail.is_multi_region_trail().unwrap_or(false);
        let location = if is_multi_region {
            format!("{home_region} / MultiRegion")
        } else {
            home_region.to_string()
        };

        let s3_bucket_name = trail.s3_bucket_name().unwrap_or("").to_string();
        let log_file_validation_enabled = trail
            .log_file_validation_enabled()
            .map(|b| b.to_string())
            .unwrap_or_default();
        let kms_key_id = trail.kms_key_id().unwrap_or("").to_string();
        let is_multi_region_trail = trail
            .is_multi_region_trail()
            .map(|b| b.to_string())
            .unwrap_or_default();
        let is_organization_trail = trail
            .is_organization_trail()
            .map(|b| b.to_string())
            .unwrap_or_default();
        let include_global_service_events = trail
            .include_global_service_events()
            .map(|b| b.to_string())
            .unwrap_or_default();
        let has_custom_event_selectors = trail
            .has_custom_event_selectors()
            .map(|b| b.to_string())
            .unwrap_or_default();

        // Per-trail status call — soft-fail so one broken trail doesn't
        // drop the others' rows.
        let (is_logging, latest_delivery_time, latest_notification_time) =
            match client.get_trail_status().name(trail_arn).send().await {
                Ok(status) => (
                    status
                        .is_logging()
                        .map(|b| b.to_string())
                        .unwrap_or_default(),
                    dt_to_rfc3339(status.latest_delivery_time()),
                    dt_to_rfc3339(status.latest_notification_time()),
                ),
                Err(e) => {
                    eprintln!("cloudtrail get_trail_status failed for {trail_arn}: {e:#}");
                    (String::new(), String::new(), String::new())
                }
            };

        // Tags — soft-fail to empty. `list_tags` returns a list keyed by
        // resource id since it accepts a batch of resource ids; we pass a
        // single-element list and pull the matching entry back out.
        let function = match client.list_tags().resource_id_list(trail_arn).send().await {
            Ok(resp) => resp
                .resource_tag_list()
                .iter()
                .find(|rt| rt.resource_id() == Some(trail_arn))
                .map(|rt| function_from_cloudtrail_tags(rt.tags_list()))
                .unwrap_or_default(),
            Err(e) => {
                eprintln!("cloudtrail list_tags failed for {trail_arn}: {e:#}");
                String::new()
            }
        };

        let comments = format!(
            "S3BucketName: {s3_bucket_name} | LogFileValidationEnabled: {log_file_validation_enabled} | \
             KmsKeyId: {kms_key_id} | IsMultiRegionTrail: {is_multi_region_trail} | \
             IsOrganizationTrail: {is_organization_trail} | \
             IncludeGlobalServiceEvents: {include_global_service_events} | \
             HasCustomEventSelectors: {has_custom_event_selectors} | IsLogging: {is_logging} | \
             LatestDeliveryTime: {latest_delivery_time} | LatestNotificationTime: {latest_notification_time}"
        );

        rows.push(
            RowBuilder::new()
                .unique_id(trail_arn)
                .virtual_flag("Yes")
                .public("No")
                .location(location)
                .asset_type("CloudTrail Trail")
                .sw_vendor("Amazon Web Services")
                .sw_name_ver("AWS CloudTrail")
                .vlan_network_id("")
                .function(function)
                .comments(comments)
                .build(),
        );
    }

    Ok(rows)
}

// ---------------------------------------------------------------------------
// Config Recorder — §21
// ---------------------------------------------------------------------------

pub(super) async fn collect_config_recorders(
    client: &ConfigClient,
    account_id: &str,
    region: &str,
) -> Result<Vec<Vec<String>>> {
    let mut rows = Vec::new();

    let recorders_resp = client
        .describe_configuration_recorders()
        .send()
        .await
        .context("Config describe_configuration_recorders")?;

    // Most accounts have at most one recorder; an account with none returns
    // zero rows, which is expected/normal per the mapping spec.
    let statuses: HashMap<String, aws_sdk_config::types::ConfigurationRecorderStatus> = client
        .describe_configuration_recorder_status()
        .send()
        .await
        .map(|resp| {
            resp.configuration_recorders_status()
                .iter()
                .filter_map(|s| s.name().map(|n| (n.to_string(), s.clone())))
                .collect()
        })
        .unwrap_or_else(|e| {
            eprintln!("config describe_configuration_recorder_status failed: {e:#}");
            HashMap::new()
        });

    for recorder in recorders_resp.configuration_recorders() {
        let Some(name) = recorder.name() else {
            continue;
        };

        let unique_id =
            format!("arn:aws:config:{region}:{account_id}:configuration-recorder/{name}");
        let role_arn = recorder.role_arn().unwrap_or("").to_string();
        let (all_supported, include_global_resource_types, resource_type_count) =
            match recorder.recording_group() {
                Some(rg) => (
                    rg.all_supported().to_string(),
                    rg.include_global_resource_types().to_string(),
                    rg.resource_types().len().to_string(),
                ),
                None => (String::new(), String::new(), String::new()),
            };

        let status = statuses.get(name);
        let last_status = status
            .and_then(|s| s.last_status())
            .map(|s| s.as_str())
            .unwrap_or("")
            .to_string();
        let last_status_change_time =
            dt_to_rfc3339(status.and_then(|s| s.last_status_change_time()));
        let last_error_code = status
            .and_then(|s| s.last_error_code())
            .unwrap_or("")
            .to_string();
        let last_error_message = status
            .and_then(|s| s.last_error_message())
            .unwrap_or("")
            .to_string();
        let recording = status
            .map(|s| s.recording().to_string())
            .unwrap_or_default();

        let comments = format!(
            "RoleArn: {role_arn} | AllSupported: {all_supported} | \
             IncludeGlobalResourceTypes: {include_global_resource_types} | \
             ResourceTypeCount: {resource_type_count} | LastStatus: {last_status} | \
             LastStatusChangeTime: {last_status_change_time} | LastErrorCode: {last_error_code} | \
             LastErrorMessage: {last_error_message} | Recording: {recording}"
        );

        rows.push(
            RowBuilder::new()
                .unique_id(unique_id)
                .virtual_flag("Yes")
                .public("No")
                .location(region)
                .asset_type("Config Recorder")
                .sw_vendor("Amazon Web Services")
                .sw_name_ver("AWS Config")
                .vlan_network_id("")
                .function("")
                .comments(comments)
                .build(),
        );
    }

    Ok(rows)
}

// ---------------------------------------------------------------------------
// GuardDuty Detector — §22
// ---------------------------------------------------------------------------

/// Tag-first Function-column derivation for GuardDuty detectors.
/// `get_detector` returns tags as a plain `HashMap<String, String>` (no
/// dedicated `Tag` type) — same shape as `messaging::function_from_sqs_tags`
/// / `apigateway::function_from_apigw_tags`.
fn function_from_guardduty_tags(tags: Option<&HashMap<String, String>>) -> String {
    let Some(tags) = tags else {
        return String::new();
    };
    [
        "Purpose", "App", "Role", "Function", "purpose", "app", "role",
    ]
    .iter()
    .find_map(|k| tags.get(*k).cloned())
    .unwrap_or_default()
}

/// Summarizes the legacy per-source `DataSources` block as
/// `cloudtrail=ENABLED,dnslogs=ENABLED,flowlogs=DISABLED,...` — only the
/// sub-fields the SDK actually returns are included.
fn summarize_data_sources(
    ds: Option<&aws_sdk_guardduty::types::DataSourceConfigurationsResult>,
) -> String {
    let Some(ds) = ds else {
        return String::new();
    };

    let mut parts = Vec::new();
    if let Some(s) = ds.cloud_trail().and_then(|c| c.status()) {
        parts.push(format!("cloudtrail={}", s.as_str()));
    }
    if let Some(s) = ds.dns_logs().and_then(|c| c.status()) {
        parts.push(format!("dnslogs={}", s.as_str()));
    }
    if let Some(s) = ds.flow_logs().and_then(|c| c.status()) {
        parts.push(format!("flowlogs={}", s.as_str()));
    }
    if let Some(s) = ds.s3_logs().and_then(|c| c.status()) {
        parts.push(format!("s3logs={}", s.as_str()));
    }
    if let Some(s) = ds
        .kubernetes()
        .and_then(|k| k.audit_logs())
        .and_then(|a| a.status())
    {
        parts.push(format!("k8saudit={}", s.as_str()));
    }
    parts.join(",")
}

/// Comma-joins the newer `features[]` block as `name=status` pairs.
fn summarize_features(
    features: &[aws_sdk_guardduty::types::DetectorFeatureConfigurationResult],
) -> String {
    features
        .iter()
        .filter_map(|f| {
            let name = f.name()?.as_str();
            let status = f.status()?.as_str();
            Some(format!("{name}={status}"))
        })
        .collect::<Vec<_>>()
        .join(",")
}

pub(super) async fn collect_guardduty_detectors(
    client: &GuardDutyClient,
    account_id: &str,
    region: &str,
) -> Result<Vec<Vec<String>>> {
    let mut rows = Vec::new();
    let mut next_token: Option<String> = None;

    loop {
        let mut req = client.list_detectors();
        if let Some(ref t) = next_token {
            req = req.next_token(t);
        }
        let resp = req.send().await.context("GuardDuty list_detectors")?;

        for id in resp.detector_ids() {
            let detector = match client.get_detector().detector_id(id).send().await {
                Ok(d) => d,
                Err(e) => {
                    eprintln!("guardduty get_detector failed for {id}: {e:#}");
                    continue;
                }
            };

            let unique_id = format!("arn:aws:guardduty:{region}:{account_id}:detector/{id}");
            let status = detector
                .status()
                .map(|s| s.as_str())
                .unwrap_or("")
                .to_string();
            let service_role = detector.service_role().unwrap_or("").to_string();
            let finding_publishing_frequency = detector
                .finding_publishing_frequency()
                .map(|f| f.as_str())
                .unwrap_or("")
                .to_string();
            let data_sources = summarize_data_sources(detector.data_sources());
            let features = summarize_features(detector.features());
            let function = function_from_guardduty_tags(detector.tags());

            let member_accounts_count = {
                let mut count = 0usize;
                let mut member_next_token: Option<String> = None;
                let mut failed = false;
                loop {
                    let mut mreq = client.list_members().detector_id(id);
                    if let Some(ref t) = member_next_token {
                        mreq = mreq.next_token(t);
                    }
                    match mreq.send().await {
                        Ok(mresp) => {
                            count += mresp.members().len();
                            member_next_token = mresp.next_token().map(|s| s.to_string());
                            if member_next_token.is_none() {
                                break;
                            }
                        }
                        Err(e) => {
                            eprintln!("guardduty list_members failed for {id}: {e:#}");
                            failed = true;
                            break;
                        }
                    }
                }
                if failed {
                    String::new()
                } else {
                    count.to_string()
                }
            };

            let comments = format!(
                "Status: {status} | ServiceRole: {service_role} | \
                 FindingPublishingFrequency: {finding_publishing_frequency} | \
                 DataSources: {data_sources} | Features: {features} | \
                 MemberAccountsCount: {member_accounts_count}"
            );

            rows.push(
                RowBuilder::new()
                    .unique_id(unique_id)
                    .virtual_flag("Yes")
                    .public("No")
                    .location(region)
                    .asset_type("GuardDuty Detector")
                    .sw_vendor("Amazon Web Services")
                    .sw_name_ver("Amazon GuardDuty")
                    .vlan_network_id("")
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
// Security Hub Hub — §23
// ---------------------------------------------------------------------------

pub(super) async fn collect_securityhub_hubs(
    client: &SecurityHubClient,
    region: &str,
) -> Result<Vec<Vec<String>>> {
    // Security Hub not being enabled in a region is the common case, not an
    // error — `describe_hub` returns `InvalidAccessException` /
    // `ResourceNotFoundException` (among others) when there's no hub. Any
    // error here is treated the same way: log and return zero rows rather
    // than propagating, so one un-enabled region doesn't abort a
    // multi-region run.
    let hub = match client.describe_hub().send().await {
        Ok(h) => h,
        Err(e) => {
            eprintln!("securityhub describe_hub: hub not enabled (or error) in {region}: {e:#}");
            return Ok(Vec::new());
        }
    };

    let Some(hub_arn) = hub.hub_arn() else {
        return Ok(Vec::new());
    };

    let subscribed_at = hub.subscribed_at().unwrap_or("").to_string();
    let auto_enable_controls = hub
        .auto_enable_controls()
        .map(|b| b.to_string())
        .unwrap_or_default();
    let control_finding_generator = hub
        .control_finding_generator()
        .map(|c| c.as_str())
        .unwrap_or("")
        .to_string();

    // Enabled standards — soft-fail to empty on error.
    let mut enabled_standards = Vec::new();
    let mut next_token: Option<String> = None;
    loop {
        let mut req = client.get_enabled_standards();
        if let Some(ref t) = next_token {
            req = req.next_token(t);
        }
        match req.send().await {
            Ok(resp) => {
                for sub in resp.standards_subscriptions() {
                    if let Some(arn) = sub.standards_subscription_arn() {
                        enabled_standards.push(arn.to_string());
                    }
                }
                next_token = resp.next_token().map(|s| s.to_string());
                if next_token.is_none() {
                    break;
                }
            }
            Err(e) => {
                eprintln!("securityhub get_enabled_standards failed: {e:#}");
                enabled_standards.clear();
                break;
            }
        }
    }

    let comments = format!(
        "SubscribedAt: {subscribed_at} | AutoEnableControls: {auto_enable_controls} | \
         ControlFindingGenerator: {control_finding_generator} | \
         EnabledStandards: {}",
        enabled_standards.join(", ")
    );

    Ok(vec![RowBuilder::new()
        .unique_id(hub_arn)
        .virtual_flag("Yes")
        .public("No")
        .location(region)
        .asset_type("Security Hub Hub")
        .sw_vendor("Amazon Web Services")
        .sw_name_ver("AWS Security Hub")
        .vlan_network_id("")
        .function("")
        .comments(comments)
        .build()])
}

// ---------------------------------------------------------------------------
// WAF WebACL — §24
// ---------------------------------------------------------------------------

/// Tag-first Function-column derivation for WAF WebACLs. `Tag::key()`/
/// `value()` both return plain `&str` here (unlike CloudTrail's
/// `Option<&str>` value) — closest analog is `storage::function_from_efs_tags`.
fn function_from_waf_tags(tags: &[aws_sdk_wafv2::types::Tag]) -> String {
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

fn format_default_action(action: Option<&aws_sdk_wafv2::types::DefaultAction>) -> String {
    match action {
        Some(a) if a.allow().is_some() => "ALLOW".to_string(),
        Some(a) if a.block().is_some() => "BLOCK".to_string(),
        _ => String::new(),
    }
}

pub(super) async fn collect_waf_webacls(
    client: &Wafv2Client,
    region: &str,
) -> Result<Vec<Vec<String>>> {
    let mut rows = Vec::new();

    match collect_waf_scope(client, region, aws_sdk_wafv2::types::Scope::Regional).await {
        Ok(r) => rows.extend(r),
        Err(e) => eprintln!("WARN: WAF regional scope: {e:#}"),
    }

    // CLOUDFRONT-scope WebACLs are global (not per-region) — only fetch them
    // once, from us-east-1, or an --all-regions run would emit the same
    // global ACL rows once per region.
    if region == "us-east-1" {
        match collect_waf_scope(client, region, aws_sdk_wafv2::types::Scope::Cloudfront).await {
            Ok(r) => rows.extend(r),
            Err(e) => eprintln!("WARN: WAF cloudfront scope: {e:#}"),
        }
    }

    Ok(rows)
}

async fn collect_waf_scope(
    client: &Wafv2Client,
    region: &str,
    scope: aws_sdk_wafv2::types::Scope,
) -> Result<Vec<Vec<String>>> {
    let mut rows = Vec::new();
    let mut next_marker: Option<String> = None;

    let is_regional = scope == aws_sdk_wafv2::types::Scope::Regional;
    let location = if is_regional {
        region.to_string()
    } else {
        "global / CloudFront".to_string()
    };

    loop {
        let mut req = client.list_web_acls().scope(scope.clone());
        if let Some(ref m) = next_marker {
            req = req.next_marker(m);
        }
        let resp = req.send().await.context("WAFv2 list_web_acls")?;

        for summary in resp.web_acls() {
            let (Some(name), Some(id), Some(arn)) = (summary.name(), summary.id(), summary.arn())
            else {
                continue;
            };

            let detail: Option<aws_sdk_wafv2::types::WebAcl> = match client
                .get_web_acl()
                .name(name)
                .id(id)
                .scope(scope.clone())
                .send()
                .await
            {
                Ok(d) => d.web_acl().cloned(),
                Err(e) => {
                    eprintln!("wafv2 get_web_acl failed for {arn}: {e:#}");
                    None
                }
            };

            let default_action =
                format_default_action(detail.as_ref().and_then(|w| w.default_action()));
            let rule_count = detail
                .as_ref()
                .map(|w| w.rules().len().to_string())
                .unwrap_or_default();
            let managed_by_firewall_manager = detail
                .as_ref()
                .map(|w| w.managed_by_firewall_manager().to_string())
                .unwrap_or_default();
            let (cw_metrics_enabled, sampled_requests_enabled) =
                match detail.as_ref().and_then(|w| w.visibility_config()) {
                    Some(vc) => (
                        vc.cloud_watch_metrics_enabled().to_string(),
                        vc.sampled_requests_enabled().to_string(),
                    ),
                    None => (String::new(), String::new()),
                };

            // `list_resources_for_web_acl` only supports REGIONAL-scope
            // WebACLs — CLOUDFRONT-scope ACLs are associated with
            // CloudFront distributions instead, which this API rejects.
            let associated_resource_arns = if is_regional {
                let mut arns = Vec::new();
                for rt in [
                    aws_sdk_wafv2::types::ResourceType::ApplicationLoadBalancer,
                    aws_sdk_wafv2::types::ResourceType::ApiGateway,
                    aws_sdk_wafv2::types::ResourceType::Appsync,
                ] {
                    match client
                        .list_resources_for_web_acl()
                        .web_acl_arn(arn)
                        .resource_type(rt)
                        .send()
                        .await
                    {
                        Ok(r) => arns.extend(r.resource_arns().iter().cloned()),
                        Err(e) => {
                            eprintln!("wafv2 list_resources_for_web_acl failed for {arn}: {e:#}");
                        }
                    }
                }
                arns.join(", ")
            } else {
                "cloudfront-distributions".to_string()
            };

            let function = match client
                .list_tags_for_resource()
                .resource_arn(arn)
                .send()
                .await
            {
                Ok(resp) => resp
                    .tag_info_for_resource()
                    .map(|t| function_from_waf_tags(t.tag_list()))
                    .unwrap_or_default(),
                Err(e) => {
                    eprintln!("wafv2 list_tags_for_resource failed for {arn}: {e:#}");
                    String::new()
                }
            };

            let comments = format!(
                "Scope: {} | DefaultAction: {default_action} | \
                 ManagedByFirewallManager: {managed_by_firewall_manager} | \
                 AssociatedResourceArns: {associated_resource_arns} | RuleCount: {rule_count} | \
                 CloudWatchMetricsEnabled: {cw_metrics_enabled} | \
                 SampledRequestsEnabled: {sampled_requests_enabled}",
                scope.as_str()
            );

            rows.push(
                RowBuilder::new()
                    .unique_id(arn)
                    .virtual_flag("Yes")
                    .public("Yes")
                    .location(location.clone())
                    .asset_type("WAF WebACL")
                    .sw_vendor("Amazon Web Services")
                    .sw_name_ver("AWS WAFv2")
                    .vlan_network_id("")
                    .function(function)
                    .comments(comments)
                    .build(),
            );
        }

        next_marker = resp.next_marker().map(|s| s.to_string());
        if next_marker.is_none() {
            break;
        }
    }

    Ok(rows)
}
