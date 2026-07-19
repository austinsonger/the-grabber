use anyhow::{Context, Result};
use aws_sdk_secretsmanager::Client as SecretsManagerClient;

use crate::inventory_core::RowBuilder;

// ---------------------------------------------------------------------------
// Secrets Manager Secrets — mapping doc §14
//
// Metadata only. This collector must NEVER call the value-retrieval API (or
// any other API that returns `SecretString`/`SecretBinary`) — doing so would
// exfiltrate the actual secret material into the inventory output.
// `list_secrets` already returns everything needed except replica region
// names, which live in `describe_secret`'s `replication_status[]` and aren't
// present on `SecretListEntry` at all — see the per-secret call below.
// ---------------------------------------------------------------------------

/// Tag-first Function-column derivation for Secrets Manager secrets.
/// Secrets Manager's `Tag::key()`/`value()` both return `Option<&str>` —
/// same accessor shape as EFS/DynamoDB's tag types, unlike SNS/EventBridge
/// where `key()` is a plain `&str`.
fn function_from_secret_tags(tags: &[aws_sdk_secretsmanager::types::Tag]) -> String {
    tags.iter()
        .find(|t| {
            matches!(
                t.key(),
                Some("Purpose" | "App" | "Role" | "Function" | "purpose" | "app" | "role")
            )
        })
        .and_then(|t| t.value())
        .unwrap_or("")
        .to_string()
}

/// Formats a `RotationRulesType` per §14: `AutomaticallyAfterDays: <n>` if
/// set, else `ScheduleExpression: <expr>` if set, else empty. Only one of
/// the two is ever populated on a given secret.
fn format_rotation_rules(
    rules: Option<&aws_sdk_secretsmanager::types::RotationRulesType>,
) -> String {
    let Some(rules) = rules else {
        return String::new();
    };
    if let Some(days) = rules.automatically_after_days() {
        return format!("AutomaticallyAfterDays: {days}");
    }
    if let Some(expr) = rules.schedule_expression() {
        return format!("ScheduleExpression: {expr}");
    }
    String::new()
}

/// Converts an SDK `DateTime` to RFC3339, matching the `secs_to_rfc3339`
/// pattern used for ECR image timestamps in `compute.rs`.
fn dt_to_rfc3339(dt: Option<&aws_sdk_secretsmanager::primitives::DateTime>) -> String {
    dt.and_then(|d| chrono::DateTime::<chrono::Utc>::from_timestamp(d.secs(), 0))
        .map(|c| c.to_rfc3339())
        .unwrap_or_default()
}

pub(super) async fn collect_secretsmanager_secrets(
    c: &SecretsManagerClient,
    region: &str,
) -> Result<Vec<Vec<String>>> {
    let mut rows = Vec::new();
    let mut next_token: Option<String> = None;

    loop {
        let mut req = c.list_secrets();
        if let Some(ref t) = next_token {
            req = req.next_token(t);
        }
        let resp = req.send().await.context("Secrets Manager list_secrets")?;

        for secret in resp.secret_list() {
            let Some(arn) = secret.arn() else {
                continue;
            };

            let kms_key_id = secret.kms_key_id().unwrap_or("").to_string();
            let rotation_enabled = secret
                .rotation_enabled()
                .map(|b| b.to_string())
                .unwrap_or_default();
            let rotation_lambda_arn = secret.rotation_lambda_arn().unwrap_or("").to_string();
            let rotation_rules = format_rotation_rules(secret.rotation_rules());
            let last_rotated_date = dt_to_rfc3339(secret.last_rotated_date());
            let last_changed_date = dt_to_rfc3339(secret.last_changed_date());
            let last_accessed_date = dt_to_rfc3339(secret.last_accessed_date());
            // list_secrets doesn't return per-version metadata — a version
            // count would need describe_secret + list_secret_version_ids
            // per secret, which isn't worth the extra API calls. Left empty.
            let version_count = String::new();
            let primary_region = secret.primary_region().unwrap_or("").to_string();

            // ReplicaRegions lives only in describe_secret's
            // replication_status[] (SecretListEntry has no such field).
            // Metadata-only call, soft-failed like the secondary calls in
            // messaging.rs — a failure here just leaves ReplicaRegions empty
            // rather than aborting the whole secret.
            let replica_regions = match c.describe_secret().secret_id(arn).send().await {
                Ok(r) => r
                    .replication_status()
                    .iter()
                    .filter_map(|s| s.region())
                    .collect::<Vec<_>>()
                    .join(", "),
                Err(e) => {
                    eprintln!("secretsmanager describe_secret failed for {arn}: {e}");
                    String::new()
                }
            };

            let function = {
                let tag_function = function_from_secret_tags(secret.tags());
                if tag_function.is_empty() {
                    secret.description().unwrap_or("").to_string()
                } else {
                    tag_function
                }
            };

            let comments = format!(
                "KmsKeyId: {kms_key_id} | RotationEnabled: {rotation_enabled} | \
                 RotationLambdaArn: {rotation_lambda_arn} | RotationRules: {rotation_rules} | \
                 LastRotatedDate: {last_rotated_date} | LastChangedDate: {last_changed_date} | \
                 LastAccessedDate: {last_accessed_date} | VersionCount: {version_count} | \
                 PrimaryRegion: {primary_region} | ReplicaRegions: {replica_regions}"
            );

            rows.push(
                RowBuilder::new()
                    .unique_id(arn)
                    .virtual_flag("Yes")
                    .public("No")
                    .location(region)
                    .asset_type("Secrets Manager Secret")
                    .sw_vendor("Amazon Web Services")
                    .sw_name_ver("AWS Secrets Manager")
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
