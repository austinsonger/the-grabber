use std::path::PathBuf;

use anyhow::Result;
use aws_config::{BehaviorVersion, Region};
use chrono::Utc;

use crate::audit_log;
use crate::cli::Cli;
use crate::evidence::CollectParams;
use crate::runner::collect_ops::{
    run_csv_collectors, run_json_collectors, run_json_inv_collectors,
};
use crate::runner::collector_registry::{
    build_csv_collectors, build_json_collectors, build_json_inv_collectors,
};
use crate::runner::multi_account::GLOBAL_COLLECTOR_KEYS;

pub(crate) async fn run_multi_region_standard(
    cli: &Cli,
    config: &aws_config::SdkConfig,
    account_id: &str,
    cli_identity: Option<audit_log::AwsIdentity>,
    cli_started_at: &str,
    params: &CollectParams,
    selected: &[String],
    output_dir: &PathBuf,
) -> Result<()> {
    // Determine the target region list.
    let target_regions: Vec<String> = if let Some(explicit) = cli.regions.as_ref() {
        explicit.clone()
    } else {
        let regions = crate::aws_loader::discover_regions(config).await;
        if regions.is_empty() {
            anyhow::bail!("--all-regions: could not discover any enabled regions");
        }
        regions
    };

    // Build the wanted name lists, honouring any --collectors filter.
    let wanted_csv: Vec<&str> = {
        // All keys that appear in both the full key space AND the wants() filter.
        let full: &[&str] = &[
            "vpc",
            "nacl",
            "waf",
            "elasticache",
            "elasticache-global",
            "efs",
            "dynamodb",
            "ebs",
            "rds-inventory",
            "cloudtrail-config",
            "sns",
            "vpc-flow-logs",
            "metric-filters",
            "s3-logging",
            "iam-certs",
            "elb",
            "elb-listeners",
            "acm",
            "iam-users",
            "iam-policies",
            "iam-access-keys",
            "guardduty",
            "securityhub",
            "config-rules",
            "security-groups",
            "route-tables",
            "ec2-instances",
            "asg",
            "kms",
            "secrets",
            "s3-config",
            "cw-alarms",
            "cw-log-groups",
            "api-gateway",
            "cloudfront",
            "ecs",
            "eks",
            "iam-trusts",
            "access-analyzer",
            "scp",
            "ct-selectors",
            "ct-validation",
            "ct-s3-policy",
            "ct-changes",
            "ct-account-mgmt",
            "ct-sessions",
            "ct-privileged",
            "ct-insights",
            "ct-lake",
            "athena-log-queries",
            "s3-data-events",
            "guardduty-config",
            "guardduty-coverage",
            "guardduty-rules",
            "sh-standards",
            "igw",
            "nat-gateways",
            "public-resources",
            "ec2-detailed",
            "ssm-instances",
            "ssm-patches",
            "kms-policies",
            "ebs-encryption",
            "rds-snapshots",
            "s3-policies",
            "macie",
            "config-history",
            "inspector",
            "inspector-ecr-images",
            "inspector-history",
            "waf-logging",
            "alb-logs",
            "iam-password-policy",
            "ebs-config",
            "s3-encryption",
            "s3-bucket-policy",
            "s3-public-access",
            "s3-logging-config",
            "sg-config",
            "vpc-config",
            "rt-config",
            "ec2-config",
            "ct-full-config",
            "cw-log-config",
            "metric-filter-config",
            "gd-full-config",
            "sh-config",
            "config-recorder",
            "launch-templates",
            "vpc-endpoints",
            "ssm-baselines",
            "ssm-params",
            "time-sync",
            "inspector-config",
            "inspector-coverage",
            "inspector-suppression",
            "waf-config",
            "elb-full-config",
            "org-config",
            "account-contacts",
            "saml-providers",
            "iam-account-summary",
            "sns-policies",
            "backup-plans",
            "backup-vaults",
            "rds-backup-config",
            "backup-vaultlock",
            "backup-copy-actions",
            "backup-restore-testing",
            "drs-replication",
            "r53-arc",
            "rds-pitr",
            "s3-replication",
            "s3-object-lock",
            "lambda-config",
            "lambda-permissions",
            "ecr-config",
            "route53-zones",
            "route53-resolver",
            "resource-tags",
            "secrets-policies",
            "config-timeline",
            "config-compliance",
            "config-snapshot",
            "ct-iam-changes",
            "cfn-drift",
            "ssm-patch-detail",
            "ssm-patch-summary",
            "ssm-patch-exec",
            "ssm-maint-windows",
            "cw-config-alarms",
            "cw-anomaly",
            "change-event-rules",
            "inspector-sbom",
            // ── New collectors (2026-06) ──
            "client-vpn",
            "acm-pca",
            "ssm-software-inventory",
            "ssm-compliance-summary",
            "ssm-associations",
            "ssm-automation",
            "shield",
            "license-manager",
            "service-quotas",
            "route53-dnssec",
            "network-firewall",
            "ssm-sessions",
            "cognito-pools",
            "logs-insights-queries",
            "eb-archives",
            "firehose-streams",
            "cw-contributor-insights",
            "detective-graphs",
            "sh-insights",
            "waf-destinations",
            "vpc-mirror",
            "tgw-routes",
            "privatelink-services",
            "r53-dns-firewall",
            "kms-grants",
            "appmesh-tls",
            "signer-profiles",
            "ecr-signatures",
            "codeartifact-repos",
            "codepipeline-codebuild",
            "control-tower",
            "audit-manager",
            "resource-explorer",
            "fis-experiments",
            "synthetics-canaries",
            "macie-jobs",
            "savings-plans-ri",
            "compute-optimizer",
            "tagging-compliance",
            "scp-attachments",
            "iam-simulator",
            "idc-inline-policies",
            "roles-anywhere",
            "iam-boundaries",
            "verified-permissions",
            "security-lake",
            "fms-policies",
            "guardduty-protection-plans",
            "dx-vpn",
            "global-accelerator",
            "apigw-deep",
            "cloudfront-oac",
            "nfw-rules",
            "ssm-opsitems",
            "ssm-change-requests",
            "resilience-hub",
            "oam-observability",
            "appconfig-deployments",
            "eks-addons",
            "eks-access-entries",
            "eks-pod-identity",
            "ecs-task-defs",
            "ecr-replication",
            "glue-catalog",
            "lakeformation-perms",
            "redshift-clusters",
            "opensearch-domains",
            "msk-clusters",
            "sfn-executions",
            "kinesis-streams",
            "vpc-lattice",
            "waf-rulegroups-deep",
            "mgn-source-servers",
            "dms",
            "snowball-jobs",
            "sagemaker-posture",
            "bedrock",
        ];
        full.iter()
            .copied()
            .filter(|k| selected.iter().any(|s| s.eq_ignore_ascii_case(k)))
            .collect()
    };
    let wanted_json_inv: Vec<&str> = [
        "iam-roles",
        "iam-role-policies",
        "iam-user-policies",
        "eventbridge-rules",
        "ct-config-changes",
        "kms-config",
    ]
    .iter()
    .copied()
    .filter(|k| selected.iter().any(|s| s.eq_ignore_ascii_case(k)))
    .collect();
    let wanted_json: Vec<&str> = ["cloudtrail", "backup", "rds"]
        .iter()
        .copied()
        .filter(|k| selected.iter().any(|s| s.eq_ignore_ascii_case(k)))
        .collect();

    // Split into global (run once) and regional (run per region).
    let global_csv: Vec<&str> = wanted_csv
        .iter()
        .copied()
        .filter(|k| GLOBAL_COLLECTOR_KEYS.contains(k))
        .collect();
    let regional_csv: Vec<&str> = wanted_csv
        .iter()
        .copied()
        .filter(|k| !GLOBAL_COLLECTOR_KEYS.contains(k))
        .collect();
    let global_json_inv: Vec<&str> = wanted_json_inv
        .iter()
        .copied()
        .filter(|k| GLOBAL_COLLECTOR_KEYS.contains(k))
        .collect();
    let regional_json_inv: Vec<&str> = wanted_json_inv
        .iter()
        .copied()
        .filter(|k| !GLOBAL_COLLECTOR_KEYS.contains(k))
        .collect();
    // JSON time-windowed collectors are all regional.

    let mr_run_id = Utc::now().format("%Y-%m-%d-%H%M%S").to_string();
    let mr_dates = Some((params.start_time.timestamp(), params.end_time.timestamp()));
    let mr_coll_start = params.start_time.format("%Y-%m-%d").to_string();
    let mr_coll_end = params.end_time.format("%Y-%m-%d").to_string();
    let mut mr_outcomes: Vec<audit_log::CollectorOutcome> = Vec::new();

    // ── Run global collectors once (into base output dir) ─────────────────
    if !global_csv.is_empty() || !global_json_inv.is_empty() {
        eprintln!("\n=== Global collectors (running once) ===");
        let global_csv_v = build_csv_collectors(&global_csv, config);
        let global_inv_v = build_json_inv_collectors(&global_json_inv, config);
        mr_outcomes.extend(
            run_csv_collectors(
                &global_csv_v,
                account_id,
                &cli.region,
                output_dir,
                mr_dates,
                &mr_run_id,
            )
            .await?,
        );
        mr_outcomes.extend(
            run_json_inv_collectors(
                &global_inv_v,
                account_id,
                &cli.region,
                output_dir,
                &mr_run_id,
            )
            .await?,
        );
    }

    // ── Loop through each region ──────────────────────────────────────────
    for region_name in &target_regions {
        eprintln!("\n=== Region: {} ===", region_name);

        let region_config = {
            let mut loader = aws_config::defaults(BehaviorVersion::latest())
                .region(Region::new(region_name.clone()));
            if let Some(ref p) = cli.profile {
                loader = loader.profile_name(p);
            }
            loader.load().await
        };

        let region_dir = output_dir.join(region_name);

        if !regional_csv.is_empty() {
            let csv_v = build_csv_collectors(&regional_csv, &region_config);
            mr_outcomes.extend(
                run_csv_collectors(
                    &csv_v,
                    account_id,
                    region_name,
                    &region_dir,
                    mr_dates,
                    &mr_run_id,
                )
                .await?,
            );
        }
        if !regional_json_inv.is_empty() {
            let inv_v = build_json_inv_collectors(&regional_json_inv, &region_config);
            mr_outcomes.extend(
                run_json_inv_collectors(&inv_v, account_id, region_name, &region_dir, &mr_run_id)
                    .await?,
            );
        }
        if !wanted_json.is_empty() {
            let json_v = build_json_collectors(&wanted_json, &region_config);
            mr_outcomes.extend(
                run_json_collectors(&json_v, params, region_name, &region_dir, &mr_run_id).await?,
            );
        }
    }

    // ── Write run manifest (multi-region) ─────────────────────────────────
    let mr_manifest = audit_log::RunManifest::build(
        &mr_run_id,
        account_id,
        &cli.region,
        &mr_coll_start,
        &mr_coll_end,
        mr_outcomes,
    );
    if cli.write_run_manifest {
        match audit_log::write_run_manifest(output_dir, &mr_manifest) {
            Ok(p) => eprintln!("Run manifest written: {}", p.display()),
            Err(e) => eprintln!("WARN: could not write run manifest: {e}"),
        }
    }

    // ── Write chain-of-custody (multi-region) ─────────────────────────────
    if cli.write_chain_of_custody {
        let identity = cli_identity.unwrap_or(audit_log::AwsIdentity {
            account_id: account_id.to_string(),
            caller_arn: "unknown".to_string(),
            user_id: "unknown".to_string(),
        });
        let profile = cli.profile.as_deref().unwrap_or("default");
        let entry = audit_log::CustodyEntry::new(
            &mr_run_id,
            cli_started_at,
            identity,
            profile,
            &cli.region,
            &mr_coll_start,
            &mr_coll_end,
            mr_manifest.summary.total_collectors,
        );
        match audit_log::write_chain_of_custody(output_dir, &entry) {
            Ok(p) => eprintln!("Chain of custody written: {}", p.display()),
            Err(e) => eprintln!("WARN: could not write chain of custody: {e}"),
        }
    }

    let mr_timestamp = mr_run_id.clone();

    if cli.zip {
        let zip_name = format!("Evidence-{}.zip", mr_timestamp);
        let zip_path = std::path::Path::new(&zip_name);
        match crate::zip_bundle::bundle_dir(output_dir, zip_path) {
            Ok(()) => eprintln!("Zip bundle written: {}", zip_name),
            Err(e) => eprintln!("Zip bundle failed: {e}"),
        }
    }

    if cli.sign {
        let key = match &cli.signing_key {
            Some(hex) => crate::signing::SigningKey::from_hex(hex)?,
            None => crate::signing::SigningKey::generate()?,
        };
        let cwd = std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("."));
        let files = crate::signing::collect_dir_files(output_dir);
        match crate::signing::sign_files(&files, &mr_timestamp, &key, &cwd) {
            Ok((manifest_path, key_path)) => {
                eprintln!("Signing manifest: {}", manifest_path.display());
                eprintln!(
                    "Signing key file: {} (move to secure storage)",
                    key_path.display()
                );
                eprintln!("Signing key (hex): {}", key.to_hex());
            }
            Err(e) => eprintln!("Signing failed: {e}"),
        }
    }

    Ok(())
}
