use crate::evidence::{CsvCollector, EvidenceCollector, JsonCollector};
use crate::providers::{CloudProvider, ProviderFactory};

use crate::providers::aws::{
    access_analyzer::AccessAnalyzerCollector,
    account_config::{AccountContactsCollector, IamAccountSummaryCollector, SamlProviderCollector},
    acm::AcmCertCollector,
    acm_pca::AcmPrivateCaCollector,
    alb_logs::AlbLogsCollector,
    ami_default_creds::AmiDefaultCredentialScanCollector,
    apigateway::ApiGatewayCollector,
    autoscaling::AutoScalingCollector,
    backup::BackupCollector,
    backup_config::{
        BackupPlanConfigCollector, BackupRegionSettingsCollector, BackupVaultConfigCollector,
        RdsBackupConfigCollector,
    },
    client_vpn::AwsClientVpnCollector,
    cloudformation_drift::CloudFormationDriftCollector,
    cloudfront::CloudFrontCollector,
    cloudtrail::CloudTrailCollector,
    cloudtrail_config::CloudTrailFullConfigCollector,
    cloudtrail_details::{
        CloudTrailChangeEventsCollector, CloudTrailEventSelectorsCollector,
        CloudTrailLogValidationCollector, CloudTrailS3PolicyCollector, S3DataEventsCollector,
    },
    cloudtrail_iam::{CloudTrailConfigChangesCollector, CloudTrailIamChangesCollector},
    cloudtrail_inventory::CloudTrailInventoryCollector,
    cloudwatch::MetricFilterAlarmCollector,
    cloudwatch_alarms::CloudWatchConfigAlarmsCollector,
    cloudwatch_config::{CwLogGroupConfigCollector, MetricFilterConfigCollector},
    cloudwatch_resources::{CloudWatchAlarmCollector, CloudWatchLogGroupCollector},
    config_history::ConfigHistoryCollector,
    config_rules::ConfigRulesCollector,
    config_timeline::{
        ConfigComplianceHistoryCollector, ConfigResourceTimelineCollector, ConfigSnapshotCollector,
    },
    doc_repo_backup::DocRepoBackupConfigCollector,
    dynamodb::DynamoDbCollector,
    ebs::EbsCollector,
    ec2_config::{
        Ec2InstanceConfigCollector, RouteTableConfigCollector, SecurityGroupConfigCollector,
        VpcConfigCollector,
    },
    ec2_detailed::Ec2DetailedCollector,
    ec2_inventory::{Ec2InstanceCollector, RouteTableCollector, SecurityGroupCollector},
    ecr_config::EcrRepoConfigCollector,
    ecs::EcsClusterCollector,
    efs::EfsCollector,
    eks::EksClusterCollector,
    elasticache::{ElastiCacheCollector, ElastiCacheGlobalCollector},
    elb::{LoadBalancerCollector, LoadBalancerListenerCollector},
    elb_config::ElbFullConfigCollector,
    guardduty::GuardDutyCollector,
    guardduty_config::{GuardDutyConfigCollector, GuardDutySuppressionCollector},
    guardduty_malware_scans::GuardDutyMalwareScanHistoryCollector,
    guardduty_runtime::GuardDutyRuntimeCoverageCollector,
    iam_certs::IamCertCollector,
    iam_credential_report::IamCredentialReportCollector,
    iam_inventory::{
        IamAccessKeyCollector, IamPolicyCollector, IamRoleCollector, IamUserCollector,
    },
    iam_policies::{
        IamPasswordPolicyCollector, IamRolePoliciesCollector, IamUserPoliciesCollector,
    },
    iam_trusts::IamTrustsCollector,
    inspector::InspectorCollector,
    inspector_config::InspectorConfigCollector,
    inspector_ecr::InspectorEcrImagesCollector,
    inspector_history::InspectorFindingsHistoryCollector,
    inspector_sbom::{InspectorSbomCollector, InspectorSbomConfig},
    kms::KmsKeyCollector,
    kms_config::{EbsEncryptionConfigCollector, KmsKeyConfigCollector},
    kms_policies::{EbsDefaultEncryptionCollector, KmsKeyPolicyCollector},
    lambda_config::{LambdaConfigCollector, LambdaPermissionsCollector},
    launch_templates::LaunchTemplateCollector,
    license_manager::LicenseManagerCollector,
    macie::MacieCollector,
    network_firewall::NetworkFirewallCollector,
    network_firewall_failclosed::NetworkFirewallFailClosedCollector,
    network_gateways::{InternetGatewayCollector, NatGatewayCollector},
    org_config::OrgConfigCollector,
    organizations::OrganizationsSCPCollector,
    public_resources::PublicResourceCollector,
    rds::RdsCollector,
    rds_inventory::RdsInventoryCollector,
    rds_snapshots::RdsSnapshotCollector,
    route53_config::{
        Route53DnssecCollector, Route53ResolverRulesCollector, Route53ZonesCollector,
    },
    s3_config::S3BucketConfigCollector,
    s3_detail::{
        S3BucketPolicyDetailCollector, S3EncryptionConfigCollector, S3LoggingConfigCollector,
        S3PublicAccessBlockCollector,
    },
    s3_inventory::S3BucketLoggingCollector,
    s3_policies::S3PoliciesCollector,
    secrets_extended::SecretsManagerPoliciesCollector,
    secretsmanager::SecretsManagerCollector,
    security_svc_config::{
        AwsConfigRecorderCollector, GuardDutyFullConfigCollector, SecurityHubConfigCollector,
    },
    securityhub::SecurityHubCollector,
    securityhub_standards::SecurityHubStandardsCollector,
    service_quotas::ServiceQuotasCollector,
    session_timeouts::SessionTimeoutConfigCollector,
    shield::ShieldCollector,
    sns::SnsSubscriptionCollector,
    sns_eventbridge::{
        ChangeEventRulesCollector, EventBridgeRulesCollector, SnsTopicPoliciesCollector,
    },
    ssm::{SsmManagedInstanceCollector, SsmPatchComplianceCollector},
    ssm_allowlist::SsmApplicationAllowlistCollector,
    ssm_automation_runbooks::SsmAutomationRunbooksCollector,
    ssm_extended::{
        SsmInstanceAssociationsStatusCollector, SsmParameterConfigCollector,
        SsmPatchBaselineCollector, TimeSyncConfigCollector,
    },
    ssm_patch_detail::{
        SsmMaintenanceWindowCollector, SsmPatchDetailCollector, SsmPatchExecutionCollector,
        SsmPatchSummaryCollector,
    },
    ssm_sessions::SsmSessionsCollector,
    ssm_software_inventory::SsmSoftwareInventoryCollector,
    tagging_config::ResourceTaggingCollector,
    transit_gateway_peering::TransitGatewayPeeringCollector,
    vpc::{NetworkAclCollector, VpcCollector},
    vpc_endpoints::VpcEndpointCollector,
    vpcflowlogs::VpcFlowLogCollector,
    waf::WafCollector,
    waf_full_config::WafFullConfigCollector,
    waf_logging::WafLoggingCollector,
};

pub struct AwsProviderFactory {
    config: aws_config::SdkConfig,
    account_id: String,
    region: String,
    selected: Vec<String>,
    sbom: Option<(InspectorSbomConfig, Option<std::path::PathBuf>)>,
}

impl AwsProviderFactory {
    pub fn new(
        config: aws_config::SdkConfig,
        account_id: String,
        region: String,
        selected: Vec<String>,
    ) -> Self {
        Self {
            config,
            account_id,
            region,
            selected,
            sbom: None,
        }
    }

    pub fn with_sbom_config(
        mut self,
        sbom_config: InspectorSbomConfig,
        output_dir: Option<std::path::PathBuf>,
    ) -> Self {
        self.sbom = Some((sbom_config, output_dir));
        self
    }
}

impl ProviderFactory for AwsProviderFactory {
    fn provider(&self) -> CloudProvider {
        CloudProvider::Aws
    }
    fn account_id(&self) -> &str {
        &self.account_id
    }
    fn region(&self) -> &str {
        &self.region
    }

    fn csv_collectors(&self) -> Vec<Box<dyn CsvCollector>> {
        let names: Vec<&str> = self.selected.iter().map(String::as_str).collect();
        let has = |n: &str| names.contains(&n);
        let cfg = &self.config;
        let mut v: Vec<Box<dyn CsvCollector>> = Vec::new();

        if has("vpc") {
            v.push(Box::new(VpcCollector::new(cfg)));
        }
        if has("nacl") {
            v.push(Box::new(NetworkAclCollector::new(cfg)));
        }
        if has("waf") {
            v.push(Box::new(WafCollector::new(cfg)));
        }
        if has("elasticache") {
            v.push(Box::new(ElastiCacheCollector::new(cfg)));
        }
        if has("elasticache-global") {
            v.push(Box::new(ElastiCacheGlobalCollector::new(cfg)));
        }
        if has("efs") {
            v.push(Box::new(EfsCollector::new(cfg)));
        }
        if has("dynamodb") {
            v.push(Box::new(DynamoDbCollector::new(cfg)));
        }
        if has("ebs") {
            v.push(Box::new(EbsCollector::new(cfg)));
        }
        if has("rds-inventory") {
            v.push(Box::new(RdsInventoryCollector::new(cfg)));
        }
        if has("cloudtrail-config") {
            v.push(Box::new(CloudTrailInventoryCollector::new(cfg)));
        }
        if has("sns") {
            v.push(Box::new(SnsSubscriptionCollector::new(cfg)));
        }
        if has("vpc-flow-logs") {
            v.push(Box::new(VpcFlowLogCollector::new(cfg)));
        }
        if has("metric-filters") {
            v.push(Box::new(MetricFilterAlarmCollector::new(cfg)));
        }
        if has("s3-logging") {
            v.push(Box::new(S3BucketLoggingCollector::new(cfg)));
        }
        if has("iam-certs") {
            v.push(Box::new(IamCertCollector::new(cfg)));
        }
        if has("elb") {
            v.push(Box::new(LoadBalancerCollector::new(cfg)));
        }
        if has("elb-listeners") {
            v.push(Box::new(LoadBalancerListenerCollector::new(cfg)));
        }
        if has("acm") {
            v.push(Box::new(AcmCertCollector::new(cfg)));
        }
        if has("acm-pca") {
            v.push(Box::new(AcmPrivateCaCollector::new(cfg)));
        }
        if has("ami-default-creds") {
            v.push(Box::new(AmiDefaultCredentialScanCollector::new(cfg)));
        }
        if has("iam-users") {
            v.push(Box::new(IamUserCollector::new(cfg)));
        }
        if has("iam-policies") {
            v.push(Box::new(IamPolicyCollector::new(cfg)));
        }
        if has("iam-access-keys") {
            v.push(Box::new(IamAccessKeyCollector::new(cfg)));
        }
        if has("iam-cred-report") {
            v.push(Box::new(IamCredentialReportCollector::new(cfg)));
        }
        if has("guardduty") {
            v.push(Box::new(GuardDutyCollector::new(cfg)));
        }
        if has("securityhub") {
            v.push(Box::new(SecurityHubCollector::new(cfg)));
        }
        if has("service-quotas") {
            v.push(Box::new(ServiceQuotasCollector::new(cfg)));
        }
        if has("shield") {
            v.push(Box::new(ShieldCollector::new(cfg)));
        }
        if has("config-rules") {
            v.push(Box::new(ConfigRulesCollector::new(cfg)));
        }
        if has("security-groups") {
            v.push(Box::new(SecurityGroupCollector::new(cfg)));
        }
        if has("route-tables") {
            v.push(Box::new(RouteTableCollector::new(cfg)));
        }
        if has("ec2-instances") {
            v.push(Box::new(Ec2InstanceCollector::new(cfg)));
        }
        if has("asg") {
            v.push(Box::new(AutoScalingCollector::new(cfg)));
        }
        if has("kms") {
            v.push(Box::new(KmsKeyCollector::new(cfg)));
        }
        if has("secrets") {
            v.push(Box::new(SecretsManagerCollector::new(cfg)));
        }
        if has("s3-config") {
            v.push(Box::new(S3BucketConfigCollector::new(cfg)));
        }
        if has("cw-alarms") {
            v.push(Box::new(CloudWatchAlarmCollector::new(cfg)));
        }
        if has("cw-log-groups") {
            v.push(Box::new(CloudWatchLogGroupCollector::new(cfg)));
        }
        if has("api-gateway") {
            v.push(Box::new(ApiGatewayCollector::new(cfg)));
        }
        if has("cloudfront") {
            v.push(Box::new(CloudFrontCollector::new(cfg)));
        }
        if has("ecs") {
            v.push(Box::new(EcsClusterCollector::new(cfg)));
        }
        if has("eks") {
            v.push(Box::new(EksClusterCollector::new(cfg)));
        }
        if has("iam-trusts") {
            v.push(Box::new(IamTrustsCollector::new(cfg)));
        }
        if has("access-analyzer") {
            v.push(Box::new(AccessAnalyzerCollector::new(cfg)));
        }
        if has("scp") {
            v.push(Box::new(OrganizationsSCPCollector::new(cfg)));
        }
        if has("ct-selectors") {
            v.push(Box::new(CloudTrailEventSelectorsCollector::new(cfg)));
        }
        if has("ct-validation") {
            v.push(Box::new(CloudTrailLogValidationCollector::new(cfg)));
        }
        if has("ct-s3-policy") {
            v.push(Box::new(CloudTrailS3PolicyCollector::new(cfg)));
        }
        if has("ct-changes") {
            v.push(Box::new(CloudTrailChangeEventsCollector::new(cfg)));
        }
        if has("s3-data-events") {
            v.push(Box::new(S3DataEventsCollector::new(cfg)));
        }
        if has("guardduty-config") {
            v.push(Box::new(GuardDutyConfigCollector::new(cfg)));
        }
        if has("guardduty-rules") {
            v.push(Box::new(GuardDutySuppressionCollector::new(cfg)));
        }
        if has("guardduty-runtime") {
            v.push(Box::new(GuardDutyRuntimeCoverageCollector::new(cfg)));
        }
        if has("guardduty-malware") {
            v.push(Box::new(GuardDutyMalwareScanHistoryCollector::new(cfg)));
        }
        if has("sh-standards") {
            v.push(Box::new(SecurityHubStandardsCollector::new(cfg)));
        }
        if has("network-firewall") {
            v.push(Box::new(NetworkFirewallCollector::new(cfg)));
        }
        if has("nfw-failclosed") {
            v.push(Box::new(NetworkFirewallFailClosedCollector::new(cfg)));
        }
        if has("igw") {
            v.push(Box::new(InternetGatewayCollector::new(cfg)));
        }
        if has("nat-gateways") {
            v.push(Box::new(NatGatewayCollector::new(cfg)));
        }
        if has("public-resources") {
            v.push(Box::new(PublicResourceCollector::new(cfg)));
        }
        if has("ec2-detailed") {
            v.push(Box::new(Ec2DetailedCollector::new(cfg)));
        }
        if has("ssm-instances") {
            v.push(Box::new(SsmManagedInstanceCollector::new(cfg)));
        }
        if has("ssm-patches") {
            v.push(Box::new(SsmPatchComplianceCollector::new(cfg)));
        }
        if has("kms-policies") {
            v.push(Box::new(KmsKeyPolicyCollector::new(cfg)));
        }
        if has("ebs-encryption") {
            v.push(Box::new(EbsDefaultEncryptionCollector::new(cfg)));
        }
        if has("rds-snapshots") {
            v.push(Box::new(RdsSnapshotCollector::new(cfg)));
        }
        if has("s3-policies") {
            v.push(Box::new(S3PoliciesCollector::new(cfg)));
        }
        if has("macie") {
            v.push(Box::new(MacieCollector::new(cfg)));
        }
        if has("config-history") {
            v.push(Box::new(ConfigHistoryCollector::new(cfg)));
        }
        if has("inspector") {
            v.push(Box::new(InspectorCollector::new(cfg)));
        }
        if has("inspector-ecr-images") {
            v.push(Box::new(InspectorEcrImagesCollector::new(cfg)));
        }
        if has("inspector-history") {
            v.push(Box::new(InspectorFindingsHistoryCollector::new(cfg)));
        }
        if has("inspector-sbom") {
            let (sbom_cfg, sbom_out) = match self.sbom.as_ref() {
                Some((c, o)) => (
                    InspectorSbomConfig {
                        bucket: c.bucket.clone(),
                        key_prefix: c.key_prefix.clone(),
                        kms_key_arn: c.kms_key_arn.clone(),
                        format: c.format.clone(),
                    },
                    o.clone(),
                ),
                None => (
                    InspectorSbomConfig {
                        bucket: String::new(),
                        key_prefix: None,
                        kms_key_arn: String::new(),
                        format: aws_sdk_inspector2::types::SbomReportFormat::Cyclonedx14,
                    },
                    None,
                ),
            };
            v.push(Box::new(InspectorSbomCollector::new(
                cfg, cfg, sbom_cfg, sbom_out,
            )));
        }
        if has("waf-logging") {
            v.push(Box::new(WafLoggingCollector::new(cfg)));
        }
        if has("alb-logs") {
            v.push(Box::new(AlbLogsCollector::new(cfg)));
        }
        if has("iam-password-policy") {
            v.push(Box::new(IamPasswordPolicyCollector::new(cfg)));
        }
        if has("ebs-config") {
            v.push(Box::new(EbsEncryptionConfigCollector::new(cfg)));
        }
        if has("s3-encryption") {
            v.push(Box::new(S3EncryptionConfigCollector::new(cfg)));
        }
        if has("s3-bucket-policy") {
            v.push(Box::new(S3BucketPolicyDetailCollector::new(cfg)));
        }
        if has("s3-public-access") {
            v.push(Box::new(S3PublicAccessBlockCollector::new(cfg)));
        }
        if has("s3-logging-config") {
            v.push(Box::new(S3LoggingConfigCollector::new(cfg)));
        }
        if has("sg-config") {
            v.push(Box::new(SecurityGroupConfigCollector::new(cfg)));
        }
        if has("vpc-config") {
            v.push(Box::new(VpcConfigCollector::new(cfg)));
        }
        if has("rt-config") {
            v.push(Box::new(RouteTableConfigCollector::new(cfg)));
        }
        if has("ec2-config") {
            v.push(Box::new(Ec2InstanceConfigCollector::new(cfg)));
        }
        if has("ct-full-config") {
            v.push(Box::new(CloudTrailFullConfigCollector::new(cfg)));
        }
        if has("cw-log-config") {
            v.push(Box::new(CwLogGroupConfigCollector::new(cfg)));
        }
        if has("metric-filter-config") {
            v.push(Box::new(MetricFilterConfigCollector::new(cfg)));
        }
        if has("gd-full-config") {
            v.push(Box::new(GuardDutyFullConfigCollector::new(cfg)));
        }
        if has("sh-config") {
            v.push(Box::new(SecurityHubConfigCollector::new(cfg)));
        }
        if has("config-recorder") {
            v.push(Box::new(AwsConfigRecorderCollector::new(cfg)));
        }
        if has("launch-templates") {
            v.push(Box::new(LaunchTemplateCollector::new(cfg)));
        }
        if has("license-manager") {
            v.push(Box::new(LicenseManagerCollector::new(cfg)));
        }
        if has("vpc-endpoints") {
            v.push(Box::new(VpcEndpointCollector::new(cfg)));
        }
        if has("ssm-baselines") {
            v.push(Box::new(SsmPatchBaselineCollector::new(cfg)));
        }
        if has("ssm-params") {
            v.push(Box::new(SsmParameterConfigCollector::new(cfg)));
        }
        if has("ssm-assoc-status") {
            v.push(Box::new(SsmInstanceAssociationsStatusCollector::new(cfg)));
        }
        if has("time-sync") {
            v.push(Box::new(TimeSyncConfigCollector::new(cfg)));
        }
        if has("inspector-config") {
            v.push(Box::new(InspectorConfigCollector::new(cfg)));
        }
        if has("waf-config") {
            v.push(Box::new(WafFullConfigCollector::new(cfg)));
        }
        if has("elb-full-config") {
            v.push(Box::new(ElbFullConfigCollector::new(cfg)));
        }
        if has("org-config") {
            v.push(Box::new(OrgConfigCollector::new(cfg)));
        }
        if has("account-contacts") {
            v.push(Box::new(AccountContactsCollector::new(cfg)));
        }
        if has("saml-providers") {
            v.push(Box::new(SamlProviderCollector::new(cfg)));
        }
        if has("iam-account-summary") {
            v.push(Box::new(IamAccountSummaryCollector::new(cfg)));
        }
        if has("sns-policies") {
            v.push(Box::new(SnsTopicPoliciesCollector::new(cfg)));
        }
        if has("backup-plans") {
            v.push(Box::new(BackupPlanConfigCollector::new(cfg)));
        }
        if has("backup-vaults") {
            v.push(Box::new(BackupVaultConfigCollector::new(cfg)));
        }
        if has("backup-region-settings") {
            v.push(Box::new(BackupRegionSettingsCollector::new(cfg)));
        }
        if has("rds-backup-config") {
            v.push(Box::new(RdsBackupConfigCollector::new(cfg)));
        }
        if has("doc-repo-backup") {
            v.push(Box::new(DocRepoBackupConfigCollector::new(cfg)));
        }
        if has("lambda-config") {
            v.push(Box::new(LambdaConfigCollector::new(cfg)));
        }
        if has("lambda-permissions") {
            v.push(Box::new(LambdaPermissionsCollector::new(cfg)));
        }
        if has("ecr-config") {
            v.push(Box::new(EcrRepoConfigCollector::new(cfg)));
        }
        if has("client-vpn") {
            v.push(Box::new(AwsClientVpnCollector::new(cfg)));
        }
        if has("route53-zones") {
            v.push(Box::new(Route53ZonesCollector::new(cfg)));
        }
        if has("route53-resolver") {
            v.push(Box::new(Route53ResolverRulesCollector::new(cfg)));
        }
        if has("route53-dnssec") {
            v.push(Box::new(Route53DnssecCollector::new(cfg)));
        }
        if has("resource-tags") {
            v.push(Box::new(ResourceTaggingCollector::new(cfg)));
        }
        if has("secrets-policies") {
            v.push(Box::new(SecretsManagerPoliciesCollector::new(cfg)));
        }
        if has("config-timeline") {
            v.push(Box::new(ConfigResourceTimelineCollector::new(cfg)));
        }
        if has("config-compliance") {
            v.push(Box::new(ConfigComplianceHistoryCollector::new(cfg)));
        }
        if has("config-snapshot") {
            v.push(Box::new(ConfigSnapshotCollector::new(cfg)));
        }
        if has("ct-iam-changes") {
            v.push(Box::new(CloudTrailIamChangesCollector::new(cfg)));
        }
        if has("cfn-drift") {
            v.push(Box::new(CloudFormationDriftCollector::new(cfg)));
        }
        if has("ssm-patch-detail") {
            v.push(Box::new(SsmPatchDetailCollector::new(cfg)));
        }
        if has("ssm-patch-summary") {
            v.push(Box::new(SsmPatchSummaryCollector::new(cfg)));
        }
        if has("ssm-patch-exec") {
            v.push(Box::new(SsmPatchExecutionCollector::new(cfg)));
        }
        if has("ssm-maint-windows") {
            v.push(Box::new(SsmMaintenanceWindowCollector::new(cfg)));
        }
        if has("cw-config-alarms") {
            v.push(Box::new(CloudWatchConfigAlarmsCollector::new(cfg)));
        }
        if has("change-event-rules") {
            v.push(Box::new(ChangeEventRulesCollector::new(cfg)));
        }
        if has("ssm-sessions") {
            v.push(Box::new(SsmSessionsCollector::new(cfg)));
        }
        if has("ssm-software-inventory") {
            v.push(Box::new(SsmSoftwareInventoryCollector::new(cfg)));
        }
        if has("ssm-allowlist") {
            v.push(Box::new(SsmApplicationAllowlistCollector::new(cfg)));
        }
        if has("ssm-automation") {
            v.push(Box::new(SsmAutomationRunbooksCollector::new(cfg)));
        }
        if has("session-timeouts") {
            v.push(Box::new(SessionTimeoutConfigCollector::new(cfg)));
        }
        if has("tgw-peering") {
            v.push(Box::new(TransitGatewayPeeringCollector::new(cfg)));
        }

        v
    }

    fn json_collectors(&self) -> Vec<Box<dyn JsonCollector>> {
        let names: Vec<&str> = self.selected.iter().map(String::as_str).collect();
        let has = |n: &str| names.contains(&n);
        let cfg = &self.config;
        let mut v: Vec<Box<dyn JsonCollector>> = Vec::new();

        if has("iam-roles") {
            v.push(Box::new(IamRoleCollector::new(cfg)));
        }
        if has("iam-role-policies") {
            v.push(Box::new(IamRolePoliciesCollector::new(cfg)));
        }
        if has("iam-user-policies") {
            v.push(Box::new(IamUserPoliciesCollector::new(cfg)));
        }
        if has("eventbridge-rules") {
            v.push(Box::new(EventBridgeRulesCollector::new(cfg)));
        }
        if has("ct-config-changes") {
            v.push(Box::new(CloudTrailConfigChangesCollector::new(cfg)));
        }
        if has("kms-config") {
            v.push(Box::new(KmsKeyConfigCollector::new(cfg)));
        }

        v
    }

    fn evidence_collectors(&self) -> Vec<Box<dyn EvidenceCollector>> {
        let names: Vec<&str> = self.selected.iter().map(String::as_str).collect();
        let has = |n: &str| names.contains(&n);
        let cfg = &self.config;
        let mut v: Vec<Box<dyn EvidenceCollector>> = Vec::new();

        if has("cloudtrail") {
            v.push(Box::new(CloudTrailCollector::new(cfg)));
        }
        if has("backup") {
            v.push(Box::new(BackupCollector::new(cfg)));
        }
        if has("rds") {
            v.push(Box::new(RdsCollector::new(cfg)));
        }

        v
    }
}
