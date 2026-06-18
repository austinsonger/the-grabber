use crate::evidence::{CsvCollector, EvidenceCollector, JsonCollector};
use crate::providers::{CloudProvider, ProviderFactory};

use crate::providers::aws::{
    access_analyzer::AccessAnalyzerCollector,
    account_config::{AccountContactsCollector, IamAccountSummaryCollector, SamlProviderCollector},
    acm::AcmCertCollector,
    acm_pca::AcmPrivateCaCollector,
    alb_logs::AlbLogsCollector,
    apigateway::ApiGatewayCollector,
    apigateway_deep::ApiGatewayDeepCollector,
    appconfig::AppConfigDeploymentsCollector,
    appmesh_tls::AppMeshTlsCollector,
    artifact_reports::ArtifactReportsCollector,
    athena_saved_queries::AthenaSavedQueriesCollector,
    audit_manager::AuditManagerCollector,
    autoscaling::AutoScalingCollector,
    backup::BackupCollector,
    backup_config::{
        BackupPlanConfigCollector, BackupVaultConfigCollector, RdsBackupConfigCollector,
    },
    backup_copy_actions::BackupCopyActionsCollector,
    backup_restore_testing::BackupRestoreTestingCollector,
    backup_vaultlock::BackupVaultLockCollector,
    bedrock::BedrockCollector,
    bedrock_kb::BedrockKbCollector,
    budgets_collector::BudgetsCollector,
    cfn_stacksets::CfnStackSetsCollector,
    client_vpn::AwsClientVpnCollector,
    cloudformation_drift::CloudFormationDriftCollector,
    cloudfront::CloudFrontCollector,
    cloudfront_oac::CloudFrontOacCollector,
    cloudtrail::CloudTrailCollector,
    cloudtrail_accountmgmt::CloudTrailAccountMgmtCollector,
    cloudtrail_config::CloudTrailFullConfigCollector,
    cloudtrail_details::{
        CloudTrailChangeEventsCollector, CloudTrailEventSelectorsCollector,
        CloudTrailLogValidationCollector, CloudTrailS3PolicyCollector, S3DataEventsCollector,
    },
    cloudtrail_iam::{CloudTrailConfigChangesCollector, CloudTrailIamChangesCollector},
    cloudtrail_insights::CloudTrailInsightsCollector,
    cloudtrail_inventory::CloudTrailInventoryCollector,
    cloudtrail_lake::CloudTrailLakeCollector,
    cloudtrail_privileged::CloudTrailPrivilegedCollector,
    cloudtrail_sessions::CloudTrailSessionEventsCollector,
    cloudwatch::MetricFilterAlarmCollector,
    cloudwatch_alarms::CloudWatchConfigAlarmsCollector,
    cloudwatch_config::{CwLogGroupConfigCollector, MetricFilterConfigCollector},
    cloudwatch_resources::{CloudWatchAlarmCollector, CloudWatchLogGroupCollector},
    codeartifact::CodeArtifactCollector,
    codepipeline_codebuild::CodePipelineCodeBuildCollector,
    cognito::CognitoUserPoolCollector,
    compute_optimizer::ComputeOptimizerCollector,
    config_aggregators::ConfigAggregatorsCollector,
    config_conformance::ConfigConformanceCollector,
    config_history::ConfigHistoryCollector,
    config_rules::ConfigRulesCollector,
    config_timeline::{
        ConfigComplianceHistoryCollector, ConfigResourceTimelineCollector, ConfigSnapshotCollector,
    },
    contributor_insights::ContributorInsightsCollector,
    control_tower::ControlTowerCollector,
    cost_anomaly::CostAnomalyCollector,
    cw_anomaly_detectors::CloudWatchAnomalyDetectorsCollector,
    detective_graphs::DetectiveGraphsCollector,
    dms::DmsCollector,
    drs_replication::DrsReplicationCollector,
    dx_vpn::DxVpnCollector,
    dynamodb::DynamoDbCollector,
    ebs::EbsCollector,
    ec2_config::{
        Ec2InstanceConfigCollector, RouteTableConfigCollector, SecurityGroupConfigCollector,
        VpcConfigCollector,
    },
    ec2_detailed::Ec2DetailedCollector,
    ec2_inventory::{Ec2InstanceCollector, RouteTableCollector, SecurityGroupCollector},
    ecr_config::EcrRepoConfigCollector,
    ecr_replication::EcrReplicationCollector,
    ecr_signatures::EcrSignaturesCollector,
    ecs::EcsClusterCollector,
    ecs_task_defs::EcsTaskDefsCollector,
    efs::EfsCollector,
    eks::EksClusterCollector,
    eks_access_entries::EksAccessEntriesCollector,
    eks_addons::EksAddonsCollector,
    eks_pod_identity::EksPodIdentityCollector,
    elasticache::{ElastiCacheCollector, ElastiCacheGlobalCollector},
    elb::{LoadBalancerCollector, LoadBalancerListenerCollector},
    elb_config::ElbFullConfigCollector,
    eventbridge_archives::EventBridgeArchivesCollector,
    firehose::FirehoseDeliveryStreamsCollector,
    fis::FisCollector,
    fms_policies::FmsPoliciesCollector,
    global_accelerator::GlobalAcceleratorCollector,
    glue_catalog::GlueCatalogCollector,
    guardduty::GuardDutyCollector,
    guardduty_config::{GuardDutyConfigCollector, GuardDutySuppressionCollector},
    guardduty_coverage::GuardDutyCoverageCollector,
    guardduty_protection_plans::GdProtectionPlansCollector,
    health::AwsHealthCollector,
    iam_access_advisor::IamAccessAdvisorCollector,
    iam_boundaries::IamBoundariesCollector,
    iam_certs::IamCertCollector,
    iam_credential_report::IamCredentialReportCollector,
    iam_inventory::{
        IamAccessKeyCollector, IamPolicyCollector, IamRoleCollector, IamUserCollector,
    },
    iam_policies::{
        IamPasswordPolicyCollector, IamRolePoliciesCollector, IamUserPoliciesCollector,
    },
    iam_roles_anywhere::IamRolesAnywhereCollector,
    iam_roles_lastused::IamRolesLastUsedCollector,
    iam_simulator::IamSimulatorCollector,
    iam_trusts::IamTrustsCollector,
    identity_center::IdentityCenterCollector,
    identity_center_inline::IdentityCenterInlineCollector,
    identity_store::IdentityStoreCollector,
    inspector::InspectorCollector,
    inspector_config::InspectorConfigCollector,
    inspector_coverage::Inspector2CoverageCollector,
    inspector_ecr::InspectorEcrImagesCollector,
    inspector_history::InspectorFindingsHistoryCollector,
    inspector_sbom::{InspectorSbomCollector, InspectorSbomConfig},
    inspector_suppression::Inspector2SuppressionCollector,
    iot_device_defender::IotDeviceDefenderCollector,
    iot_things::IotThingsCollector,
    kinesis::KinesisStreamsCollector,
    kms::KmsKeyCollector,
    kms_config::{EbsEncryptionConfigCollector, KmsKeyConfigCollector},
    kms_grants::KmsGrantsCollector,
    kms_policies::{EbsDefaultEncryptionCollector, KmsKeyPolicyCollector},
    lakeformation_perms::LakeFormationPermsCollector,
    lambda_config::{LambdaConfigCollector, LambdaPermissionsCollector},
    launch_templates::LaunchTemplateCollector,
    license_manager::LicenseManagerCollector,
    logs_insights_queries::LogsInsightsSavedQueriesCollector,
    macie::MacieCollector,
    macie_jobs::MacieJobsCollector,
    mgn::MgnSourceServersCollector,
    msk::MskClustersCollector,
    network_firewall::NetworkFirewallCollector,
    network_gateways::{InternetGatewayCollector, NatGatewayCollector},
    nfw_rules::NfwRulesCollector,
    oam_observability::OamObservabilityCollector,
    opensearch::OpenSearchDomainsCollector,
    org_config::OrgConfigCollector,
    org_delegated::OrgDelegatedCollector,
    org_tag_policies::OrgTagPoliciesCollector,
    organizations::OrganizationsSCPCollector,
    privatelink_services::PrivateLinkServicesCollector,
    public_resources::PublicResourceCollector,
    r53_dns_firewall::R53DnsFirewallCollector,
    rds::RdsCollector,
    rds_inventory::RdsInventoryCollector,
    rds_pitr::RdsPitrCollector,
    rds_snapshots::RdsSnapshotCollector,
    redshift::RedshiftClustersCollector,
    resilience_hub::ResilienceHubCollector,
    resource_drift::ResourceDriftCollector,
    resource_explorer::ResourceExplorerCollector,
    route53_arc::Route53ArcCollector,
    route53_config::{
        Route53DnssecCollector, Route53ResolverRulesCollector, Route53ZonesCollector,
    },
    s3_config::S3BucketConfigCollector,
    s3_detail::{
        S3BucketPolicyDetailCollector, S3EncryptionConfigCollector, S3LoggingConfigCollector,
        S3PublicAccessBlockCollector,
    },
    s3_inventory::S3BucketLoggingCollector,
    s3_object_lock::S3ObjectLockCollector,
    s3_policies::S3PoliciesCollector,
    s3_replication::S3ReplicationCollector,
    sagemaker::SageMakerPostureCollector,
    savings_plans::SavingsPlansCollector,
    scp_attachments::ScpAttachmentsCollector,
    secrets_extended::SecretsManagerPoliciesCollector,
    secretsmanager::SecretsManagerCollector,
    security_lake::SecurityLakeCollector,
    security_svc_config::{
        AwsConfigRecorderCollector, GuardDutyFullConfigCollector, SecurityHubConfigCollector,
    },
    securityhub::SecurityHubCollector,
    securityhub_insights::SecurityHubInsightsCollector,
    securityhub_standards::SecurityHubStandardsCollector,
    service_catalog::ServiceCatalogCollector,
    service_quotas::ServiceQuotasCollector,
    shield::ShieldCollector,
    signer::SignerCollector,
    snowball::SnowballJobsCollector,
    sns::SnsSubscriptionCollector,
    sns_eventbridge::{
        ChangeEventRulesCollector, EventBridgeRulesCollector, SnsTopicPoliciesCollector,
    },
    ssm::{SsmManagedInstanceCollector, SsmPatchComplianceCollector},
    ssm_associations::SsmAssociationsCollector,
    ssm_automation::SsmAutomationCollector,
    ssm_change_requests::SsmChangeRequestsCollector,
    ssm_compliance_summary::SsmComplianceSummaryCollector,
    ssm_extended::{
        SsmParameterConfigCollector, SsmPatchBaselineCollector, TimeSyncConfigCollector,
    },
    ssm_opsitems::SsmOpsItemsCollector,
    ssm_patch_detail::{
        SsmMaintenanceWindowCollector, SsmPatchDetailCollector, SsmPatchExecutionCollector,
        SsmPatchSummaryCollector,
    },
    ssm_sessions::SsmSessionsCollector,
    ssm_software_inventory::SsmSoftwareInventoryCollector,
    step_functions::StepFunctionsExecutionsCollector,
    sts_federation::StsFederationCollector,
    synthetics::SyntheticsCanariesCollector,
    ta_priority::TaPriorityCollector,
    tagging_compliance::TaggingComplianceCollector,
    tagging_config::ResourceTaggingCollector,
    tgw_routes::TgwRoutesCollector,
    trusted_advisor::TrustedAdvisorCollector,
    verified_permissions::VerifiedPermissionsCollector,
    vpc::{NetworkAclCollector, VpcCollector},
    vpc_endpoints::VpcEndpointCollector,
    vpc_lattice::VpcLatticeCollector,
    vpc_traffic_mirror::VpcTrafficMirrorCollector,
    vpcflowlogs::VpcFlowLogCollector,
    waf::WafCollector,
    waf_destinations::WafDestinationsCollector,
    waf_full_config::WafFullConfigCollector,
    waf_logging::WafLoggingCollector,
    waf_rulegroups_deep::WafRuleGroupsDeepCollector,
    well_architected::WellArchitectedCollector,
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
        if has("iam-credential-report") {
            v.push(Box::new(IamCredentialReportCollector::new(cfg)));
        }
        if has("iam-access-advisor") {
            v.push(Box::new(IamAccessAdvisorCollector::new(cfg)));
        }
        if has("iam-roles-lastused") {
            v.push(Box::new(IamRolesLastUsedCollector::new(cfg)));
        }
        if has("identity-center") {
            v.push(Box::new(IdentityCenterCollector::new(cfg)));
        }
        if has("identity-store") {
            v.push(Box::new(IdentityStoreCollector::new(cfg)));
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
        if has("iam-users") {
            v.push(Box::new(IamUserCollector::new(cfg)));
        }
        if has("iam-policies") {
            v.push(Box::new(IamPolicyCollector::new(cfg)));
        }
        if has("iam-access-keys") {
            v.push(Box::new(IamAccessKeyCollector::new(cfg)));
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
        if has("config-conformance") {
            v.push(Box::new(ConfigConformanceCollector::new(cfg)));
        }
        if has("config-aggregators") {
            v.push(Box::new(ConfigAggregatorsCollector::new(cfg)));
        }
        if has("well-architected") {
            v.push(Box::new(WellArchitectedCollector::new(cfg)));
        }
        if has("service-catalog") {
            v.push(Box::new(ServiceCatalogCollector::new(cfg)));
        }
        if has("resource-drift") {
            v.push(Box::new(ResourceDriftCollector::new(cfg)));
        }
        if has("cfn-stacksets") {
            v.push(Box::new(CfnStackSetsCollector::new(cfg)));
        }
        if has("ta-priority") {
            v.push(Box::new(TaPriorityCollector::new(cfg)));
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
        if has("ct-account-mgmt") {
            v.push(Box::new(CloudTrailAccountMgmtCollector::new(cfg)));
        }
        if has("ct-sessions") {
            v.push(Box::new(CloudTrailSessionEventsCollector::new(cfg)));
        }
        if has("ct-privileged") {
            v.push(Box::new(CloudTrailPrivilegedCollector::new(cfg)));
        }
        if has("ct-insights") {
            v.push(Box::new(CloudTrailInsightsCollector::new(cfg)));
        }
        if has("ct-lake") {
            v.push(Box::new(CloudTrailLakeCollector::new(cfg)));
        }
        if has("athena-log-queries") {
            v.push(Box::new(AthenaSavedQueriesCollector::new(cfg)));
        }
        if has("logs-insights-queries") {
            v.push(Box::new(LogsInsightsSavedQueriesCollector::new(cfg)));
        }
        if has("eb-archives") {
            v.push(Box::new(EventBridgeArchivesCollector::new(cfg)));
        }
        if has("firehose-streams") {
            v.push(Box::new(FirehoseDeliveryStreamsCollector::new(cfg)));
        }
        if has("cw-contributor-insights") {
            v.push(Box::new(ContributorInsightsCollector::new(cfg)));
        }
        if has("detective-graphs") {
            v.push(Box::new(DetectiveGraphsCollector::new(cfg)));
        }
        if has("sh-insights") {
            v.push(Box::new(SecurityHubInsightsCollector::new(cfg)));
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
        if has("guardduty-coverage") {
            v.push(Box::new(GuardDutyCoverageCollector::new(cfg)));
        }
        if has("guardduty-protection-plans") {
            v.push(Box::new(GdProtectionPlansCollector::new(cfg)));
        }
        if has("sh-standards") {
            v.push(Box::new(SecurityHubStandardsCollector::new(cfg)));
        }
        if has("network-firewall") {
            v.push(Box::new(NetworkFirewallCollector::new(cfg)));
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
        if has("privatelink-services") {
            v.push(Box::new(PrivateLinkServicesCollector::new(cfg)));
        }
        if has("r53-dns-firewall") {
            v.push(Box::new(R53DnsFirewallCollector::new(cfg)));
        }
        if has("kms-grants") {
            v.push(Box::new(KmsGrantsCollector::new(cfg)));
        }
        if has("appmesh-tls") {
            v.push(Box::new(AppMeshTlsCollector::new(cfg)));
        }
        if has("signer-profiles") {
            v.push(Box::new(SignerCollector::new(cfg)));
        }
        if has("ecr-signatures") {
            v.push(Box::new(EcrSignaturesCollector::new(cfg)));
        }
        if has("codeartifact-repos") {
            v.push(Box::new(CodeArtifactCollector::new(cfg)));
        }
        if has("artifact-reports") {
            v.push(Box::new(ArtifactReportsCollector::new(cfg)));
        }
        if has("trusted-advisor") {
            v.push(Box::new(TrustedAdvisorCollector::new(cfg)));
        }
        if has("aws-health") {
            v.push(Box::new(AwsHealthCollector::new(cfg)));
        }
        if has("codepipeline-codebuild") {
            v.push(Box::new(CodePipelineCodeBuildCollector::new(cfg)));
        }
        if has("ssm-baselines") {
            v.push(Box::new(SsmPatchBaselineCollector::new(cfg)));
        }
        if has("ssm-params") {
            v.push(Box::new(SsmParameterConfigCollector::new(cfg)));
        }
        if has("time-sync") {
            v.push(Box::new(TimeSyncConfigCollector::new(cfg)));
        }
        if has("inspector-config") {
            v.push(Box::new(InspectorConfigCollector::new(cfg)));
        }
        if has("inspector-coverage") {
            v.push(Box::new(Inspector2CoverageCollector::new(cfg)));
        }
        if has("inspector-suppression") {
            v.push(Box::new(Inspector2SuppressionCollector::new(cfg)));
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
        if has("org-delegated") {
            v.push(Box::new(OrgDelegatedCollector::new(cfg)));
        }
        if has("control-tower") {
            v.push(Box::new(ControlTowerCollector::new(cfg)));
        }
        if has("audit-manager") {
            v.push(Box::new(AuditManagerCollector::new(cfg)));
        }
        if has("resource-explorer") {
            v.push(Box::new(ResourceExplorerCollector::new(cfg)));
        }
        if has("fis-experiments") {
            v.push(Box::new(FisCollector::new(cfg)));
        }
        if has("synthetics-canaries") {
            v.push(Box::new(SyntheticsCanariesCollector::new(cfg)));
        }
        if has("macie-jobs") {
            v.push(Box::new(MacieJobsCollector::new(cfg)));
        }
        if has("cost-anomaly") {
            v.push(Box::new(CostAnomalyCollector::new(cfg)));
        }
        if has("budgets") {
            v.push(Box::new(BudgetsCollector::new(cfg)));
        }
        if has("savings-plans-ri") {
            v.push(Box::new(SavingsPlansCollector::new(cfg)));
        }
        if has("compute-optimizer") {
            v.push(Box::new(ComputeOptimizerCollector::new(cfg)));
        }
        if has("tagging-compliance") {
            v.push(Box::new(TaggingComplianceCollector::new(cfg)));
        }
        if has("org-tag-policies") {
            v.push(Box::new(OrgTagPoliciesCollector::new(cfg)));
        }
        if has("scp-attachments") {
            v.push(Box::new(ScpAttachmentsCollector::new(cfg)));
        }
        if has("iam-simulator") {
            v.push(Box::new(IamSimulatorCollector::new(cfg)));
        }
        if has("idc-inline-policies") {
            v.push(Box::new(IdentityCenterInlineCollector::new(cfg)));
        }
        if has("roles-anywhere") {
            v.push(Box::new(IamRolesAnywhereCollector::new(cfg)));
        }
        if has("iam-boundaries") {
            v.push(Box::new(IamBoundariesCollector::new(cfg)));
        }
        if has("verified-permissions") {
            v.push(Box::new(VerifiedPermissionsCollector::new(cfg)));
        }
        if has("security-lake") {
            v.push(Box::new(SecurityLakeCollector::new(cfg)));
        }
        if has("fms-policies") {
            v.push(Box::new(FmsPoliciesCollector::new(cfg)));
        }
        if has("waf-rulegroups-deep") {
            v.push(Box::new(WafRuleGroupsDeepCollector::new(cfg)));
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
        if has("rds-backup-config") {
            v.push(Box::new(RdsBackupConfigCollector::new(cfg)));
        }
        if has("backup-vaultlock") {
            v.push(Box::new(BackupVaultLockCollector::new(cfg)));
        }
        if has("backup-copy-actions") {
            v.push(Box::new(BackupCopyActionsCollector::new(cfg)));
        }
        if has("backup-restore-testing") {
            v.push(Box::new(BackupRestoreTestingCollector::new(cfg)));
        }
        if has("drs-replication") {
            v.push(Box::new(DrsReplicationCollector::new(cfg)));
        }
        if has("mgn-source-servers") {
            v.push(Box::new(MgnSourceServersCollector::new(cfg)));
        }
        if has("dms") {
            v.push(Box::new(DmsCollector::new(cfg)));
        }
        if has("snowball-jobs") {
            v.push(Box::new(SnowballJobsCollector::new(cfg)));
        }
        if has("sagemaker-posture") {
            v.push(Box::new(SageMakerPostureCollector::new(cfg)));
        }
        if has("bedrock") {
            v.push(Box::new(BedrockCollector::new(cfg)));
        }
        if has("bedrock-kb") {
            v.push(Box::new(BedrockKbCollector::new(cfg)));
        }
        if has("iot-things") {
            v.push(Box::new(IotThingsCollector::new(cfg)));
        }
        if has("iot-defender") {
            v.push(Box::new(IotDeviceDefenderCollector::new(cfg)));
        }
        if has("r53-arc") {
            v.push(Box::new(Route53ArcCollector::new(cfg)));
        }
        if has("rds-pitr") {
            v.push(Box::new(RdsPitrCollector::new(cfg)));
        }
        if has("s3-replication") {
            v.push(Box::new(S3ReplicationCollector::new(cfg)));
        }
        if has("s3-object-lock") {
            v.push(Box::new(S3ObjectLockCollector::new(cfg)));
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
        if has("cw-anomaly") {
            v.push(Box::new(CloudWatchAnomalyDetectorsCollector::new(cfg)));
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
        if has("ssm-compliance-summary") {
            v.push(Box::new(SsmComplianceSummaryCollector::new(cfg)));
        }
        if has("ssm-associations") {
            v.push(Box::new(SsmAssociationsCollector::new(cfg)));
        }
        if has("ssm-automation") {
            v.push(Box::new(SsmAutomationCollector::new(cfg)));
        }
        if has("ssm-opsitems") {
            v.push(Box::new(SsmOpsItemsCollector::new(cfg)));
        }
        if has("ssm-change-requests") {
            v.push(Box::new(SsmChangeRequestsCollector::new(cfg)));
        }
        if has("resilience-hub") {
            v.push(Box::new(ResilienceHubCollector::new(cfg)));
        }
        if has("oam-observability") {
            v.push(Box::new(OamObservabilityCollector::new(cfg)));
        }
        if has("appconfig-deployments") {
            v.push(Box::new(AppConfigDeploymentsCollector::new(cfg)));
        }
        if has("eks-addons") {
            v.push(Box::new(EksAddonsCollector::new(cfg)));
        }
        if has("eks-access-entries") {
            v.push(Box::new(EksAccessEntriesCollector::new(cfg)));
        }
        if has("eks-pod-identity") {
            v.push(Box::new(EksPodIdentityCollector::new(cfg)));
        }
        if has("ecs-task-defs") {
            v.push(Box::new(EcsTaskDefsCollector::new(cfg)));
        }
        if has("ecr-replication") {
            v.push(Box::new(EcrReplicationCollector::new(cfg)));
        }
        if has("glue-catalog") {
            v.push(Box::new(GlueCatalogCollector::new(cfg)));
        }
        if has("lakeformation-perms") {
            v.push(Box::new(LakeFormationPermsCollector::new(cfg)));
        }
        if has("cognito-pools") {
            v.push(Box::new(CognitoUserPoolCollector::new(cfg)));
        }
        if has("sts-federation") {
            v.push(Box::new(StsFederationCollector::new(cfg)));
        }
        if has("waf-destinations") {
            v.push(Box::new(WafDestinationsCollector::new(cfg)));
        }
        if has("vpc-mirror") {
            v.push(Box::new(VpcTrafficMirrorCollector::new(cfg)));
        }
        if has("tgw-routes") {
            v.push(Box::new(TgwRoutesCollector::new(cfg)));
        }
        if has("redshift-clusters") {
            v.push(Box::new(RedshiftClustersCollector::new(cfg)));
        }
        if has("opensearch-domains") {
            v.push(Box::new(OpenSearchDomainsCollector::new(cfg)));
        }
        if has("msk-clusters") {
            v.push(Box::new(MskClustersCollector::new(cfg)));
        }
        if has("sfn-executions") {
            v.push(Box::new(StepFunctionsExecutionsCollector::new(cfg)));
        }
        if has("kinesis-streams") {
            v.push(Box::new(KinesisStreamsCollector::new(cfg)));
        }
        if has("vpc-lattice") {
            v.push(Box::new(VpcLatticeCollector::new(cfg)));
        }
        if has("dx-vpn") {
            v.push(Box::new(DxVpnCollector::new(cfg)));
        }
        if has("global-accelerator") {
            v.push(Box::new(GlobalAcceleratorCollector::new(cfg)));
        }
        if has("apigw-deep") {
            v.push(Box::new(ApiGatewayDeepCollector::new(cfg)));
        }
        if has("cloudfront-oac") {
            v.push(Box::new(CloudFrontOacCollector::new(cfg)));
        }
        if has("nfw-rules") {
            v.push(Box::new(NfwRulesCollector::new(cfg)));
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
