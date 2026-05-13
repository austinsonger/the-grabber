use crate::evidence::{CsvCollector, EvidenceCollector, JsonCollector};
use crate::providers::aws::{
    access_analyzer::AccessAnalyzerCollector,
    account_config::{AccountContactsCollector, IamAccountSummaryCollector, SamlProviderCollector},
    acm::AcmCertCollector,
    alb_logs::AlbLogsCollector,
    apigateway::ApiGatewayCollector,
    autoscaling::AutoScalingCollector,
    backup::BackupCollector,
    backup_config::{BackupPlanConfigCollector, BackupVaultConfigCollector, RdsBackupConfigCollector},
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
    dynamodb::DynamoDbCollector,
    ebs::EbsCollector,
    ec2_config::{
        Ec2InstanceConfigCollector, RouteTableConfigCollector, SecurityGroupConfigCollector,
        VpcConfigCollector,
    },
    ec2_detailed::Ec2DetailedCollector,
    ec2_inventory::{Ec2InstanceCollector, RouteTableCollector, SecurityGroupCollector},
    ecr::EcrScanCollector,
    ecr_config::EcrRepoConfigCollector,
    ecs::EcsClusterCollector,
    efs::EfsCollector,
    eks::EksClusterCollector,
    elasticache::{ElastiCacheCollector, ElastiCacheGlobalCollector},
    elb::{LoadBalancerCollector, LoadBalancerListenerCollector},
    elb_config::ElbFullConfigCollector,
    guardduty::GuardDutyCollector,
    guardduty_config::{GuardDutyConfigCollector, GuardDutySuppressionCollector},
    iam_certs::IamCertCollector,
    iam_inventory::{IamAccessKeyCollector, IamPolicyCollector, IamRoleCollector, IamUserCollector},
    iam_policies::{
        IamPasswordPolicyCollector, IamRolePoliciesCollector, IamUserPoliciesCollector,
    },
    iam_trusts::IamTrustsCollector,
    inspector::InspectorCollector,
    inspector_config::InspectorConfigCollector,
    inspector_ecr::InspectorEcrImagesCollector,
    inspector_history::InspectorFindingsHistoryCollector,
    kms::KmsKeyCollector,
    kms_config::{EbsEncryptionConfigCollector, KmsKeyConfigCollector},
    kms_policies::{EbsDefaultEncryptionCollector, KmsKeyPolicyCollector},
    lambda_config::{LambdaConfigCollector, LambdaPermissionsCollector},
    launch_templates::LaunchTemplateCollector,
    macie::MacieCollector,
    network_gateways::{InternetGatewayCollector, NatGatewayCollector},
    org_config::OrgConfigCollector,
    organizations::OrganizationsSCPCollector,
    public_resources::PublicResourceCollector,
    rds::RdsCollector,
    rds_inventory::RdsInventoryCollector,
    rds_snapshots::RdsSnapshotCollector,
    route53_config::{Route53ResolverRulesCollector, Route53ZonesCollector},
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
    sns::SnsSubscriptionCollector,
    sns_eventbridge::{
        ChangeEventRulesCollector, EventBridgeRulesCollector, SnsTopicPoliciesCollector,
    },
    ssm::{SsmManagedInstanceCollector, SsmPatchComplianceCollector},
    ssm_extended::{SsmParameterConfigCollector, SsmPatchBaselineCollector, TimeSyncConfigCollector},
    ssm_patch_detail::{
        SsmMaintenanceWindowCollector, SsmPatchDetailCollector, SsmPatchExecutionCollector,
        SsmPatchSummaryCollector,
    },
    tagging_config::ResourceTaggingCollector,
    vpc::{NetworkAclCollector, VpcCollector},
    vpc_endpoints::VpcEndpointCollector,
    vpcflowlogs::VpcFlowLogCollector,
    waf::WafCollector,
    waf_full_config::WafFullConfigCollector,
    waf_logging::WafLoggingCollector,
};

pub fn build_csv_collectors(
    names: &[&str],
    config: &aws_config::SdkConfig,
) -> Vec<Box<dyn CsvCollector>> {
    let has = |n: &str| names.contains(&n);
    let mut v: Vec<Box<dyn CsvCollector>> = Vec::new();

    if has("vpc")                  { v.push(Box::new(VpcCollector::new(config))); }
    if has("nacl")                 { v.push(Box::new(NetworkAclCollector::new(config))); }
    if has("waf")                  { v.push(Box::new(WafCollector::new(config))); }
    if has("elasticache")          { v.push(Box::new(ElastiCacheCollector::new(config))); }
    if has("elasticache-global")   { v.push(Box::new(ElastiCacheGlobalCollector::new(config))); }
    if has("efs")                  { v.push(Box::new(EfsCollector::new(config))); }
    if has("dynamodb")             { v.push(Box::new(DynamoDbCollector::new(config))); }
    if has("ebs")                  { v.push(Box::new(EbsCollector::new(config))); }
    if has("rds-inventory")        { v.push(Box::new(RdsInventoryCollector::new(config))); }
    if has("cloudtrail-config")    { v.push(Box::new(CloudTrailInventoryCollector::new(config))); }
    if has("sns")                  { v.push(Box::new(SnsSubscriptionCollector::new(config))); }
    if has("vpc-flow-logs")        { v.push(Box::new(VpcFlowLogCollector::new(config))); }
    if has("metric-filters")       { v.push(Box::new(MetricFilterAlarmCollector::new(config))); }
    if has("s3-logging")           { v.push(Box::new(S3BucketLoggingCollector::new(config))); }
    if has("iam-certs")            { v.push(Box::new(IamCertCollector::new(config))); }
    if has("elb")                  { v.push(Box::new(LoadBalancerCollector::new(config))); }
    if has("elb-listeners")        { v.push(Box::new(LoadBalancerListenerCollector::new(config))); }
    if has("acm")                  { v.push(Box::new(AcmCertCollector::new(config))); }
    if has("iam-users")            { v.push(Box::new(IamUserCollector::new(config))); }
    if has("iam-policies")         { v.push(Box::new(IamPolicyCollector::new(config))); }
    if has("iam-access-keys")      { v.push(Box::new(IamAccessKeyCollector::new(config))); }
    if has("guardduty")            { v.push(Box::new(GuardDutyCollector::new(config))); }
    if has("securityhub")          { v.push(Box::new(SecurityHubCollector::new(config))); }
    if has("config-rules")         { v.push(Box::new(ConfigRulesCollector::new(config))); }
    if has("security-groups")      { v.push(Box::new(SecurityGroupCollector::new(config))); }
    if has("route-tables")         { v.push(Box::new(RouteTableCollector::new(config))); }
    if has("ec2-instances")        { v.push(Box::new(Ec2InstanceCollector::new(config))); }
    if has("asg")                  { v.push(Box::new(AutoScalingCollector::new(config))); }
    if has("kms")                  { v.push(Box::new(KmsKeyCollector::new(config))); }
    if has("secrets")              { v.push(Box::new(SecretsManagerCollector::new(config))); }
    if has("s3-config")            { v.push(Box::new(S3BucketConfigCollector::new(config))); }
    if has("cw-alarms")            { v.push(Box::new(CloudWatchAlarmCollector::new(config))); }
    if has("cw-log-groups")        { v.push(Box::new(CloudWatchLogGroupCollector::new(config))); }
    if has("api-gateway")          { v.push(Box::new(ApiGatewayCollector::new(config))); }
    if has("cloudfront")           { v.push(Box::new(CloudFrontCollector::new(config))); }
    if has("ecs")                  { v.push(Box::new(EcsClusterCollector::new(config))); }
    if has("eks")                  { v.push(Box::new(EksClusterCollector::new(config))); }
    if has("iam-trusts")           { v.push(Box::new(IamTrustsCollector::new(config))); }
    if has("access-analyzer")      { v.push(Box::new(AccessAnalyzerCollector::new(config))); }
    if has("scp")                  { v.push(Box::new(OrganizationsSCPCollector::new(config))); }
    if has("ct-selectors")         { v.push(Box::new(CloudTrailEventSelectorsCollector::new(config))); }
    if has("ct-validation")        { v.push(Box::new(CloudTrailLogValidationCollector::new(config))); }
    if has("ct-s3-policy")         { v.push(Box::new(CloudTrailS3PolicyCollector::new(config))); }
    if has("ct-changes")           { v.push(Box::new(CloudTrailChangeEventsCollector::new(config))); }
    if has("s3-data-events")       { v.push(Box::new(S3DataEventsCollector::new(config))); }
    if has("guardduty-config")     { v.push(Box::new(GuardDutyConfigCollector::new(config))); }
    if has("guardduty-rules")      { v.push(Box::new(GuardDutySuppressionCollector::new(config))); }
    if has("sh-standards")         { v.push(Box::new(SecurityHubStandardsCollector::new(config))); }
    if has("igw")                  { v.push(Box::new(InternetGatewayCollector::new(config))); }
    if has("nat-gateways")         { v.push(Box::new(NatGatewayCollector::new(config))); }
    if has("public-resources")     { v.push(Box::new(PublicResourceCollector::new(config))); }
    if has("ec2-detailed")         { v.push(Box::new(Ec2DetailedCollector::new(config))); }
    if has("ssm-instances")        { v.push(Box::new(SsmManagedInstanceCollector::new(config))); }
    if has("ssm-patches")          { v.push(Box::new(SsmPatchComplianceCollector::new(config))); }
    if has("kms-policies")         { v.push(Box::new(KmsKeyPolicyCollector::new(config))); }
    if has("ebs-encryption")       { v.push(Box::new(EbsDefaultEncryptionCollector::new(config))); }
    if has("rds-snapshots")        { v.push(Box::new(RdsSnapshotCollector::new(config))); }
    if has("s3-policies")          { v.push(Box::new(S3PoliciesCollector::new(config))); }
    if has("macie")                { v.push(Box::new(MacieCollector::new(config))); }
    if has("config-history")       { v.push(Box::new(ConfigHistoryCollector::new(config))); }
    if has("inspector")            { v.push(Box::new(InspectorCollector::new(config))); }
    if has("inspector-ecr-images") { v.push(Box::new(InspectorEcrImagesCollector::new(config))); }
    if has("inspector-history")    { v.push(Box::new(InspectorFindingsHistoryCollector::new(config))); }
    if has("ecr-scan")             { v.push(Box::new(EcrScanCollector::new(config))); }
    if has("waf-logging")          { v.push(Box::new(WafLoggingCollector::new(config))); }
    if has("alb-logs")             { v.push(Box::new(AlbLogsCollector::new(config))); }
    if has("iam-password-policy")  { v.push(Box::new(IamPasswordPolicyCollector::new(config))); }
    if has("ebs-config")           { v.push(Box::new(EbsEncryptionConfigCollector::new(config))); }
    if has("s3-encryption")        { v.push(Box::new(S3EncryptionConfigCollector::new(config))); }
    if has("s3-bucket-policy")     { v.push(Box::new(S3BucketPolicyDetailCollector::new(config))); }
    if has("s3-public-access")     { v.push(Box::new(S3PublicAccessBlockCollector::new(config))); }
    if has("s3-logging-config")    { v.push(Box::new(S3LoggingConfigCollector::new(config))); }
    if has("sg-config")            { v.push(Box::new(SecurityGroupConfigCollector::new(config))); }
    if has("vpc-config")           { v.push(Box::new(VpcConfigCollector::new(config))); }
    if has("rt-config")            { v.push(Box::new(RouteTableConfigCollector::new(config))); }
    if has("ec2-config")           { v.push(Box::new(Ec2InstanceConfigCollector::new(config))); }
    if has("ct-full-config")       { v.push(Box::new(CloudTrailFullConfigCollector::new(config))); }
    if has("cw-log-config")        { v.push(Box::new(CwLogGroupConfigCollector::new(config))); }
    if has("metric-filter-config") { v.push(Box::new(MetricFilterConfigCollector::new(config))); }
    if has("gd-full-config")       { v.push(Box::new(GuardDutyFullConfigCollector::new(config))); }
    if has("sh-config")            { v.push(Box::new(SecurityHubConfigCollector::new(config))); }
    if has("config-recorder")      { v.push(Box::new(AwsConfigRecorderCollector::new(config))); }
    if has("launch-templates")     { v.push(Box::new(LaunchTemplateCollector::new(config))); }
    if has("vpc-endpoints")        { v.push(Box::new(VpcEndpointCollector::new(config))); }
    if has("ssm-baselines")        { v.push(Box::new(SsmPatchBaselineCollector::new(config))); }
    if has("ssm-params")           { v.push(Box::new(SsmParameterConfigCollector::new(config))); }
    if has("time-sync")            { v.push(Box::new(TimeSyncConfigCollector::new(config))); }
    if has("inspector-config")     { v.push(Box::new(InspectorConfigCollector::new(config))); }
    if has("waf-config")           { v.push(Box::new(WafFullConfigCollector::new(config))); }
    if has("elb-full-config")      { v.push(Box::new(ElbFullConfigCollector::new(config))); }
    if has("org-config")           { v.push(Box::new(OrgConfigCollector::new(config))); }
    if has("account-contacts")     { v.push(Box::new(AccountContactsCollector::new(config))); }
    if has("saml-providers")       { v.push(Box::new(SamlProviderCollector::new(config))); }
    if has("iam-account-summary")  { v.push(Box::new(IamAccountSummaryCollector::new(config))); }
    if has("sns-policies")         { v.push(Box::new(SnsTopicPoliciesCollector::new(config))); }
    if has("backup-plans")         { v.push(Box::new(BackupPlanConfigCollector::new(config))); }
    if has("backup-vaults")        { v.push(Box::new(BackupVaultConfigCollector::new(config))); }
    if has("rds-backup-config")    { v.push(Box::new(RdsBackupConfigCollector::new(config))); }
    if has("lambda-config")        { v.push(Box::new(LambdaConfigCollector::new(config))); }
    if has("lambda-permissions")   { v.push(Box::new(LambdaPermissionsCollector::new(config))); }
    if has("ecr-config")           { v.push(Box::new(EcrRepoConfigCollector::new(config))); }
    if has("route53-zones")        { v.push(Box::new(Route53ZonesCollector::new(config))); }
    if has("route53-resolver")     { v.push(Box::new(Route53ResolverRulesCollector::new(config))); }
    if has("resource-tags")        { v.push(Box::new(ResourceTaggingCollector::new(config))); }
    if has("secrets-policies")     { v.push(Box::new(SecretsManagerPoliciesCollector::new(config))); }
    if has("config-timeline")      { v.push(Box::new(ConfigResourceTimelineCollector::new(config))); }
    if has("config-compliance")    { v.push(Box::new(ConfigComplianceHistoryCollector::new(config))); }
    if has("config-snapshot")      { v.push(Box::new(ConfigSnapshotCollector::new(config))); }
    if has("ct-iam-changes")       { v.push(Box::new(CloudTrailIamChangesCollector::new(config))); }
    if has("cfn-drift")            { v.push(Box::new(CloudFormationDriftCollector::new(config))); }
    if has("ssm-patch-detail")     { v.push(Box::new(SsmPatchDetailCollector::new(config))); }
    if has("ssm-patch-summary")    { v.push(Box::new(SsmPatchSummaryCollector::new(config))); }
    if has("ssm-patch-exec")       { v.push(Box::new(SsmPatchExecutionCollector::new(config))); }
    if has("ssm-maint-windows")    { v.push(Box::new(SsmMaintenanceWindowCollector::new(config))); }
    if has("cw-config-alarms")     { v.push(Box::new(CloudWatchConfigAlarmsCollector::new(config))); }
    if has("change-event-rules")   { v.push(Box::new(ChangeEventRulesCollector::new(config))); }

    v
}

pub fn build_json_inv_collectors(
    names: &[&str],
    config: &aws_config::SdkConfig,
) -> Vec<Box<dyn JsonCollector>> {
    let has = |n: &str| names.contains(&n);
    let mut v: Vec<Box<dyn JsonCollector>> = Vec::new();

    if has("iam-roles")         { v.push(Box::new(IamRoleCollector::new(config))); }
    if has("iam-role-policies") { v.push(Box::new(IamRolePoliciesCollector::new(config))); }
    if has("iam-user-policies") { v.push(Box::new(IamUserPoliciesCollector::new(config))); }
    if has("eventbridge-rules") { v.push(Box::new(EventBridgeRulesCollector::new(config))); }
    if has("ct-config-changes") { v.push(Box::new(CloudTrailConfigChangesCollector::new(config))); }
    if has("kms-config")        { v.push(Box::new(KmsKeyConfigCollector::new(config))); }

    v
}

pub fn build_json_collectors(
    names: &[&str],
    config: &aws_config::SdkConfig,
) -> Vec<Box<dyn EvidenceCollector>> {
    let has = |n: &str| names.contains(&n);
    let mut v: Vec<Box<dyn EvidenceCollector>> = Vec::new();

    if has("cloudtrail") { v.push(Box::new(CloudTrailCollector::new(config))); }
    if has("backup")     { v.push(Box::new(BackupCollector::new(config))); }
    if has("rds")        { v.push(Box::new(RdsCollector::new(config))); }

    v
}
