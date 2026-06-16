// ---------------------------------------------------------------------------
// Static collector menu data (matches COLLECTOR_CATEGORIES index boundaries)
// ---------------------------------------------------------------------------

use crate::providers::CloudProvider;

pub const COLLECTOR_ITEMS: &[(&str, &str, CloudProvider)] = &[
    // ── App & Network Services ── (0..6)
    (
        "api-gateway",
        "API Gateway              ",
        CloudProvider::Aws,
    ),
    (
        "cloudfront",
        "CloudFront Distributions ",
        CloudProvider::Aws,
    ),
    (
        "lambda-config",
        "Lambda Configuration     ",
        CloudProvider::Aws,
    ),
    (
        "lambda-permissions",
        "Lambda Permissions       ",
        CloudProvider::Aws,
    ),
    (
        "route53-zones",
        "Route53 Hosted Zones     ",
        CloudProvider::Aws,
    ),
    (
        "route53-resolver",
        "Route53 Resolver Rules   ",
        CloudProvider::Aws,
    ),
    // ── Audit Trail ── (6..29)
    (
        "athena-log-queries",
        "Athena Log Queries       ",
        CloudProvider::Aws,
    ),
    (
        "config-recorder",
        "AWS Config Recorder      ",
        CloudProvider::Aws,
    ),
    (
        "config-rules",
        "AWS Config Rules         ",
        CloudProvider::Aws,
    ),
    ("cfn-drift", "CloudFormation Drift     ", CloudProvider::Aws),
    ("cloudtrail", "CloudTrail API", CloudProvider::Aws),
    ("ct-changes", "CloudTrail Change Events", CloudProvider::Aws),
    (
        "ct-account-mgmt",
        "CT Account Mgmt Events   ",
        CloudProvider::Aws,
    ),
    (
        "ct-sessions",
        "CT Session Events        ",
        CloudProvider::Aws,
    ),
    (
        "ct-insights",
        "CT Insights              ",
        CloudProvider::Aws,
    ),
    ("ct-lake", "CT Lake Data Stores      ", CloudProvider::Aws),
    (
        "ct-privileged",
        "CT Privileged Events     ",
        CloudProvider::Aws,
    ),
    (
        "cloudtrail-config",
        "CloudTrail Configuration ",
        CloudProvider::Aws,
    ),
    (
        "ct-selectors",
        "CloudTrail Evt Selectors ",
        CloudProvider::Aws,
    ),
    (
        "ct-full-config",
        "CloudTrail Full Config   ",
        CloudProvider::Aws,
    ),
    (
        "ct-validation",
        "CloudTrail Log Validation",
        CloudProvider::Aws,
    ),
    (
        "s3",
        "CloudTrail S3            (7 months, requires s3-bucket, JSON)",
        CloudProvider::Aws,
    ),
    (
        "ct-s3-policy",
        "CloudTrail S3 Policy     ",
        CloudProvider::Aws,
    ),
    (
        "config-compliance",
        "Config Compliance History(all rules, CSV)",
        CloudProvider::Aws,
    ),
    (
        "config-history",
        "Config Resource History  ",
        CloudProvider::Aws,
    ),
    (
        "config-timeline",
        "Config Resource Timeline",
        CloudProvider::Aws,
    ),
    (
        "config-snapshot",
        "Config Snapshot (PiT)",
        CloudProvider::Aws,
    ),
    (
        "ct-config-changes",
        "CT Config Change Events  ",
        CloudProvider::Aws,
    ),
    (
        "ct-iam-changes",
        "CT IAM Changes (Hi-Risk) ",
        CloudProvider::Aws,
    ),
    // ── Compute ── (27..41)
    ("asg", "Auto Scaling Groups      ", CloudProvider::Aws),
    (
        "ec2-detailed",
        "EC2 Details (AMI/IMDS)   ",
        CloudProvider::Aws,
    ),
    (
        "ec2-config",
        "EC2 Instance Config      ",
        CloudProvider::Aws,
    ),
    (
        "ec2-instances",
        "EC2 Instances            ",
        CloudProvider::Aws,
    ),
    (
        "launch-templates",
        "EC2 Launch Templates     ",
        CloudProvider::Aws,
    ),
    (
        "ssm-maint-windows",
        "SSM Maintenance Windows  ",
        CloudProvider::Aws,
    ),
    (
        "ssm-instances",
        "SSM Managed Instances    ",
        CloudProvider::Aws,
    ),
    (
        "ssm-params",
        "SSM Parameter Store      ",
        CloudProvider::Aws,
    ),
    (
        "ssm-baselines",
        "SSM Patch Baselines      ",
        CloudProvider::Aws,
    ),
    (
        "ssm-patches",
        "SSM Patch Compliance     ",
        CloudProvider::Aws,
    ),
    (
        "ssm-patch-detail",
        "SSM Patch Detail         (per instance, CSV)",
        CloudProvider::Aws,
    ),
    (
        "ssm-patch-exec",
        "SSM Patch Executions     (command history, CSV)",
        CloudProvider::Aws,
    ),
    ("ssm-patch-summary", "SSM Patch Summary", CloudProvider::Aws),
    ("time-sync", "Time Sync Config (SSM)   ", CloudProvider::Aws),
    // ── Containers ── (37..41)
    (
        "ecr-config",
        "ECR Repo Config          ",
        CloudProvider::Aws,
    ),
    ("ecs", "ECS Clusters             ", CloudProvider::Aws),
    ("eks", "EKS Clusters             ", CloudProvider::Aws),
    // ── Database & Backup ── (41..48)
    ("backup", "AWS Backup API", CloudProvider::Aws),
    (
        "backup-plans",
        "AWS Backup Plans         ",
        CloudProvider::Aws,
    ),
    (
        "backup-vaults",
        "Backup Vault Config      ",
        CloudProvider::Aws,
    ),
    (
        "rds-backup-config",
        "RDS Backup Config        ",
        CloudProvider::Aws,
    ),
    (
        "rds-inventory",
        "RDS Inventory            ",
        CloudProvider::Aws,
    ),
    ("rds", "RDS Snapshots", CloudProvider::Aws),
    (
        "rds-snapshots",
        "RDS Snapshots            ",
        CloudProvider::Aws,
    ),
    // ── Encryption & Secrets ── (48..55)
    (
        "ebs-encryption",
        "EBS Default Encryption   ",
        CloudProvider::Aws,
    ),
    (
        "ebs-config",
        "EBS Encryption Config    ",
        CloudProvider::Aws,
    ),
    (
        "kms-config",
        "KMS Key Config (Full)    ",
        CloudProvider::Aws,
    ),
    (
        "kms-policies",
        "KMS Key Policies         ",
        CloudProvider::Aws,
    ),
    ("kms", "KMS Keys                 ", CloudProvider::Aws),
    ("secrets", "Secrets Manager          ", CloudProvider::Aws),
    (
        "secrets-policies",
        "Secrets Manager Policies ",
        CloudProvider::Aws,
    ),
    // ── Identity & Access ── (55..67)
    (
        "access-analyzer",
        "IAM Access Analyzer      ",
        CloudProvider::Aws,
    ),
    (
        "iam-access-keys",
        "IAM Access Keys          ",
        CloudProvider::Aws,
    ),
    (
        "iam-account-summary",
        "IAM Account Summary      ",
        CloudProvider::Aws,
    ),
    ("iam-certs", "IAM Certificates         ", CloudProvider::Aws),
    (
        "iam-credential-report",
        "IAM Credential Report    ",
        CloudProvider::Aws,
    ),
    (
        "iam-password-policy",
        "IAM Password Policy      ",
        CloudProvider::Aws,
    ),
    (
        "iam-policies",
        "IAM Policies             ",
        CloudProvider::Aws,
    ),
    (
        "iam-role-policies",
        "IAM Role Policies        ",
        CloudProvider::Aws,
    ),
    (
        "iam-trusts",
        "IAM Role Trust Policies  ",
        CloudProvider::Aws,
    ),
    ("iam-roles", "IAM Roles                ", CloudProvider::Aws),
    (
        "iam-user-policies",
        "IAM User Policies        ",
        CloudProvider::Aws,
    ),
    ("iam-users", "IAM Users                ", CloudProvider::Aws),
    (
        "saml-providers",
        "SAML IdP Config          ",
        CloudProvider::Aws,
    ),
    // ── Monitoring & Events ── (67..77)
    ("cw-alarms", "CloudWatch Alarms        ", CloudProvider::Aws),
    (
        "cw-log-groups",
        "CloudWatch Log Groups    ",
        CloudProvider::Aws,
    ),
    (
        "cw-config-alarms",
        "CW Alarms (All)          ",
        CloudProvider::Aws,
    ),
    (
        "cw-log-config",
        "CW Log Group Config      ",
        CloudProvider::Aws,
    ),
    (
        "change-event-rules",
        "EventBridge Change Rules (event-pattern, CSV)",
        CloudProvider::Aws,
    ),
    (
        "eventbridge-rules",
        "EventBridge Rules        ",
        CloudProvider::Aws,
    ),
    (
        "metric-filters",
        "Log Metric Filters/Alarms",
        CloudProvider::Aws,
    ),
    (
        "metric-filter-config",
        "Metric Filter Config    ",
        CloudProvider::Aws,
    ),
    (
        "sns-policies",
        "SNS Topic Policies       ",
        CloudProvider::Aws,
    ),
    ("sns", "SNS Topic Subscribers    ", CloudProvider::Aws),
    // ── Network ── (77..97)
    ("acm", "ACM Certificates         ", CloudProvider::Aws),
    ("alb-logs", "ALB Access Log Config    ", CloudProvider::Aws),
    ("igw", "Internet Gateways        ", CloudProvider::Aws),
    (
        "elb-full-config",
        "Load Balancer Full Config",
        CloudProvider::Aws,
    ),
    (
        "elb-listeners",
        "Load Balancer Listeners  ",
        CloudProvider::Aws,
    ),
    ("elb", "Load Balancers           ", CloudProvider::Aws),
    (
        "nat-gateways",
        "NAT Gateways             ",
        CloudProvider::Aws,
    ),
    ("nacl", "Network ACLs             ", CloudProvider::Aws),
    (
        "public-resources",
        "Publicly Exposed Res.    ",
        CloudProvider::Aws,
    ),
    ("rt-config", "Route Table Config       ", CloudProvider::Aws),
    (
        "route-tables",
        "Route Tables             ",
        CloudProvider::Aws,
    ),
    ("sg-config", "Security Group Config    ", CloudProvider::Aws),
    (
        "security-groups",
        "Security Groups          ",
        CloudProvider::Aws,
    ),
    (
        "vpc-config",
        "VPC Configuration        ",
        CloudProvider::Aws,
    ),
    (
        "vpc-endpoints",
        "VPC Endpoints            ",
        CloudProvider::Aws,
    ),
    (
        "vpc-flow-logs",
        "VPC Flow Logging         ",
        CloudProvider::Aws,
    ),
    ("vpc", "VPCs                     ", CloudProvider::Aws),
    (
        "waf-config",
        "WAF Full Config          ",
        CloudProvider::Aws,
    ),
    (
        "waf-logging",
        "WAF Logging Config       ",
        CloudProvider::Aws,
    ),
    ("waf", "WAF Regional Web ACLs    ", CloudProvider::Aws),
    // ── Organization & Account ── (97..101)
    (
        "account-contacts",
        "Account Alt. Contacts    ",
        CloudProvider::Aws,
    ),
    (
        "org-config",
        "AWS Org Config           (requires org master, CSV)",
        CloudProvider::Aws,
    ),
    (
        "scp",
        "Org SCPs                 (requires org admin, CSV)",
        CloudProvider::Aws,
    ),
    (
        "resource-tags",
        "Resource Tags            ",
        CloudProvider::Aws,
    ),
    // ── Security Detection ── (101..113)
    (
        "guardduty-config",
        "GuardDuty Config         ",
        CloudProvider::Aws,
    ),
    ("guardduty", "GuardDuty Findings       ", CloudProvider::Aws),
    (
        "gd-full-config",
        "GuardDuty Full Config    ",
        CloudProvider::Aws,
    ),
    (
        "guardduty-rules",
        "GuardDuty Suppression    ",
        CloudProvider::Aws,
    ),
    (
        "inspector-history",
        "Inspector Findings Hist. ",
        CloudProvider::Aws,
    ),
    (
        "inspector-config",
        "Inspector2 Config        ",
        CloudProvider::Aws,
    ),
    (
        "inspector-ecr-images",
        "Inspector2 ECR Images    ",
        CloudProvider::Aws,
    ),
    ("inspector", "Inspector2 Findings      ", CloudProvider::Aws),
    ("macie", "Macie Findings           ", CloudProvider::Aws),
    (
        "securityhub",
        "Security Hub Findings    ",
        CloudProvider::Aws,
    ),
    ("sh-config", "SecurityHub Config       ", CloudProvider::Aws),
    (
        "sh-standards",
        "SecurityHub Standards    ",
        CloudProvider::Aws,
    ),
    (
        "inspector-sbom",
        "Inspector2 SBOM Export   ",
        CloudProvider::Aws,
    ),
    // ── Storage ── (114..127)
    ("dynamodb", "DynamoDB Tables          ", CloudProvider::Aws),
    ("ebs", "EBS Volumes              ", CloudProvider::Aws),
    ("efs", "EFS File Systems         ", CloudProvider::Aws),
    (
        "elasticache",
        "ElastiCache Clusters     ",
        CloudProvider::Aws,
    ),
    (
        "elasticache-global",
        "ElastiCache Global DS    ",
        CloudProvider::Aws,
    ),
    (
        "s3-logging",
        "S3 Bucket Access Logging ",
        CloudProvider::Aws,
    ),
    (
        "s3-policies",
        "S3 Bucket Policies       ",
        CloudProvider::Aws,
    ),
    (
        "s3-bucket-policy",
        "S3 Bucket Policy (Full)  ",
        CloudProvider::Aws,
    ),
    ("s3-config", "S3 Buckets Config        ", CloudProvider::Aws),
    (
        "s3-data-events",
        "S3 Data Events Config    ",
        CloudProvider::Aws,
    ),
    (
        "s3-encryption",
        "S3 Encryption Config     ",
        CloudProvider::Aws,
    ),
    (
        "s3-logging-config",
        "S3 Logging Config        ",
        CloudProvider::Aws,
    ),
    (
        "s3-public-access",
        "S3 Public Access Block   ",
        CloudProvider::Aws,
    ),
    // ── Security Scanning (Tenable) ── (127..130)
    (
        "tenable-vulns",
        "Vulnerability Findings   ",
        CloudProvider::Tenable,
    ),
    (
        "tenable-was",
        "Web App Scanning         ",
        CloudProvider::Tenable,
    ),
    (
        "tenable-pci-asv",
        "PCI ASV Compliance       ",
        CloudProvider::Tenable,
    ),
    (
        "tenable-assets",
        "Asset Inventory          ",
        CloudProvider::Tenable,
    ),
    (
        "tenable-compliance",
        "Compliance Findings      ",
        CloudProvider::Tenable,
    ),
    // ── Identity Provider (Okta) ──
    (
        "okta-users",
        "Users                    ",
        CloudProvider::Okta,
    ),
    (
        "okta-groups",
        "Groups                   ",
        CloudProvider::Okta,
    ),
    (
        "okta-group-members",
        "Group Members            ",
        CloudProvider::Okta,
    ),
    (
        "okta-apps",
        "Applications             ",
        CloudProvider::Okta,
    ),
    (
        "okta-policies",
        "Policies                 ",
        CloudProvider::Okta,
    ),
    (
        "okta-factors",
        "MFA Factors              ",
        CloudProvider::Okta,
    ),
    (
        "okta-system-log",
        "System Log Events        ",
        CloudProvider::Okta,
    ),
    // ── Issue Tracker (Jira) ──
    (
        "jira-projects",
        "Projects                 ",
        CloudProvider::Jira,
    ),
    (
        "jira-issues",
        "Issues                   ",
        CloudProvider::Jira,
    ),
];

// ---------------------------------------------------------------------------
// Available AWS regions
// ---------------------------------------------------------------------------

pub const AWS_REGIONS: &[&str] = &[
    // North America
    "us-east-1",
    "us-east-2",
    "us-west-1",
    "us-west-2",
    "ca-central-1",
    // Europe
    "eu-west-1",
    "eu-west-2",
    "eu-west-3",
    "eu-central-1",
    "eu-north-1",
    "eu-south-1",
    // Asia Pacific
    "ap-southeast-1",
    "ap-southeast-2",
    "ap-northeast-1",
    "ap-northeast-2",
    "ap-south-1",
    // South America
    "sa-east-1",
];
