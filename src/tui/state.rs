// ---------------------------------------------------------------------------
// Progress events sent from collector tasks → TUI
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub enum Progress {
    /// Signals the start of collection for a new account (multi-account mode).
    AccountStarted {
        name: String,
        index: usize,
        total: usize,
        region: String,
        collectors: Vec<String>,
    },
    /// Signals that collection for an account has finished.
    AccountFinished {
        name: String,
    },
    /// Signals that collection is now running against a specific region (all-regions mode).
    RegionStarted {
        region: String,
    },
    Started {
        collector: String,
    },
    Done {
        collector: String,
        count: usize,
    },
    Error {
        collector: String,
        message: String,
    },
    /// Sent once all collectors finish.
    Finished {
        files: Vec<String>,
        /// Path to the zip bundle, if the zip option was enabled.
        zip_path: Option<String>,
        /// Path to the HMAC-SHA256 signing manifest, if signing was enabled.
        signing_manifest: Option<String>,
        /// Path to the signing key file, if signing was enabled.
        signing_key_path: Option<String>,
        /// POAM mode summary payload.
        poam_summary: Option<PoamSummary>,
    },
}

// ---------------------------------------------------------------------------
// Feature selection
// ---------------------------------------------------------------------------

/// Which top-level feature the user chose on the Feature Selection screen.
#[derive(Debug, Clone, PartialEq)]
pub enum Feature {
    /// Traditional evidence-collector flow.
    Collectors,
    /// New unified AWS asset-inventory flow.
    Inventory,
    /// POA&M reconciliation flow.
    Poam,
}

/// Which panel has focus on the SelectCollectors screen.
#[derive(Debug, Clone, PartialEq)]
pub enum CollectorFocus {
    Search,
    Categories,
    Items,
}

// ---------------------------------------------------------------------------
// Wizard screens
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
pub enum Screen {
    Welcome,
    /// Choose between Collectors and Inventory.
    FeatureSelection,
    SelectAccount, // shown when TOML accounts are configured
    SelectProfile, // legacy: pick from ~/.aws/config profiles
    SelectRegion,  // legacy: pick region
    SetDates,
    /// Multi-select AWS asset types (Inventory flow only).
    Inventory,
    PoamAccount,
    PoamRegion,
    PoamYear,
    PoamMonth,
    SelectCollectors,
    SetOptions,
    Confirm,
    /// Shown while building AWS SDK clients before collection starts.
    Preparing,
    Running,
    Results,
}

// ---------------------------------------------------------------------------
// Collector categories (used by two-panel SelectCollectors screen)
// ---------------------------------------------------------------------------

pub const COLLECTOR_CATEGORIES: &[(usize, &str)] = &[
    (0, "App Layer & DNS"),
    (6, "Audit Trail"),
    (23, "Compute"),
    (37, "Containers"),
    (41, "Database & Backup"),
    (48, "Encryption & Secrets"),
    (55, "Identity & Access"),
    (67, "Monitoring & Events"),
    (77, "Network"),
    (97, "Organization & Account"),
    (101, "Security Detection"),
    (113, "Storage"),
];

// ---------------------------------------------------------------------------
// Text input state
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default)]
pub struct TextInput {
    pub value: String,
    pub cursor: usize,
}

impl TextInput {
    pub fn new(default: &str) -> Self {
        Self {
            value: default.to_string(),
            cursor: default.len(),
        }
    }

    pub fn insert(&mut self, c: char) {
        self.value.insert(self.cursor, c);
        self.cursor += c.len_utf8();
    }

    pub fn backspace(&mut self) {
        if self.cursor > 0 {
            let c = self.value[..self.cursor].chars().last().unwrap();
            self.cursor -= c.len_utf8();
            self.value.remove(self.cursor);
        }
    }

    pub fn move_left(&mut self) {
        if self.cursor > 0 {
            let c = self.value[..self.cursor].chars().last().unwrap();
            self.cursor -= c.len_utf8();
        }
    }

    pub fn move_right(&mut self) {
        if self.cursor < self.value.len() {
            let c = self.value[self.cursor..].chars().next().unwrap();
            self.cursor += c.len_utf8();
        }
    }

    pub fn clear(&mut self) {
        self.value.clear();
        self.cursor = 0;
    }
}

// ---------------------------------------------------------------------------
// Collector status (shown on Running screen)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct CollectorStatus {
    pub name: String,
    pub state: CollectorState,
}

#[derive(Debug, Clone)]
pub enum CollectorState {
    Waiting,
    Running,
    Done(usize),
    Failed(String),
}

#[derive(Debug, Clone, Default)]
pub struct PoamSummary {
    pub region: String,
    pub year: String,
    pub month: String,
    pub evidence_path: String,
    pub csv_used: Option<String>,
    pub added_open_count: usize,
    pub moved_closed_count: usize,
    pub warnings: Vec<String>,
}

// ---------------------------------------------------------------------------
// Static collector menu data (matches COLLECTOR_CATEGORIES index boundaries)
// ---------------------------------------------------------------------------

pub const COLLECTOR_ITEMS: &[(&str, &str)] = &[
    // ── App Layer & DNS ── (0..6)
    (
        "api-gateway",
        "API Gateway              (current state, CSV)",
    ),
    (
        "cloudfront",
        "CloudFront Distributions (current state, CSV)",
    ),
    (
        "lambda-config",
        "Lambda Configuration     (current state, CSV)",
    ),
    (
        "lambda-permissions",
        "Lambda Permissions       (current state, CSV)",
    ),
    (
        "route53-zones",
        "Route53 Hosted Zones     (current state, CSV)",
    ),
    (
        "route53-resolver",
        "Route53 Resolver Rules   (current state, CSV)",
    ),
    // ── Audit Trail ── (6..23)
    (
        "config-recorder",
        "AWS Config Recorder      (current state, CSV)",
    ),
    (
        "config-rules",
        "AWS Config Rules         (current state, CSV)",
    ),
    ("cfn-drift", "CloudFormation Drift     (current state, CSV)"),
    (
        "cloudtrail",
        "CloudTrail API           (last 90 days, JSON)",
    ),
    ("ct-changes", "CloudTrail Change Events (last 7 days, CSV)"),
    (
        "cloudtrail-config",
        "CloudTrail Configuration (current state, CSV)",
    ),
    (
        "ct-selectors",
        "CloudTrail Evt Selectors (current state, CSV)",
    ),
    (
        "ct-full-config",
        "CloudTrail Full Config   (current state, CSV)",
    ),
    (
        "ct-validation",
        "CloudTrail Log Validation(current state, CSV)",
    ),
    (
        "s3",
        "CloudTrail S3            (7 months, requires s3-bucket, JSON)",
    ),
    (
        "ct-s3-policy",
        "CloudTrail S3 Policy     (current state, CSV)",
    ),
    (
        "config-compliance",
        "Config Compliance History(all rules, CSV)",
    ),
    (
        "config-history",
        "Config Resource History  (current state, CSV)",
    ),
    (
        "config-timeline",
        "Config Resource Timeline (last 5 per resource, CSV)",
    ),
    (
        "config-snapshot",
        "Config Snapshot (PiT)    (point-in-time, CSV)",
    ),
    (
        "ct-config-changes",
        "CT Config Change Events  (last 90 days, CSV)",
    ),
    (
        "ct-iam-changes",
        "CT IAM Changes (Hi-Risk) (last 90 days, CSV)",
    ),
    // ── Compute ── (23..37)
    ("asg", "Auto Scaling Groups      (current state, CSV)"),
    (
        "ec2-detailed",
        "EC2 Details (AMI/IMDS)   (current state, CSV)",
    ),
    (
        "ec2-config",
        "EC2 Instance Config      (current state, CSV)",
    ),
    (
        "ec2-instances",
        "EC2 Instances            (current state, CSV)",
    ),
    (
        "launch-templates",
        "EC2 Launch Templates     (current state, CSV)",
    ),
    (
        "ssm-maint-windows",
        "SSM Maintenance Windows  (current state, CSV)",
    ),
    (
        "ssm-instances",
        "SSM Managed Instances    (current state, CSV)",
    ),
    (
        "ssm-params",
        "SSM Parameter Store      (current state, CSV)",
    ),
    (
        "ssm-baselines",
        "SSM Patch Baselines      (current state, CSV)",
    ),
    (
        "ssm-patches",
        "SSM Patch Compliance     (current state, CSV)",
    ),
    (
        "ssm-patch-detail",
        "SSM Patch Detail         (per instance, CSV)",
    ),
    (
        "ssm-patch-exec",
        "SSM Patch Executions     (command history, CSV)",
    ),
    (
        "ssm-patch-summary",
        "SSM Patch Summary        (per instance, CSV)",
    ),
    ("time-sync", "Time Sync Config (SSM)   (current state, CSV)"),
    // ── Containers ── (37..41)
    ("ecr-scan", "ECR Image Scan Findings  (current state, CSV)"),
    (
        "ecr-config",
        "ECR Repo Config          (current state, CSV)",
    ),
    ("ecs", "ECS Clusters             (current state, CSV)"),
    ("eks", "EKS Clusters             (current state, CSV)"),
    // ── Database & Backup ── (41..48)
    (
        "backup",
        "AWS Backup API           (native backup jobs, JSON)",
    ),
    (
        "backup-plans",
        "AWS Backup Plans         (current state, CSV)",
    ),
    (
        "backup-vaults",
        "Backup Vault Config      (current state, CSV)",
    ),
    (
        "rds-backup-config",
        "RDS Backup Config        (current state, CSV)",
    ),
    (
        "rds-inventory",
        "RDS Inventory            (current state, CSV)",
    ),
    ("rds", "RDS Snapshots            (last 30 days, JSON)"),
    (
        "rds-snapshots",
        "RDS Snapshots            (current state, CSV)",
    ),
    // ── Encryption & Secrets ── (48..55)
    (
        "ebs-encryption",
        "EBS Default Encryption   (current state, CSV)",
    ),
    (
        "ebs-config",
        "EBS Encryption Config    (current state, CSV)",
    ),
    (
        "kms-config",
        "KMS Key Config (Full)    (current state, CSV)",
    ),
    (
        "kms-policies",
        "KMS Key Policies         (current state, CSV)",
    ),
    ("kms", "KMS Keys                 (current state, CSV)"),
    ("secrets", "Secrets Manager          (current state, CSV)"),
    (
        "secrets-policies",
        "Secrets Manager Policies (current state, CSV)",
    ),
    // ── Identity & Access ── (55..67)
    (
        "access-analyzer",
        "IAM Access Analyzer      (current state, CSV)",
    ),
    (
        "iam-access-keys",
        "IAM Access Keys          (current state, CSV)",
    ),
    (
        "iam-account-summary",
        "IAM Account Summary      (current state, CSV)",
    ),
    ("iam-certs", "IAM Certificates         (current state, CSV)"),
    (
        "iam-password-policy",
        "IAM Password Policy      (current state, CSV)",
    ),
    (
        "iam-policies",
        "IAM Policies             (current state, CSV)",
    ),
    (
        "iam-role-policies",
        "IAM Role Policies        (current state, CSV)",
    ),
    (
        "iam-trusts",
        "IAM Role Trust Policies  (current state, CSV)",
    ),
    ("iam-roles", "IAM Roles                (current state, CSV)"),
    (
        "iam-user-policies",
        "IAM User Policies        (current state, CSV)",
    ),
    ("iam-users", "IAM Users                (current state, CSV)"),
    (
        "saml-providers",
        "SAML IdP Config          (current state, CSV)",
    ),
    // ── Monitoring & Events ── (67..77)
    ("cw-alarms", "CloudWatch Alarms        (current state, CSV)"),
    (
        "cw-log-groups",
        "CloudWatch Log Groups    (current state, CSV)",
    ),
    (
        "cw-config-alarms",
        "CW Alarms (All)          (current state, CSV)",
    ),
    (
        "cw-log-config",
        "CW Log Group Config      (current state, CSV)",
    ),
    (
        "change-event-rules",
        "EventBridge Change Rules (event-pattern, CSV)",
    ),
    (
        "eventbridge-rules",
        "EventBridge Rules        (current state, CSV)",
    ),
    (
        "metric-filters",
        "Log Metric Filters/Alarms(current state, CSV)",
    ),
    (
        "metric-filter-config",
        "Metric Filter Config    (current state, CSV)",
    ),
    (
        "sns-policies",
        "SNS Topic Policies       (current state, CSV)",
    ),
    ("sns", "SNS Topic Subscribers    (current state, CSV)"),
    // ── Network ── (77..97)
    ("acm", "ACM Certificates         (current state, CSV)"),
    ("alb-logs", "ALB Access Log Config    (current state, CSV)"),
    ("igw", "Internet Gateways        (current state, CSV)"),
    (
        "elb-full-config",
        "Load Balancer Full Config(current state, CSV)",
    ),
    (
        "elb-listeners",
        "Load Balancer Listeners  (current state, CSV)",
    ),
    ("elb", "Load Balancers           (current state, CSV)"),
    (
        "nat-gateways",
        "NAT Gateways             (current state, CSV)",
    ),
    ("nacl", "Network ACLs             (current state, CSV)"),
    (
        "public-resources",
        "Publicly Exposed Res.    (current state, CSV)",
    ),
    ("rt-config", "Route Table Config       (current state, CSV)"),
    (
        "route-tables",
        "Route Tables             (current state, CSV)",
    ),
    ("sg-config", "Security Group Config    (current state, CSV)"),
    (
        "security-groups",
        "Security Groups          (current state, CSV)",
    ),
    (
        "vpc-config",
        "VPC Configuration        (current state, CSV)",
    ),
    (
        "vpc-endpoints",
        "VPC Endpoints            (current state, CSV)",
    ),
    (
        "vpc-flow-logs",
        "VPC Flow Logging         (current state, CSV)",
    ),
    ("vpc", "VPCs                     (current state, CSV)"),
    (
        "waf-config",
        "WAF Full Config          (current state, CSV)",
    ),
    (
        "waf-logging",
        "WAF Logging Config       (current state, CSV)",
    ),
    ("waf", "WAF Regional Web ACLs    (current state, CSV)"),
    // ── Organization & Account ── (97..101)
    (
        "account-contacts",
        "Account Alt. Contacts    (current state, CSV)",
    ),
    (
        "org-config",
        "AWS Org Config           (requires org master, CSV)",
    ),
    ("scp", "Org SCPs                 (requires org admin, CSV)"),
    (
        "resource-tags",
        "Resource Tags            (current state, CSV)",
    ),
    // ── Security Detection ── (101..113)
    (
        "guardduty-config",
        "GuardDuty Config         (current state, CSV)",
    ),
    ("guardduty", "GuardDuty Findings       (current state, CSV)"),
    (
        "gd-full-config",
        "GuardDuty Full Config    (current state, CSV)",
    ),
    (
        "guardduty-rules",
        "GuardDuty Suppression    (current state, CSV)",
    ),
    (
        "inspector-history",
        "Inspector Findings Hist. (if enabled, CSV)",
    ),
    (
        "inspector-config",
        "Inspector2 Config        (if enabled, CSV)",
    ),
    (
        "inspector-ecr-images",
        "Inspector2 ECR Images    (if enabled, CSV)",
    ),
    ("inspector", "Inspector2 Findings      (if enabled, CSV)"),
    ("macie", "Macie Findings           (if enabled, CSV)"),
    (
        "securityhub",
        "Security Hub Findings    (current state, CSV)",
    ),
    ("sh-config", "SecurityHub Config       (current state, CSV)"),
    (
        "sh-standards",
        "SecurityHub Standards    (current state, CSV)",
    ),
    // ── Storage ── (113..126)
    ("dynamodb", "DynamoDB Tables          (current state, CSV)"),
    ("ebs", "EBS Volumes              (current state, CSV)"),
    ("efs", "EFS File Systems         (current state, CSV)"),
    (
        "elasticache",
        "ElastiCache Clusters     (current state, CSV)",
    ),
    (
        "elasticache-global",
        "ElastiCache Global DS    (current state, CSV)",
    ),
    (
        "s3-logging",
        "S3 Bucket Access Logging (current state, CSV)",
    ),
    (
        "s3-policies",
        "S3 Bucket Policies       (current state, CSV)",
    ),
    (
        "s3-bucket-policy",
        "S3 Bucket Policy (Full)  (current state, CSV)",
    ),
    ("s3-config", "S3 Buckets Config        (current state, CSV)"),
    (
        "s3-data-events",
        "S3 Data Events Config    (current state, CSV)",
    ),
    (
        "s3-encryption",
        "S3 Encryption Config     (current state, CSV)",
    ),
    (
        "s3-logging-config",
        "S3 Logging Config        (current state, CSV)",
    ),
    (
        "s3-public-access",
        "S3 Public Access Block   (current state, CSV)",
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
