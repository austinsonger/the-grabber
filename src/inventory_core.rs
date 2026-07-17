// ---------------------------------------------------------------------------
// Inventory Core — Shared types and canonical CSV schema
// ---------------------------------------------------------------------------

/// Canonical 14-column CSV header row — exact capitalization and wording required.
pub const INVENTORY_CSV_HEADERS: &[&str] = &[
    "UNIQUE ASSET IDENTIFIER",
    "IPv4 or IPv6 Address",
    "Virtual",
    "Public",
    "DNS Name or URL",
    "MAC Address",
    "Location",
    "Asset Type",
    "Hardware Make/Model",
    "Software/ Database Vendor",
    "Software/ Database Name & Version",
    "Function",
    "VLAN/ Network ID",
    "Comments",
];

// Asset type keys — match the TUI inventory_items keys exactly.
pub const ASSET_KEY_KMS_KEY: &str = "kms-key";
pub const ASSET_KEY_S3_BUCKET: &str = "s3-bucket";
pub const ASSET_KEY_LAMBDA_FUNCTION: &str = "lambda-function";
pub const ASSET_KEY_EC2_INSTANCE: &str = "ec2-instance";
pub const ASSET_KEY_ALB: &str = "alb";
pub const ASSET_KEY_RDS_DB_INSTANCE: &str = "rds-db-instance";
pub const ASSET_KEY_ELASTICACHE_CLUSTER: &str = "elasticache-cluster";
pub const ASSET_KEY_CONTAINER: &str = "container";
pub const ASSET_KEY_NLB: &str = "nlb";
pub const ASSET_KEY_EBS_VOLUME: &str = "ebs-volume";
pub const ASSET_KEY_EFS_FILE_SYSTEM: &str = "efs-file-system";
pub const ASSET_KEY_FSX_FILE_SYSTEM: &str = "fsx-file-system";
pub const ASSET_KEY_REDSHIFT_CLUSTER: &str = "redshift-cluster";
pub const ASSET_KEY_DYNAMODB_TABLE: &str = "dynamodb-table";
pub const ASSET_KEY_APIGW: &str = "apigw";
pub const ASSET_KEY_SNS_TOPIC: &str = "sns-topic";
pub const ASSET_KEY_SQS_QUEUE: &str = "sqs-queue";
pub const ASSET_KEY_KINESIS_STREAM: &str = "kinesis-stream";
pub const ASSET_KEY_FIREHOSE_STREAM: &str = "firehose-stream";
pub const ASSET_KEY_EVENTBRIDGE: &str = "eventbridge";
pub const ASSET_KEY_SECRETSMANAGER_SECRET: &str = "secretsmanager-secret";
pub const ASSET_KEY_VPC_NETWORK: &str = "vpc-network";
pub const ASSET_KEY_CLOUDTRAIL_TRAIL: &str = "cloudtrail-trail";
pub const ASSET_KEY_CONFIG_RECORDER: &str = "config-recorder";
pub const ASSET_KEY_GUARDDUTY_DETECTOR: &str = "guardduty-detector";
pub const ASSET_KEY_SECURITYHUB_HUB: &str = "securityhub-hub";
pub const ASSET_KEY_WAF_WEBACL: &str = "waf-webacl";

pub const INVENTORY_ITEMS: &[(&str, &str)] = &[
    (ASSET_KEY_KMS_KEY, "KMS Key"),
    (ASSET_KEY_S3_BUCKET, "S3 Bucket"),
    (ASSET_KEY_LAMBDA_FUNCTION, "Lambda Function"),
    (ASSET_KEY_EC2_INSTANCE, "EC2 Instance"),
    (ASSET_KEY_ALB, "Application Load Balancer (ALB)"),
    (ASSET_KEY_RDS_DB_INSTANCE, "RDS DB Instance"),
    (ASSET_KEY_ELASTICACHE_CLUSTER, "ElastiCache Cluster"),
    (ASSET_KEY_CONTAINER, "Container (ECR/ECS/EKS)"),
    (ASSET_KEY_NLB, "Network Load Balancer (NLB)"),
    (ASSET_KEY_EBS_VOLUME, "EBS Volume"),
    (ASSET_KEY_EFS_FILE_SYSTEM, "EFS File System"),
    (ASSET_KEY_FSX_FILE_SYSTEM, "FSx File System"),
    (ASSET_KEY_REDSHIFT_CLUSTER, "Redshift Cluster"),
    (ASSET_KEY_DYNAMODB_TABLE, "DynamoDB Table"),
    (ASSET_KEY_APIGW, "API Gateway (REST + HTTP + WebSocket)"),
    (ASSET_KEY_SNS_TOPIC, "SNS Topic"),
    (ASSET_KEY_SQS_QUEUE, "SQS Queue"),
    (ASSET_KEY_KINESIS_STREAM, "Kinesis Data Stream"),
    (ASSET_KEY_FIREHOSE_STREAM, "Kinesis Firehose Delivery Stream"),
    (ASSET_KEY_EVENTBRIDGE, "EventBridge (Bus + Rule)"),
    (ASSET_KEY_SECRETSMANAGER_SECRET, "Secrets Manager Secret"),
    (ASSET_KEY_VPC_NETWORK, "VPC Network Fabric (VPC + Subnet + IGW + NAT + TGW Attachment)"),
    (ASSET_KEY_CLOUDTRAIL_TRAIL, "CloudTrail Trail"),
    (ASSET_KEY_CONFIG_RECORDER, "Config Recorder"),
    (ASSET_KEY_GUARDDUTY_DETECTOR, "GuardDuty Detector"),
    (ASSET_KEY_SECURITYHUB_HUB, "Security Hub Hub"),
    (ASSET_KEY_WAF_WEBACL, "WAF WebACL"),
];

/// Build a 14-element all-empty row.
pub fn empty_row() -> Vec<String> {
    vec![String::new(); INVENTORY_CSV_HEADERS.len()]
}

/// Convenience: build a full row by index position.
pub struct RowBuilder {
    inner: Vec<String>,
}

impl RowBuilder {
    pub fn new() -> Self {
        Self { inner: empty_row() }
    }

    pub fn unique_id(mut self, v: impl Into<String>) -> Self {
        self.inner[0] = v.into();
        self
    }
    pub fn ipv4_ipv6(mut self, v: impl Into<String>) -> Self {
        self.inner[1] = v.into();
        self
    }
    pub fn virtual_flag(mut self, v: impl Into<String>) -> Self {
        self.inner[2] = v.into();
        self
    }
    pub fn public(mut self, v: impl Into<String>) -> Self {
        self.inner[3] = v.into();
        self
    }
    pub fn dns_url(mut self, v: impl Into<String>) -> Self {
        self.inner[4] = v.into();
        self
    }
    pub fn mac_address(mut self, v: impl Into<String>) -> Self {
        self.inner[5] = v.into();
        self
    }
    pub fn location(mut self, v: impl Into<String>) -> Self {
        self.inner[6] = v.into();
        self
    }
    pub fn asset_type(mut self, v: impl Into<String>) -> Self {
        self.inner[7] = v.into();
        self
    }
    pub fn hw_make_model(mut self, v: impl Into<String>) -> Self {
        self.inner[8] = v.into();
        self
    }
    pub fn sw_vendor(mut self, v: impl Into<String>) -> Self {
        self.inner[9] = v.into();
        self
    }
    pub fn sw_name_ver(mut self, v: impl Into<String>) -> Self {
        self.inner[10] = v.into();
        self
    }
    pub fn function(mut self, v: impl Into<String>) -> Self {
        self.inner[11] = v.into();
        self
    }
    pub fn vlan_network_id(mut self, v: impl Into<String>) -> Self {
        self.inner[12] = v.into();
        self
    }
    pub fn comments(mut self, v: impl Into<String>) -> Self {
        self.inner[13] = v.into();
        self
    }

    pub fn build(self) -> Vec<String> {
        self.inner
    }
}

impl Default for RowBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Extract a tag value by key (case-insensitive key match).
pub fn tag_value<'a>(tags: &'a [(&str, &str)], key: &str) -> Option<&'a str> {
    tags.iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(key))
        .map(|(_, v)| *v)
}

/// Normalize an S3 bucket region — empty constraint means us-east-1.
pub fn normalize_s3_region(constraint: Option<&str>) -> &str {
    match constraint {
        None | Some("") => "us-east-1",
        Some(r) => r,
    }
}
