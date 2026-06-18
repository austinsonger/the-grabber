# Evidence List

All output files produced by this tool. Every collector writes to
`<AccountId>_<FilenamePrefix>-<YYYY-MM-DD-HHMMSS>.<ext>` in the output directory.

---

## JSON Evidence (Time-Windowed)

These collectors query event history over a date range and write structured JSON reports.

| # | Name | Filename Prefix | Description |
|---|------|----------------|-------------|
| EV1 | CloudTrail | `CloudTrail_backup_and_snapshot_events` | `StartBackupJob`, `BackupJobCompleted`, and related CloudTrail events via LookupEvents API |
| EV2 | AWS Backup | `AWS_Backup_job_history_exports` | AWS Backup job records (status, resource, plan, vault) via Backup ListBackupJobs API |
| EV3 | RDS Automated Snapshots | `RDS_automated_snapshot_exports` | RDS automated and manual snapshot records via DescribeDBSnapshots |
| EV4 | CloudTrail S3 Logs | `CloudTrail_S3_historical_log_exports` | CloudTrail events parsed directly from S3 log files (requires `--s3-bucket`) |

---

## CSV Evidence (Current-State Snapshots)

These collectors query the current configuration of AWS resources and write CSV files.

### Account & Identity

| # | Name | Filename Prefix | Columns |
|---|------|----------------|---------|
| EV5 | Account Alternate Contacts | `Account_Contacts_Config` | Contact Type, Name, Email, Phone, Title |
| EV6 | IAM SAML Identity Providers | `IAM_Identity_Provider_Config` | Provider ARN, Provider Name, Created Date, Valid Until, Metadata Length (bytes) |
| EV7 | IAM Account Summary | `IAM_Account_Summary` | Key, Value |
| EV8 | IAM Users | `IAM_Users` | User Name, ARN, MFA Enabled, Password Last Used, Access Key Status, Created Date |
| EV9 | IAM Roles | `IAM_Roles` | Role Name, ARN, Trust Policy, Attached Policies, Last Used, Region |
| EV10 | IAM Policies | `IAM_Policies` | Policy Name, ARN, Policy Type, Attached Entities, Permissions Summary |
| EV11 | IAM Access Keys | `IAM_Access_Keys` | User Name, Access Key ID, Status, Created Date, Last Used |
| EV12 | IAM Certificates | `IAM_Certificates` | Name, ARN, Issuer, Subject, Subject Alternative Names, Public Key Algorithm, Signature Algorithm, Key Usage, Extended Key Usage, Hierarchy, Issued On, Expires, Region |
| EV13 | IAM Role Trust Policies | `IAM_Role_Trusts` | Role Name, Trusted Entity, Entity Type, External ID, Conditions, Cross Account |
| EV14 | IAM Role Policies | `IAM_Role_Policies` | Role Name, Assume Role Policy (Trust), Inline Policies, Attached Managed Policies |
| EV15 | IAM User Policies | `IAM_User_Policies` | User Name, Inline Policies, Attached Policies, Permissions Boundary |
| EV16 | IAM Account Password Policy | `IAM_Password_Policy` | Minimum Password Length, Require Symbols, Require Numbers, Require Uppercase, Require Lowercase, Allow Users To Change, Expire Passwords, Max Password Age, Password Reuse Prevention, Hard Expiry |
| EV17 | IAM Access Analyzer Findings | `AccessAnalyzer_Findings` | Analyzer Name, Resource ARN, Resource Type, Finding Type, Public Access, Cross Account, Status |
| EV18 | Organizations Service Control Policies | `Organizations_SCPs` | Policy Name, Policy ID, Attached Targets, AWS Managed, Actions Summary |
| EV19 | AWS Organizations Configuration | `AWS_Organizations_Config` | Org ID, Master Account ID, Master Account Email, Feature Set, Total Accounts, Root ID, SCPs Enabled |
| EV173 | Organizations Delegated Admins & Services | `Organizations_Delegated_Services` | Type, Service Principal, Account ID, Account Email, Delegation Date |
| EV174 | Control Tower Baselines & Guardrails | `ControlTower_Guardrails` | Type, Target Identifier, Baseline/Control ARN, Baseline Version, Status, Drift Status |
| EV131 | IAM Credential Report | `IAM_Credential_Report` | User, ARN, User Creation Time, Password Enabled, Password Last Used, Password Last Changed, Password Next Rotation, MFA Active, Access Key 1 Active, Access Key 1 Last Rotated, Access Key 1 Last Used Date, Access Key 1 Last Used Service, Access Key 2 Active, Access Key 2 Last Rotated, Access Key 2 Last Used Date, Cert 1 Active, Cert 2 Active |
| EV132 | IAM Access Advisor | `IAM_Access_Advisor` | Principal ARN, Principal Type, Service Name, Service Namespace, Last Authenticated, Last Authenticated Entity, Last Authenticated Region, Total Authenticated Entities *(capped at first 200 principals)* |
| EV133 | IAM Roles Last Used | `IAM_Roles_LastUsed` | Role Name, ARN, Created Date, Last Used Date, Last Used Region, Days Since Last Use *(excludes service-linked roles)* |
| EV134 | Identity Center Assignments | `IdentityCenter_Assignments` | Instance ARN, Permission Set Name, Permission Set ARN, Session Duration, Relay State, Inline Policy Present, Managed Policies, Assigned Account ID, Principal Type, Principal ID |
| EV135 | Identity Store Users & Groups | `IdentityStore_Users_Groups` | Identity Store ID, Type, ID, User/Group Name, Display Name, Email, Group Memberships |
| EV136 | Cognito User Pool Configuration | `Cognito_UserPool_Config` | Pool ID, Pool Name, MFA Configuration, Min Password Length, Require Symbols, Require Numbers, Require Upper, Require Lower, Advanced Security Mode, Account Recovery, Created Date |
| EV137 | STS Federation Sources | `STS_Federation_Sources` | Provider Type, Provider ARN, URL or Issuer, Audiences/Clients, Thumbprints, Valid Until, Created Date |
| EV185 | Organizations Tag Policies | `Org_Tag_Policies` | Policy ID, Policy Name, AWS Managed, Target ID, Target Name, Target Type, Content Excerpt |
| EV186 | SCP Attachments | `SCP_Attachments` | SCP ID, SCP Name, Target ID, Target Type, Target Name, OU Path |
| EV187 | IAM Policy Simulator | `IAM_Simulator` | Principal ARN, Principal Type, Action, Decision, Matched Statements Count *(capped at 200 principals)* |
| EV188 | Identity Center Inline Policies | `IdentityCenter_InlinePolicies` | Permission Set ARN, Permission Set Name, Type, Policy Name / Inline Content, Policy Path |
| EV189 | IAM Roles Anywhere | `IAM_RolesAnywhere` | Type, ID, Name, Enabled, Source / Role ARNs, Notification / Session Policy |
| EV190 | IAM Permissions Boundaries | `IAM_Boundaries` | Principal Type, Principal ARN, Has Boundary, Boundary Policy ARN, Boundary Type |
| EV209 | Verified Permissions | `VerifiedPermissions_Stores` | Policy Store ID, Validation Mode, Policy ID, Policy Type, Principal, Resource |

### Certificates & PKI

| # | Name | Filename Prefix | Columns |
|---|------|----------------|---------|
| EV20 | Certificate Manager Certificates | `Certificate_Manager_Certificates` | Certificate ARN, Domain Name, Expires, In Use By, Issued On, Issuer, Key Algorithm, Renewal Eligibility, Signature Algorithm, Status, Cert Type |

### CloudTrail & Audit

| # | Name | Filename Prefix | Columns |
|---|------|----------------|---------|
| EV21 | CloudTrail Logs | `CloudTrail_Logs` | Cloud Trail Name, Apply Trail To All Regions, Log File Validation, S3 Bucket, Cloud Watch Logs Log Group ARN, Is Logging, Include Management Events, Read/Write Type |
| EV22 | CloudTrail Configuration | `CloudTrail_Config` | Trail Name, Trail ARN, Is Multi-Region, Home Region, Log File Validation, S3 Bucket, Is Logging, Event Selectors, Insight Selectors |
| EV23 | CloudTrail Event Selectors | `CloudTrail_EventSelectors` | Trail Name, Trail ARN, Management Events, Read Write Type, Data Events Enabled, Data Resource Types |
| EV24 | CloudTrail Log Validation | `CloudTrail_LogValidation` | Trail Name, S3 Bucket, Log Validation Enabled, Is Logging, Latest Delivery, Latest Digest |
| EV25 | CloudTrail S3 Bucket Policies | `CloudTrail_S3Policy` | Trail Name, S3 Bucket, Public Access Block, Encryption Type, Access Logging Enabled, Policy Has Public Allow |
| EV26 | CloudTrail Change Events | `CloudTrail_ChangeEvents` | Event Name, Event Source, Resource Type, Resource Name, User Identity, Timestamp, Source IP *(last 7 days)* |
| EV27 | CloudTrail S3 Data Events | `CloudTrail_S3DataEvents` | Trail Name, S3 Bucket/Prefix, Read Events, Write Events, Advanced Selector |
| EV28 | CloudTrail Configuration Change Events | `CloudTrail_Config_Changes` | Event Name, Event Time, User Identity, Source IP Address, Request Parameters, Response Elements *(last 90 days)* |
| EV29 | CloudTrail IAM Changes (High-Risk) | `CloudTrail_IAM_Changes` | Event Name, User Identity, Event Time, Request Parameters *(last 90 days — CreateUser, CreateRole, AttachPolicy, AssumeRole, etc.)* |
| EV125 | CloudTrail Account Management Events | `CloudTrail_AccountMgmt_Events` | Event Name, Event Time, User Identity, Source IP, Target User, Request Parameters, Response Elements *(last 90 days unless date window provided)* |
| EV126 | CloudTrail Session Events | `CloudTrail_Session_Events` | Event Name, Event Time, User Identity, Source IP, User Agent, MFA Used, Success, Error Message *(last 90 days unless date window provided)* |
| EV127 | CloudTrail Privileged Action Events | `CloudTrail_PrivilegedAction_Events` | Event Name, Event Source, Event Time, User Identity, Source IP, Request Parameters *(last 90 days unless date window provided — IAM policy/role, KMS disable, CloudTrail/Config tamper, Org changes, S3 policy)* |
| EV128 | CloudTrail Insights | `CloudTrail_Insights` | Trail Name, Insight Type, Event Time, Insight State, Source, Baseline Average, Insight Value *(last 90 days unless date window provided)* |
| EV129 | CloudTrail Lake Event Data Stores | `CloudTrail_Lake_Queries` | Event Data Store Name, ARN, Retention Period (days), Multi-Region, Org Enabled, Status, KMS Key, Recent Query Count (30d) |
| EV130 | Athena Log-Review Saved Queries | `Athena_LogReview_Queries` | WorkGroup, Query Name, Query ID, Database, Description, Last Executed, Query Statement Excerpt *(filtered to queries against CloudTrail/VPC Flow/WAF/SecurityHub/GuardDuty tables)* |

### AWS Config

| # | Name | Filename Prefix | Columns |
|---|------|----------------|---------|
| EV30 | AWS Config Rules | `AWS_Config_Rules` | Rule Name, Compliance Status, Resource Type, Last Evaluated |
| EV31 | AWS Config Recorder | `AWS_Config_Recorder` | Recorder Name, Role ARN, All Supported, Include Global Resources, Recording, Last Status, Last Status Change |
| EV32 | AWS Config Resource History | `Config_ResourceHistory` | Resource Type, Resource ID, Resource Name, Change Type, Capture Time, Config Status |
| EV33 | AWS Config Resource Timeline | `Config_Resource_Timeline` | Resource ID, Resource Type, Capture Time, Config State ID, Configuration (excerpt), Change Type |
| EV34 | AWS Config Compliance History | `Config_Compliance_History` | Config Rule Name, Resource ID, Resource Type, Compliance Type, Ordering Timestamp |
| EV35 | AWS Config Snapshot (Point-in-Time) | `Config_Snapshot` | Resource ID, Resource Type, Resource Name, Account ID, Configuration (excerpt), Relationships |

### CloudFormation

| # | Name | Filename Prefix | Columns |
|---|------|----------------|---------|
| EV36 | CloudFormation Stack Drift | `CloudFormation_Drift` | Stack Name, Stack Status, Drift Status, Last Drift Check, Drifted Resource Count, Resource Drifts |

### CloudWatch & Monitoring

| # | Name | Filename Prefix | Columns |
|---|------|----------------|---------|
| EV37 | Log Metric Filters and Alarms | `Log_Metric_Filters_and_Alarms` | Metric Filter Name, Metric Filter Namespace, Metric Filter Metric, Alarms, Alarm Actions, Cloud Watch Logs Log Group ARN |
| EV38 | CloudWatch Log Group Config | `CloudWatch_Log_Group_Config` | Log Group Name, Retention In Days, KMS Key ID, Stored Bytes, Created At |
| EV39 | Metric Filter Configuration | `Metric_Filter_Config` | Filter Name, Log Group Name, Filter Pattern, Metric Transformations |
| EV40 | CloudWatch Alarms | `CloudWatch_Alarms` | Alarm Name, Metric, Threshold, Comparison Operator, Actions Enabled, State |
| EV41 | CloudWatch Log Groups | `CloudWatch_Log_Groups` | Log Group Name, Retention Days, KMS Key ARN, Stored Bytes, Region |
| EV42 | CloudWatch Alarms for Config Changes | `Change_Alerts_Config` | Alarm Name, Metric Name, Namespace, Threshold, Comparison Operator, Actions Enabled, Alarm Actions |
| EV138 | CloudWatch Logs Insights Saved Queries | `CloudWatch_LogsInsights_SavedQueries` | Query Name, Query Definition ID, Last Modified, Log Groups, Query String Excerpt |
| EV140 | CloudWatch Contributor Insights Rules | `CloudWatch_ContributorInsights` | Rule Name, State, Schema, Definition Excerpt, Managed Rule |
| EV144 | CloudWatch Anomaly Detectors | `CloudWatch_AnomalyDetectors` | Detector Type, Metric Namespace, Metric Name, Dimensions, Stat, State, Configuration Excerpt |
| EV178 | CloudWatch Synthetics Canaries | `Synthetics_Canaries` | Canary Name, Runtime Version, Schedule, State, Last Started, Last Modified |
| EV194 | OAM Sinks & Links | `OAM_Sinks_Links` | Type, ARN, Name / Label, Sink ARN, Resource Types |

### Compute — EC2

| # | Name | Filename Prefix | Columns |
|---|------|----------------|---------|
| EV43 | EC2 Instances | `EC2_Instances` | Instance ID, Instance Type, AMI ID, State, VPC ID, Subnet ID, IAM Role, Encryption, Region |
| EV44 | EC2 Instance Details | `EC2_Detailed` | Instance ID, Instance Type, AMI ID, AMI Owner ID, IMDS Version, EBS Optimized, Monitoring |
| EV45 | EC2 Instance Configuration | `EC2_Config` | Instance ID, Image ID, Instance Type, State, IMDS Version, IAM Instance Profile, Block Devices, Monitoring |
| EV46 | EC2 Launch Templates | `Launch_Template_Config` | Template ID, Template Name, Version, Image ID, Instance Type, Security Group IDs, IAM Instance Profile |
| EV47 | Auto Scaling Groups | `AutoScaling_Groups` | Group Name, Launch Template, Desired Capacity, Min, Max, Instances, Region |
| EV48 | EBS Volumes | `EBS` | Volume ID, Volume ARN, Availability Zone, Encryption Status, KMS Key ARN, Region |
| EV49 | EBS Default Encryption | `EBS_DefaultEncryption` | Region, Default Encryption Enabled, KMS Key ID |
| EV50 | EBS Encryption Config | `EBS_Encryption_Config` | Region, EBS Encryption By Default, Default KMS Key ID |
| EV183 | Compute Optimizer Recommendations | `Compute_Optimizer` | Resource Type, ARN, Current Config, Finding, Recommended Config, Est. Monthly Savings ($) |

### Compute — Containers

| # | Name | Filename Prefix | Columns |
|---|------|----------------|---------|
| EV51 | ECS Clusters | `ECS_Clusters` | Cluster Name, Status, Running Tasks, Container Insights Enabled |
| EV52 | EKS Clusters | `EKS_Clusters` | Cluster Name, Version, Endpoint Public Access, Logging Enabled |
| EV53 | ECR Repository Configuration | `ECR_Config` | Repository Name, Registry ID, URI, Image Tag Mutability, Scan On Push, Encryption Type, KMS Key, Has Lifecycle Policy |
| EV167 | ECR Image Signatures & Scanning | `ECR_Signatures_ScanConfig` | Repository, Registry Scan Type, Enhanced Filters, Image Digest, Image Tags, Signature Present, Signature Type |
| EV196 | EKS Add-ons | `EKS_AddOns` | Cluster Name, Addon Name, Addon Version, Status, Health Issues |
| EV197 | EKS Access Entries | `EKS_AccessEntries` | Cluster Name, Principal ARN, Type, K8s Groups, Access Policies |
| EV198 | EKS Pod Identity | `EKS_PodIdentity` | Cluster Name, Namespace, Service Account, Role ARN, Association ID |
| EV199 | ECS Task Definitions | `ECS_TaskDefinitions` | Family, Revision, Network Mode, Container Name, Privileged, Run As User, Readonly Root FS, Added Capabilities |
| EV200 | ECR Replication | `ECR_Replication` | Rule Index, Destination Region, Destination Account, Repository Filter Type, Repository Filter |

### Compute — Serverless

| # | Name | Filename Prefix | Columns |
|---|------|----------------|---------|
| EV55 | Lambda Function Configuration | `Lambda_Config` | Function Name, Runtime, Role ARN, Handler, Timeout (s), Memory (MB), VPC ID, Env Vars (count, redacted), Dead Letter Config |
| EV56 | Lambda Function Permissions | `Lambda_Permissions_Config` | Function Name, Statement ID, Principal, Action, Source ARN, Effect |

### Databases

| # | Name | Filename Prefix | Columns |
|---|------|----------------|---------|
| EV57 | RDS Inventory | `RDS` | DB Instance ARN, Engine, Engine Version, Encryption Status, KMS Key ARN, Publicly Accessible, Auto Minor Version Upgrades, Region |
| EV58 | RDS Backup Configuration | `RDS_Backup_Config` | DB Instance ID, Engine, Multi-AZ, Backup Retention (days), Preferred Backup Window, Auto Minor Upgrade, Deletion Protection |
| EV59 | RDS Snapshots | `RDS_Snapshots` | Snapshot ID, DB Instance ID, Snapshot Type, Encrypted, KMS Key ID, Created Time, Public Accessible |
| EV60 | DynamoDB Tables | `DynamoDB` | Table ARN, Table Name, Encryption Status, Encryption Type, KMS Key ARN, Region |
| EV61 | ElastiCache Clusters | `ElastiCache` | Cluster Name, Engine, Engine Version, Encryption In Transit, Encryption At Rest, Availability Zone, Cluster ARN, KMS Key ARN, Region |
| EV62 | ElastiCache Global Datastores | `ElastiCache_Global_Datastore` | Name, Engine, Engine Version, Encryption In Transit, Encryption At Rest, ARN, Region |
| EV151 | RDS PITR & Cluster Backtrack | `RDS_PITR_Backtrack` | Identifier, Type, Engine, Backup Retention (days), Earliest Restorable, Latest Restorable, Backtrack Window (s), Earliest Backtrack |
| EV201 | Glue Catalog | `Glue_Catalog` | Database, Table, Owner, Type, Storage Location, Input Format |
| EV202 | Lake Formation Permissions | `LakeFormation_Permissions` | Principal, Resource Type, Resource Identifier, Permissions, Grantable Permissions |
| EV203 | Redshift Clusters | `Redshift_Clusters` | Cluster ID, Node Type, Status, Encrypted, KMS Key, Publicly Accessible, Enhanced VPC Routing, Logging Enabled, Log Bucket |
| EV204 | OpenSearch Domains | `OpenSearch_Domains` | Domain Name, Engine, At-Rest Encryption, KMS Key, Node-to-Node, Enforce HTTPS, TLS Policy, VPC ID, Audit Logs Enabled |
| EV205 | MSK Clusters | `MSK_Clusters` | Cluster ARN, Name, State, Type, At-Rest KMS, In-Transit Client-Broker, SASL/SCRAM, IAM Auth, Broker Logs CW, Broker Logs S3 |

### Encryption & Key Management

| # | Name | Filename Prefix | Columns |
|---|------|----------------|---------|
| EV63 | KMS Keys | `KMS_Keys` | Key ID, ARN, Key Manager, Key State, Rotation Enabled, Region |
| EV64 | KMS Key Policies | `KMS_KeyPolicies` | Key ID, Key ARN, Key State, Rotation Enabled, Key Usage, Policy Allows External Access |
| EV65 | KMS Key Configuration | `KMS_Key_Configuration` | Key ID, Key ARN, Enabled, Key Usage, Origin, Key State, Rotation Enabled, Key Policy |
| EV66 | Secrets Manager | `Secrets_Manager` | Secret Name, ARN, Rotation Enabled, Last Rotated, Region |
| EV67 | Secrets Manager Resource Policies | `Secrets_Manager_Policies` | Secret Name, Secret ARN, KMS Key ID, Rotation Enabled, Rotation Interval (days), Last Rotated, Has Resource Policy |
| EV164 | KMS Grants & Rotation | `KMS_Grants_Rotation` | Key ID, Key ARN, Creation Date, Rotation Enabled, Grant ID, Grantee Principal, Operations, Grant Created |

### Messaging & Events

| # | Name | Filename Prefix | Columns |
|---|------|----------------|---------|
| EV68 | SNS Topic Subscribers | `SNS_Topic_Subscribers` | Subscription ID, SNS Topic Name, SNS Topic ARN, Region |
| EV69 | SNS Topic Policies | `SNS_Topic_Config` | Topic ARN, Display Name, Subscriptions Confirmed, Subscriptions Pending, KMS Key ID, Has Policy |
| EV70 | EventBridge Rules | `EventBridge_Rules_Config` | Rule Name, Event Bus, State, Schedule / Event Pattern, Targets |
| EV71 | EventBridge Rules for Changes | `Change_Event_Rules` | Rule Name, Event Bus, State, Event Pattern, Targets *(event-pattern rules only)* |
| EV139 | EventBridge Archives & Replays | `EventBridge_Archives_Replays` | Archive Name, Event Source ARN, State, Retention Days, Size (bytes), Event Count, Recent Replay Count |
| EV145 | Firehose Delivery Streams | `Firehose_DeliveryStreams` | Stream Name, Stream ARN, Stream Status, Source Type, Destination Type, Destination Bucket/Endpoint, Encryption (KMS Key), Created Time |
| EV206 | Step Functions Executions | `StepFunctions_Executions` | State Machine ARN, Name, Type, Logging Level, Recent Failed Count, Latest Failure Time |
| EV207 | Kinesis Data Streams | `Kinesis_DataStreams` | Stream Name, Stream ARN, Mode, Retention (hours), Encryption Type, KMS Key |

### Network

| # | Name | Filename Prefix | Columns |
|---|------|----------------|---------|
| EV72 | VPCs | `VPCs` | ID, Name, CIDR Block, Owner, Region |
| EV73 | Network ACLs | `Network-ACL` | Network ACL ID, Rule Count, Subnet Associations, Default, VPC, Ingress Rules, Egress Rules, Owner, ARN, Region |
| EV74 | VPC Configuration | `VPC_Config` | VPC ID, CIDR Block, State, Instance Tenancy, Enable DNS Support, Enable DNS Hostnames, Is Default |
| EV75 | VPC Flow Logging | `VPC_Flow_Logging` | VPC ID, VPC Flow Log Name, VPC Flow Log ID, Filter, Destination, Destination Log Group, IAM Role, Status, Log Line Format |
| EV76 | VPC Endpoints | `VPC_Endpoints_Config` | Endpoint ID, VPC ID, Service Name, Endpoint Type, State, Private DNS Enabled, Has Policy |
| EV77 | Internet Gateways | `Network_InternetGateways` | Gateway ID, Attached VPC ID, Attachment State, Name Tag, Region |
| EV78 | NAT Gateways | `Network_NatGateways` | NAT Gateway ID, Subnet ID, VPC ID, Public IP, Private IP, Connectivity Type, State |
| EV79 | Security Groups | `Security_Groups` | Group ID, Group Name, Inbound Rules, Outbound Rules, VPC ID, Region |
| EV80 | Security Group Configuration | `Security_Group_Config` | Group ID, Name, Description, VPC ID, Ingress Rules, Egress Rules |
| EV81 | Route Tables | `Route_Tables` | Route Table ID, Routes, Subnet Associations, VPC ID, Region |
| EV82 | Route Table Configuration | `Route_Table_Config` | Route Table ID, VPC ID, Routes, Associations, Propagating VGWs |
| EV83 | Public Resources | `Public_Resources` | Resource ID, Resource Type, Public IP / DNS, Port Exposure, Notes |
| EV84 | Route53 Hosted Zones | `Route53_Config` | Zone ID, Name, Private Zone, Record Count, Comment, Sample Records |
| EV85 | Route53 Resolver Rules | `Route53_Resolver_Config` | Rule ID, Name, Domain Name, Rule Type, Status, Target IPs |
| EV86 | API Gateway | `API_Gateway` | API Name, Endpoint Type, Authorization Type, Logging Enabled, Region |
| EV87 | CloudFront Distributions | `CloudFront_Distributions` | Distribution ID, Domain Name, WAF Enabled, Logging Enabled, TLS Version |
| EV160 | VPC Traffic Mirroring Sessions | `VPC_TrafficMirroring` | Session ID, Network Interface, Target ID, Filter ID, Session Number, VNI |
| EV161 | Transit Gateway Route Tables | `TGW_RouteTables` | TGW ID, Route Table ID, RT State, Default Assoc, Default Prop, Destination CIDR, Route State, Route Type, Target Attachment |
| EV162 | PrivateLink Endpoint Services | `PrivateLink_Services` | Service ID, Service Name, NLB ARNs, Acceptance Required, Allowed Principals, Availability Zones |
| EV163 | Route53 Resolver DNS Firewall | `Route53_DNSFirewall` | Type, ID, Name, Status / Action, VPC ID, Owner / Priority, Details |
| EV165 | AppMesh TLS Configuration | `AppMesh_TLS_Config` | Mesh Name, Resource Type, Resource Name, Listener Port, TLS Mode, Certificate Type |
| EV208 | VPC Lattice | `VPC_Lattice` | Type, ID, Name, Auth Type, Status, Policy Excerpt |
| EV210 | Direct Connect & VPN | `DirectConnect_VPN` | Type, ID, State, Bandwidth / VLAN, Location / Tunnel CIDR, Encryption / Customer Addr |
| EV211 | Global Accelerator | `GlobalAccelerator` | Type, ARN, Name, Status, Protocol / Region, Port Ranges / Traffic Dial |
| EV212 | API Gateway Deep Config | `APIGateway_Deep` | API Type, API ID, Stage, Endpoint Type, WAF ACL, Logging Level, Tracing, Has Resource Policy, Disable Execute-API |

### Load Balancing

| # | Name | Filename Prefix | Columns |
|---|------|----------------|---------|
| EV88 | Load Balancers | `Load_Balancers` | Name, Balancer Type, ARN, Region |
| EV89 | Load Balancer Listeners | `Load_Balancer_Listeners` | Balancer Name, ARN, Certificate ID, Protocol, Region |
| EV90 | Load Balancer Configuration | `Load_Balancer_Config` | LB Name, LB ARN, Type, Scheme, VPC ID, Security Groups, Listeners, SSL Policies |
| EV91 | ALB Access Log Configuration | `ALB_AccessLogs` | ALB Name, ALB ARN, Scheme, Access Logs Enabled, Access Logs S3 Bucket, Access Logs S3 Prefix |

### Storage

| # | Name | Filename Prefix | Columns |
|---|------|----------------|---------|
| EV92 | EFS File Systems | `EFS` | File System ID, File System Name, File System ARN, KMS Key ARN, Encryption Status, Region |
| EV93 | S3 Buckets Config | `S3_Buckets_Config` | Bucket Name, Public Access Block, Versioning, Encryption, Logging, Policy, Region |
| EV94 | S3 Bucket Access Logging | `S3_Bucket_Access_Logging` | Bucket Name, Bucket ARN, Storage Encrypted, Encryption Type, Block Public Access, MFA Delete, Logging, KMS Key ID, Region |
| EV95 | S3 Bucket Policies | `S3_Policies` | Bucket Name, Public Access Block All, TLS Enforced, Has Bucket Policy, Policy Allows Public, Default Encryption |
| EV96 | S3 Bucket Encryption Config | `S3_Encryption_Config` | Bucket Name, SSE Algorithm, KMS Master Key ID, Bucket Key Enabled |
| EV97 | S3 Bucket Policy | `S3_Bucket_Policy` | Bucket Name, Has Policy, Policy Document |
| EV98 | S3 Public Access Block | `S3_Public_Access_Block` | Bucket Name, Block Public ACLs, Ignore Public ACLs, Block Public Policy, Restrict Public Buckets |
| EV99 | S3 Logging Configuration | `S3_Logging_Config` | Bucket Name, Logging Enabled, Target Bucket, Target Prefix |
| EV152 | S3 Bucket Replication | `S3_Replication_Config` | Source Bucket, Rule ID, Status, Priority, Destination Bucket, Destination Account, KMS Key, RTC Enabled |
| EV153 | S3 Object Lock Configuration | `S3_ObjectLock_Config` | Bucket Name, Object Lock Enabled, Default Mode, Default Retention Days, Default Retention Years |

### Security Services

| # | Name | Filename Prefix | Columns |
|---|------|----------------|---------|
| EV100 | GuardDuty Findings | `GuardDuty_Findings` | Finding ID, Type, Severity, Resource, Region, Created At, Status |
| EV101 | GuardDuty Configuration | `GuardDuty_Config` | Detector ID, Status, S3 Protection, EKS Audit Logs, Malware Protection, Created At |
| EV102 | GuardDuty Suppression Rules | `GuardDuty_Suppression` | Detector ID, Rule Name, Action, Description, Filter Criteria Summary |
| EV103 | Security Hub Findings | `SecurityHub_Findings` | Control ID, Severity, Compliance Status, Resource ARN, Region |
| EV104 | Security Hub Enabled Standards | `SecurityHub_Standards` | Standard Name, Standards ARN, Status, Subscribed At |
| EV105 | Security Hub Configuration | `SecurityHub_Config` | Hub ARN, Auto Enable Controls, Subscribed Standards, Subscribed At |
| EV106 | Inspector2 Findings | `Inspector2_Findings` | Finding ARN, Account ID, Type, Title, Description, Severity, Inspector Score, EPSS Score, CVE ID, CVE Source, CVE Source URL, Vendor Severity, Vendor Created At, Vendor Updated At, CVSS Base Score, CVSS Scoring Vector, Related Vulnerabilities, Reference URLs, Package Name, Package Version, Package Arch, Package Manager, Package File Path, Fixed In Version, Package Remediation, Source Layer Hash, Resource ID, Resource Type, Resource Region, Remediation Text, Remediation URL, Exploit Available, Last Known Exploit At, Status, Fix Available, First Observed At, Last Observed At, Updated At |
| EV106a | Inspector2 ECR Findings | `Inspector2_ECR_Findings` | Finding ARN, Severity, Type, CVE ID, Repository, Image Tag, Image Digest, Package Name, Package Version, Fixed Version, Status, Fix Available, Title |
| EV107 | Inspector2 Configuration | `Inspector_Config` | Resource Type, Scan Status, Scan Type, EC2 Status, ECR Status, Lambda Status |
| EV108 | Inspector2 Findings History | `Inspector_Findings_History` | Finding ID, First Observed At, Last Observed At, Status, Severity, Resource ID, Title |
| EV109 | Macie Findings | `Macie_Findings` | Finding ID, Finding Type, Resource ARN, Severity, Count, Created At |
| EV110 | WAF Regional Web ACL Rules | `WAF_Regional_Web_ACL_Rules` | Name, Web ACL Name, Managed Rule, Default Action, Region |
| EV111 | WAF Web ACL Configuration | `WAF_Config` | Web ACL Name, Web ACL ARN, Default Action, Rules Count, Rule Names, CloudWatch Metric, Sampled Requests Enabled |
| EV112 | WAFv2 Logging Configuration | `WAF_Logging` | Web ACL Name, Web ACL ARN, Logging Enabled, Log Destination, Sampled Requests Enabled |
| EV141 | Detective Graphs | `Detective_Graphs_Config` | Graph ARN, Created Time, Member Account ID, Member Status, Datasource Packages |
| EV142 | Security Hub Insights | `SecurityHub_Insights` | Insight ARN, Name, Group By Attribute, Filters Summary |
| EV143 | GuardDuty Coverage | `GuardDuty_Coverage` | Detector ID, Resource ID, Resource Type, Coverage Status, Issue, Updated At |
| EV157 | Inspector2 Coverage | `Inspector2_Coverage` | Resource ID, Resource Type, Scan Status, Scan Status Reason, Scan Type, Account ID |
| EV158 | Inspector2 Suppression Rules | `Inspector2_Suppression_Rules` | Filter ARN, Name, Created At, Updated At, Owner, Reason, Filter Criteria Fields |
| EV159 | WAF Logging Destinations | `WAF_LoggingDestinations_Sampled` | Web ACL Name, Web ACL ARN, Logging Enabled, Log Destinations, Redacted Fields Count, Logging Filter Present |
| EV166 | AWS Signer Profiles & Jobs | `Signer_Profiles_Jobs` | Type, Profile Name, Profile Version, Platform ID, Status, Job ID, Source S3, Signed At |
| EV168 | CodeArtifact Repositories | `CodeArtifact_Repos_Sources` | Domain, Repository, Description, Upstreams, External Connections, Created Time |
| EV169 | AWS Artifact Reports | `Artifact_Reports` | Report ID, Name, Series, Category, State, Periodic Update, Last Modified, Acceptance Type |
| EV170 | CodePipeline & CodeBuild Config | `CodePipeline_CodeBuild` | Resource Type, Name, Source Provider, Source Location, Has Manual Approval, Privileged Mode, Logs Destination, Service Role |
| EV171 | Trusted Advisor Checks | `TrustedAdvisor_Checks` | Check ID, Name, Category, Status, Resources Flagged, Timestamp *(requires Business/Enterprise Support)* |
| EV172 | AWS Health Events | `AWS_Health_Events` | Event ARN, Service, Event Type Code, Region, Start Time, End Time, Status, Category *(last 90 days; requires Business+ support)* |
| EV175 | Audit Manager Assessments | `AuditManager_Assessments` | Assessment ID, Name, Framework, Status, Last Updated, Total Control Sets |
| EV177 | FIS Experiments | `FIS_Experiments` | Type, ID, Template ID / Description, State / Creation Time |
| EV179 | Macie Classification Jobs | `Macie_Classification_Jobs` | Job ID, Name, Job Type, Status, Created At, Last Run, Bucket Definitions Count |

### Systems Manager (SSM)

| # | Name | Filename Prefix | Columns |
|---|------|----------------|---------|
| EV113 | SSM Managed Instances | `SSM_ManagedInstances` | Instance ID, Computer Name, Platform, SSM Agent Version, Ping Status, Last Ping |
| EV114 | SSM Patch Compliance | `SSM_PatchCompliance` | Instance ID, Resource Type, Compliance Status, Overall Severity, Non Compliant Count |
| EV115 | SSM Patch Baselines | `SSM_Patch_Baseline_Config` | Baseline ID, Name, Operating System, Default Baseline, Approved Patches, Patch Rules Summary |
| EV116 | SSM Parameter Store Config | `SSM_Parameter_Config` | Name, Type, KMS Key ID, Last Modified, Description, Tier |
| EV117 | EC2 Time Sync Config (SSM) | `Time_Sync_Config` | Instance ID, Computer Name, Platform, SSM Ping Status, Time Source Note |
| EV118 | SSM Patch Compliance (Detailed) | `SSM_Patch_Compliance_Detail` | Instance ID, Patch ID, Title, Severity, State, Installed Time |
| EV119 | SSM Patch Summary | `SSM_Patch_Summary` | Instance ID, Compliance Status, Critical Count, Security Count, Other Count, Missing Count, Installed Count, Operation |
| EV120 | SSM Patch Execution History | `SSM_Patch_Execution` | Command ID, Instance ID, Requested Date Time, Completed Date Time, Status |
| EV121 | SSM Maintenance Windows | `SSM_Maintenance_Window` | Window ID, Name, Enabled, Schedule, Duration (hrs), Targets, Tasks |
| EV154 | SSM Compliance Summary | `SSM_Compliance_Summary` | Resource ID, Resource Type, Compliance Type, Overall Severity, Compliant Count, Non-Compliant Count, Last Execution Time |
| EV155 | SSM Associations | `SSM_Association_Compliance` | Association ID, Document Name, Targets, Schedule Expression, Last Execution Status, Last Execution Time |
| EV156 | SSM Automation Executions | `SSM_Automation_Executions` | Execution ID, Document Name, Start Time, End Time, Status, Executed By, Target Resources *(last 90 days)* |
| EV191 | SSM OpsItems | `SSM_OpsItems` | OpsItem ID, Title, Status, Priority, Source, Category, Severity, Created, Last Modified |
| EV192 | SSM Change Requests | `SSM_ChangeRequests` | OpsItem ID, Title, Status, Priority, Source, Created, Last Modified |
| EV195 | AppConfig Deployments | `AppConfig_Deployments` | App Name, Environment, Deployment #, Config Version, State, Started, Completed |

### Backup

| # | Name | Filename Prefix | Columns |
|---|------|----------------|---------|
| EV122 | AWS Backup Plans | `Backup_Plans_Config` | Plan ID, Plan Name, Version ID, Rules Count, Rules Summary |
| EV123 | Backup Vault Configuration | `Backup_Vault_Config` | Vault Name, Vault ARN, Encryption Key ARN, Recovery Points, Has Access Policy |
| EV146 | Backup Vault Lock Configuration | `Backup_VaultLock_Config` | Vault Name, Vault ARN, Locked, Lock Date, Min Retention (days), Max Retention (days) |
| EV147 | Backup Plan Copy Actions | `Backup_Plan_Copy_Actions` | Plan ID, Plan Name, Rule Name, Destination Vault ARN, Destination Region, Destination Account, Cold Storage After (days), Delete After (days) |
| EV148 | Backup Restore Testing Plans | `Backup_RestoreTesting` | Test Plan Name, Schedule, Selection Window (days), Last Execution Time, Last Status, Selections |
| EV149 | DRS Source Server Replication | `DRS_Replication_Status` | Source Server ID, Source Hostname, Replication State, Lag Duration, Last Snapshot, Recovery Instance ID |
| EV150 | Route53 ARC Routing Controls & Readiness | `Route53_ARC_Controls` | Type, Cluster/Check ARN, Control Panel / Resource, Name, Status / Routing State |
| EV193 | Resilience Hub Apps | `ResilienceHub_Apps` | App ARN, App Name, Compliance Status, Resiliency Score, Last Eval, Recent Assessment Status |

### Tagging & Inventory

| # | Name | Filename Prefix | Columns |
|---|------|----------------|---------|
| EV124 | Resource Tagging Configuration | `Resource_Tagging_Config` | Resource ARN, Resource Type, Owner, Environment, Data Classification, All Tags |
| EV176 | Resource Explorer Indexes & Views | `ResourceExplorer_Indexes` | Type, ARN, Index Type, Region, State, Created At |
| EV180 | Cost Anomaly Detection | `Cost_Anomaly` | Type, ID / Monitor Name, Detail, Start Date, Impact ($) *(last 90 days)* |
| EV181 | Budgets | `Budgets` | Budget Name, Type, Time Unit, Limit, Actual Spend, Forecasted Spend |
| EV182 | Savings Plans & Reserved Instances | `Savings_Plans_RIs` | Type, ID, Instance Type / Plan Type, State, Start, End, Commitment / Price |
| EV184 | Tagging Compliance | `Tagging_Compliance` | Type, Target / Resource ARN, Resource Type / Status, Region, Non-Compliant Count / Keys |

---

## Asset Inventory (Unified CSV — Inventory Feature)

The **Inventory** feature is a separate TUI flow (Welcome → Feature Selection → … → Inventory → Options → Confirm → Run). It queries selected AWS asset types in parallel and writes a **single unified CSV** using the 14-column canonical schema below. Available via the "Inventory" option on the Feature Selection screen.

### Canonical 14-Column Schema

| Column | Description |
|--------|-------------|
| `UNIQUE ASSET IDENTIFIER` | Primary identifier for the asset (ARN, ID, name) |
| `IPv4 or IPv6 Address` | IP address (where applicable) |
| `Virtual` | Always "Yes" for cloud-managed services |
| `Public` | "Yes" if publicly reachable, "No" otherwise |
| `DNS Name or URL` | Public endpoint or DNS name |
| `MAC Address` | MAC address (EC2 ENI only) |
| `Location` | AWS region and/or AZ |
| `Asset Type` | Human-readable asset type label |
| `Hardware Make/Model` | Instance type or service tier |
| `Software/ Database Vendor` | Vendor (Amazon Web Services, PostgreSQL, etc.) |
| `Software/ Database Name & Version` | Service name and version/runtime |
| `Function` | Description or purpose (from tags or metadata) |
| `VLAN/ Network ID` | VPC and Subnet identifiers |
| `Comments` | Free-text summary of key configuration details |

### Supported Asset Types

| Asset Type Key | Label | Output File Prefix | Notes |
|---------------|-------|--------------------|-------|
| `kms-key` | KMS Key | `AWS_Inventory` | Customer-managed keys only (skips AWS-managed) |
| `s3-bucket` | S3 Bucket | `AWS_Inventory` | Includes public-access status, encryption, versioning, logging |
| `lambda-function` | Lambda Function | `AWS_Inventory` | Includes runtime, VPC config, role, layers |
| `ec2-instance` | EC2 Instance | `AWS_Inventory` | Includes IPs, ENI MACs, VPC/subnet, instance type |
| `alb` | Application Load Balancer | `AWS_Inventory` | Includes scheme, listeners, security groups |
| `rds-db-instance` | RDS DB Instance | `AWS_Inventory` | Includes engine, version, endpoint, subnet group |
| `elasticache-cluster` | ElastiCache Cluster | `AWS_Inventory` | Includes engine, endpoints, node type |
| `container` | Container (ECR/ECS/EKS) | `AWS_Inventory` | One row per ECR image digest; cross-references ECS/EKS |

All selected asset types are queried in parallel. Output is a single CSV with empty strings for columns not applicable to a given asset type. When multiple regions are selected via Options, one file is written per region in a per-region subdirectory.

---

## Summary

| Category | Count |
|----------|-------|
| JSON evidence collectors (time-windowed) | 4 |
| CSV evidence collectors (current-state snapshots) | 175 |
| Asset Inventory asset types (Inventory feature) | 8 |
| **Total evidence collectors** | **179** |

### AWS Services Covered

Access Analyzer · ACM · AppMesh · API Gateway · Artifact · Athena · Audit Manager ·
Auto Scaling · Backup · CloudFormation · CloudFront · CloudTrail · CloudWatch ·
CloudWatch Logs · CodeArtifact · CodeBuild · CodePipeline · Cognito · Config ·
Control Tower · Detective · DRS · DynamoDB · EBS · EC2 · ECR · ECS · EFS · EKS ·
ElastiCache · ELB/ALB/NLB · EventBridge · EventBridge Archives · FIS · Firehose ·
GuardDuty · Health · IAM · Identity Center · Identity Store · Inspector2 · KMS ·
Lambda · Macie · Organizations · RDS · Resource Explorer · Route53 ·
Route53 ARC · Route53 Resolver · S3 · Secrets Manager · Security Hub · Signer ·
SNS · SSM · Support · Synthetics · VPC · WAF / WAFv2
