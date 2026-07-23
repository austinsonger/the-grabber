# Evidence List

All output files produced by this tool. Every collector writes to
`<AccountId>_<FilenamePrefix>-<YYYY-MM-DD-HHMMSS>.<ext>` in the output directory.

> **FedRAMP mapping:** every CSV row and JSON record grabber emits carries
> `FedRAMP Req IDs`, `FedRAMP Control IDs`, and `Source Evidence File`
> columns. Each file also ends with a two-line footer identifying itself.
> Canonical mapping lives in `assets/fedramp-map.json`; see
> `docs/fedramp-coverage.md` for the runtime coverage report.

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
| EV125 | IAM Credential Report — Password/Key Expiration | `IAM_Credential_Report_Expiration` | User, ARN, User Creation Time, Password Enabled, Password Last Used, Password Last Changed, Password Next Rotation, MFA Active, Access Key 1 Active, Access Key 1 Last Rotated, Access Key 1 Last Used Date, Access Key 2 Active, Access Key 2 Last Rotated, Access Key 2 Last Used Date, Cert 1 Active, Cert 1 Last Rotated, Cert 2 Active, Cert 2 Last Rotated |

### Identity — Okta

| # | Name | Filename Prefix | Columns |
|---|------|----------------|---------|
| EV135 | Okta Deprovisioning Timeliness | `Okta_Deprovisioning_Timeliness` | Event ID, Published, Actor Type, Actor Name, Target Type, Target Login, Event Type, Outcome |
| EV136 | Okta Shared/Group Account Inventory | `Okta_Group_Inventory_Shared_Accounts` | Group ID, Name, Type, Description, Members Count, Shared Naming Match |
| EV137 | Okta Lifecycle HRIS Integration | `Okta_Lifecycle_HRIS_Integration_Config` | Kind, ID, Source, Target, Notes |
| EV138 | Okta Automated Provisioning Events | `Okta_Automated_Provisioning_Events` | Event ID, Published, Event Type, Actor Type, Target Login, Is System Principal |
| EV139 | Okta ThreatInsight Detections | `Okta_ThreatInsight_Detections` | Event ID, Published, Event Type, Severity, Actor IP, Outcome, Display Message |
| EV140 | Okta Risk-Account Suspend Timing | `Okta_Risk_Account_Suspend_Timing` | Threat Event ID, Threat Detected At, Target Login, Suspend Event ID, Suspended At, Latency Minutes |
| EV141 | Okta Access Certification Campaigns | `Okta_Access_Certification_Campaigns` | Campaign ID, Name, Status, Created, Started, Ended, Owner |
| EV142 | Okta Sign-In Widget Config | `Okta_SignIn_Widget_Config` | Brand ID, Brand Name, Widget Version, Has Custom Sign-In, Sign-In URL |
| EV143 | Okta Session Policy | `Okta_Session_Policy` | Policy ID, Name, Status, Priority, System |
| EV144 | Okta Publisher Group Membership | `Okta_Publisher_Group_Membership` | Group ID, Group Name, Member ID, Member Login |
| EV145 | Okta Production Access Recertification | `Okta_Prod_Access_Recertification` | Campaign ID, Name, Status, Target Group / Resource, Reviewer, Ended |
| EV146 | Okta Shared-Account Broker Config | `Okta_Shared_Account_Broker_Config` | App ID, Label, Sign-On Mode, Status, Users Assigned |
| EV147 | Okta Password Policy First-Use | `Okta_Password_Policy_First_Use` | Policy ID, Name, Status, Priority, Password Change On First Login, Password Complexity |
| EV148 | Okta Group Membership Change Log | `Okta_Group_Membership_Change_Log` | Event ID, Published, Actor, Change Type, Target Group, Target User |
| EV149 | Okta Offboarding SLA | `Okta_Offboarding_SLA` | Event ID, Published, Login, Actor Name, Hours Since Termination, SLA Met (24hr) |
| EV150 | Okta Transfer Access Diff | `Okta_Transfer_Access_Diff` | User ID, Login, Status, Status Changed, Apps Count, Groups Count, Snapshot Time |
| EV151 | Okta Contractor Deprovisioning | `Okta_Contractor_Deprovisioning` | Event ID, Published, Contractor Login, Actor Name, Days Since Contract End, Outcome |
| EV189 | Okta Users | `Okta_Users` | User ID, Login, Email, First Name, Last Name, Status, Department, Manager, Created, Activated, Status Changed, Last Login, Last Updated, Password Changed |
| EV190 | Okta Groups | `Okta_Groups` | Group ID, Name, Type, Description, Created, Last Updated, Last Membership Updated |
| EV191 | Okta Group Members | `Okta_Group_Members` | Group ID, Group Name, Group Type, Member ID, Member Login, Member Email, Member Status |
| EV192 | Okta Applications | `Okta_Applications` | App ID, Name, Label, Status, Sign-On Mode, Created, Last Updated |
| EV193 | Okta Policies | `Okta_Policies` | Policy ID, Type, Name, Status, Description, Priority, System, Created, Last Updated, Conditions (JSON), Settings (JSON) |
| EV194 | Okta MFA Factors | `Okta_MFA_Factors` | User ID, User Login, Factor ID, Factor Type, Provider, Vendor, Status, Created, Last Updated |
| EV195 | Okta System Log | `Okta_System_Log_Events` | Event UUID, Published, Event Type, Display Message, Severity, Outcome Result, Outcome Reason, Actor ID, Actor Display Name, Actor Alternate ID, Actor Type, Client IP, Client User Agent, Target Summary |

### Device Management — Jamf

| # | Name | Filename Prefix | Columns |
|---|------|----------------|---------|
| EV196 | Jamf Computers | `Jamf_Computers` | Computer ID, Name, Serial Number, Model, OS Version, Last Contact Time, Managed, FileVault Status |
| EV197 | Jamf Mobile Devices | `Jamf_Mobile_Devices` | Device ID, Name, Serial Number, Model, OS Version, Last Enrolled, Managed, Supervised |
| EV198 | Jamf Computer Configuration Profiles | `Jamf_Computer_Config_Profiles` | Profile ID, Name, Category, Distribution Method, Scope |
| EV199 | Jamf Mobile Configuration Profiles | `Jamf_Mobile_Config_Profiles` | Profile ID, Name, Category, Distribution Method, Scope |
| EV200 | Jamf Computer Groups | `Jamf_Computer_Groups` | Group ID, Name, Type, Criteria, Member Count |
| EV201 | Jamf Mobile Device Groups | `Jamf_Mobile_Device_Groups` | Group ID, Name, Type, Criteria, Member Count |
| EV202 | Jamf Policies | `Jamf_Policies` | Policy ID, Name, Category, Frequency, Scope |
| EV203 | Jamf Patch Titles | `Jamf_Patch_Titles` | Title ID, Display Name |
| EV204 | Jamf Patch Compliance | `Jamf_Patch_Compliance` | Title ID, Display Name, Latest Version, Compliant Devices, Out Of Date Devices |

### Ticketing — Jira

| # | Name | Filename Prefix | Columns |
|---|------|----------------|---------|
| EV152 | Jira Offboarding SLA | `Jira_Offboarding_SLA` | Ticket, Summary, Status, Assignee, Reporter, Created, Resolved, Duration Hours, SLA Met (24hr) |
| EV153 | Jira Remote Access Approvals | `Jira_Remote_Access_Approvals` | Ticket, Summary, Status, Requestor, Approver, Created, Resolved, Duration Hours |
| EV154 | Jira External System Approvals | `Jira_External_System_Approvals` | Ticket, Summary, Status, Requestor, Approver, Created, Resolved |
| EV155 | Jira Public Content Review | `Jira_Public_Content_Review` | Ticket, Summary, Status, Reviewer, Created, Resolved |
| EV156 | Jira Logging Coordination | `Jira_Logging_Coordination` | Ticket, Summary, Status, Owner, Created, Resolved |
| EV157 | Jira Audit Posture Change | `Jira_Audit_Posture_Change` | Ticket, Summary, Status, Trigger Indicator, Created, Resolved |
| EV158 | Jira ISA Annual Review | `Jira_ISA_Annual_Review` | Ticket, Summary, Status, Owner, Created, Resolved, Duration Days |
| EV159 | Jira Change Retention | `Jira_Change_Retention` | Ticket, Summary, Status, Type, Created, Resolved |
| EV160 | Jira Baseline Exceptions | `Jira_Baseline_Exceptions` | Ticket, Summary, Status, Owner, Config Rule, Created, Resolved |
| EV161 | Jira Allowlist Review | `Jira_Allowlist_Review` | Ticket, Summary, Status, Reviewer, Created, Resolved, Days Since Created |
| EV162 | Jira CP Update Trigger | `Jira_CP_Update_Trigger` | Ticket, Summary, Status, Trigger, Created, Resolved |
| EV163 | Jira CP Test POAM | `Jira_CP_Test_POAM` | Ticket, Summary, Status, Owner, Due Date, Created, Resolved |
| EV164 | Jira DR Test Results | `Jira_DR_Test_Results` | Ticket, Summary, Test Date, RTO Target Hours, RTO Actual Hours, RPO Target Hours, RPO Actual Hours, Reviewer |
| EV165 | Jira IR CP Coordination | `Jira_IR_CP_Coordination` | Ticket, Summary, Status, Created, Resolved, Duration Hours |
| EV166 | Jira IR Lessons Learned Closure | `Jira_IR_Lessons_Learned_Closure` | Ticket, Summary, Status, Reviewer, Created, Resolved |
| EV167 | Jira IR Severity vs Rigor | `Jira_IR_Severity_vs_Rigor` | Ticket, Summary, Priority, Status, Investigator, Created, Resolved, Duration Hours |
| EV168 | Jira IR External Reporting SLA | `Jira_IR_External_Reporting_SLA` | Ticket, Summary, Status, Internal Report Time, External Notify Time, Hours To Notify, SLA Met (72hr) |
| EV169 | Jira Special Protection Approvals | `Jira_Special_Protection_Approvals` | Ticket, Summary, Status, Requestor, Approver, Created, Resolved |
| EV170 | Jira Data Reassignment | `Jira_Data_Reassignment` | Ticket, Summary, Status, Original Owner, Reassigned To, Created, Resolved |
| EV171 | Jira Transfer Notifications | `Jira_Transfer_Notifications` | Ticket, Summary, Status, User, Effective Date, Created, Hours Before Effective |
| EV172 | Jira Sanctions ISSO Notify | `Jira_Sanctions_ISSO_Notify` | Ticket, Summary, Status, Reporter, ISSO Notified, Hours To Notify, SLA Met (24hr) |
| EV173 | Jira Firewall Exception Duration | `Jira_Firewall_Exception_Duration` | Ticket, Summary, Status, Requestor, Approver, Created, Expiration Date, Days Active |
| EV174 | Jira Malware False Positive | `Jira_Malware_False_Positive` | Ticket, Summary, Status, Reporter, Assignee, Created, Resolved |
| EV175 | Jira Patch Test Records | `Jira_Patch_Test_Records` | Ticket, Summary, Status, Patch ID, Test Result, Tested By, Created, Resolved |
| EV176 | Jira Remote Maintenance Approvals | `Jira_Remote_Maintenance_Approvals` | Ticket, Summary, Status, Requestor, Approver, Session Start, Session End, Duration Hours |
| EV177 | Jira SW License Review | `Jira_SW_License_Review` | Ticket, Summary, Status, Software Name, License Type, Reviewer, Created, Resolved |
| EV196 | Jira Projects | `Jira_Projects` | Project ID, Key, Name, Type, Style, Lead Account ID, Lead Name |
| EV197 | Jira Issues | `Jira_Issues` | Issue Key, Summary, Type, Status, Priority, Assignee, Reporter, Created, Updated, Resolved |

### Source Control — GitHub

| ID | Evidence | Filename Prefix | Key Columns |
|----|----------|-----------------|--------------|
| EV203 | GitHub Org Members | `Github_Org_Members` | Login, User ID, Role, Site Admin, 2FA Disabled |
| EV204 | GitHub Teams | `Github_Teams` | Team ID, Slug, Name, Privacy, Permission, Description |
| EV205 | GitHub Team Members | `Github_Team_Members` | Team Slug, Team Name, Member Login, Member ID |
| EV206 | GitHub Org Security Settings | `Github_Org_Security_Settings` | Org Login, Two-Factor Requirement Enabled, Default Repository Permission, Members Can Create Repositories, Members Can Create Private Repositories |
| EV207 | GitHub Repositories | `Github_Repositories` | Repo ID, Name, Full Name, Visibility, Private, Default Branch, Archived, Created At, Pushed At |
| EV208 | GitHub Branch Protection | `Github_Branch_Protection` | Repository, Branch, Protected, Enforce Admins, Required Approving Review Count, Require Code Owner Reviews, Required Status Checks Strict, Allow Force Pushes |
| EV209 | GitHub Org Audit Log | `Github_Org_Audit_Log` | Action, Actor, User, Org, Created At, Document ID |
| EV210 | GitHub Dependabot Alerts | `Github_Dependabot_Alerts` | Repository, Alert Number, State, Package Ecosystem, Package Name, Severity, GHSA ID, CVE ID, Summary, Created At, Updated At |
| EV211 | GitHub Secret Scanning Alerts | `Github_Secret_Scanning_Alerts` | Repository, Alert Number, State, Secret Type, Secret Type Display Name, Resolution, Push Protection Bypassed, Created At |
| EV212 | GitHub Code Scanning Alerts | `Github_Code_Scanning_Alerts` | Repository, Alert Number, State, Rule ID, Severity, Security Severity Level, Description, Created At |

### Vulnerability Management — Tenable

| # | Name | Filename Prefix | Columns |
|---|------|----------------|---------|
| EV198 | Tenable Assets | `Tenable_Assets` | Asset ID, Hostname, FQDNs, IPv4 Addresses, IPv6 Addresses, MAC Addresses, Operating System, Agent Name, Network Name, Tracking Method, Has Agent, Is Licensed, Exposure Score, Sources, Tags, First Seen, Last Seen, Created At, Updated At |
| EV199 | Tenable Vulnerability Findings | `Tenable_Vulnerability_Findings` | Asset ID, Hostname, FQDN, IPv4, IPv6, OS, Device Type, Plugin ID, Plugin Name, Family, Synopsis, Description, Solution, CVEs, CPEs, Has Patch, Severity, Severity ID, Risk Factor, CVSS Base Score, CVSS Vector, CVSS3 Base Score, CVSS3 Vector, VPR Score, Port, Protocol, Service, Scan UUID, Scan Started At, Scan Completed At, State, First Found, Last Found, Last Fixed, Source |
| EV200 | Tenable Compliance Findings | `Tenable_Compliance_Findings` | Asset ID, Asset Hostname, Asset FQDN, Asset IPv4, Check ID, Check Name, Check Info, Status, Expected Value, Actual Value, Policy Name, Audit File, References, First Seen, Last Seen |
| EV201 | Tenable PCI ASV Compliance | `Tenable_PCI_ASV_Compliance` | Asset ID, Hostname, IPv4, Check Name, Status, Policy, Reference, First Found, Last Found |
| EV202 | Tenable Web App Scanning | `Tenable_WAS_Findings` | Finding ID, State, First Found, Last Found, URL, HTTP Method, Input Type, Input Name, Plugin ID, Plugin Name, Risk Factor, Synopsis, Description, Solution, CVEs, Severity, Severity ID, CVSS Base Score, CVSS3 Base Score, VPR Score, Scan ID, Scan Started At, Scan Completed At |

### Detection & Response — Elastic

| # | Name | Filename Prefix | Columns |
|---|------|----------------|---------|
| EV203 | Elastic Detection Rules | `Elastic_Detection_Rules` | Rule ID, Rule UUID, Rule Name, Type, Enabled, Severity, Risk Score, Interval, Index Patterns, Tags, Author, Max Signals, False Positives, References, Created At, Updated At |
| EV204 | Elastic Exception List Items | `Elastic_Exception_List_Items` | List ID, Item ID, Name, Description, Type, Entry Count, Tags, Created At, Created By, Updated At |
| EV205 | Elastic Security Alerts | `Elastic_Security_Alerts` | Alert ID, Rule Name, Rule UUID, Severity, Risk Score, Workflow Status, Host Name, User Name, Timestamp, Reason |
| EV206 | Elastic Security Cases | `Elastic_Security_Cases` | Case ID, Title, Status, Severity, Tags, Total Alerts, Created At, Created By, Updated At |
| EV207 | Elastic Alerting Connectors | `Elastic_Alerting_Connectors` | Connector ID, Name, Type, Preconfigured, Deprecated, Missing Secrets, Referenced By Count |
| EV208 | Elastic Security Users | `Elastic_Security_Users` | Username, Full Name, Email, Enabled, Roles |
| EV209 | Elastic Security Roles | `Elastic_Security_Roles` | Role Name, Cluster Privileges, Index Patterns, Index Privileges, Application Privilege Count |
| EV210 | Elastic Fleet Agents | `Elastic_Fleet_Agents` | Agent ID, Policy ID, Policy Revision, Active, Status, Last Checkin Status, Agent Version, Hostname, Enrolled At, Last Checkin |
| EV211 | Elastic File Integrity Monitoring Events | `Elastic_File_Integrity_Monitoring_Events` | Event ID, File Path, Event Action, File Hash SHA256, Host Name, User Name, Timestamp |
| EV212 | Elastic Index Lifecycle Management Policies | `Elastic_ILM_Policies` | Policy Name, Modified Date, Has Hot Phase, Has Warm Phase, Has Cold Phase, Has Frozen Phase, Has Delete Phase, Delete Min Age (Retention Period) |

### Certificates & PKI

| # | Name | Filename Prefix | Columns |
|---|------|----------------|---------|
| EV20 | Certificate Manager Certificates | `Certificate_Manager_Certificates` | Certificate ARN, Domain Name, Expires, In Use By, Issued On, Issuer, Key Algorithm, Renewal Eligibility, Signature Algorithm, Status, Cert Type |
| EV178 | ACM Private CA | `ACM_PCA_Config` | CA ARN, Type, Status, Key Algorithm, Signing Algorithm, Subject CN, Created, Not Before, Not After, CRL Enabled, CRL S3 Bucket, CRL Expiration Days, OCSP Enabled, OCSP Custom CName, Usage Mode, Permissions Count |

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

### Compute — Containers

| # | Name | Filename Prefix | Columns |
|---|------|----------------|---------|
| EV51 | ECS Clusters | `ECS_Clusters` | Cluster Name, Status, Running Tasks, Container Insights Enabled |
| EV52 | EKS Clusters | `EKS_Clusters` | Cluster Name, Version, Endpoint Public Access, Logging Enabled |
| EV53 | ECR Repository Configuration | `ECR_Config` | Repository Name, Registry ID, URI, Image Tag Mutability, Scan On Push, Encryption Type, KMS Key, Has Lifecycle Policy |

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

### Encryption & Key Management

| # | Name | Filename Prefix | Columns |
|---|------|----------------|---------|
| EV63 | KMS Keys | `KMS_Keys` | Key ID, ARN, Key Manager, Key State, Rotation Enabled, Region |
| EV64 | KMS Key Policies | `KMS_KeyPolicies` | Key ID, Key ARN, Key State, Rotation Enabled, Key Usage, Policy Allows External Access |
| EV65 | KMS Key Configuration | `KMS_Key_Configuration` | Key ID, Key ARN, Enabled, Key Usage, Origin, Key State, Rotation Enabled, Key Policy |
| EV66 | Secrets Manager | `Secrets_Manager` | Secret Name, ARN, Rotation Enabled, Last Rotated, Region |
| EV67 | Secrets Manager Resource Policies | `Secrets_Manager_Policies` | Secret Name, Secret ARN, KMS Key ID, Rotation Enabled, Rotation Interval (days), Last Rotated, Has Resource Policy |

### Messaging & Events

| # | Name | Filename Prefix | Columns |
|---|------|----------------|---------|
| EV68 | SNS Topic Subscribers | `SNS_Topic_Subscribers` | Subscription ID, SNS Topic Name, SNS Topic ARN, Region |
| EV69 | SNS Topic Policies | `SNS_Topic_Config` | Topic ARN, Display Name, Subscriptions Confirmed, Subscriptions Pending, KMS Key ID, Has Policy |
| EV70 | EventBridge Rules | `EventBridge_Rules_Config` | Rule Name, Event Bus, State, Schedule / Event Pattern, Targets |
| EV71 | EventBridge Rules for Changes | `Change_Event_Rules` | Rule Name, Event Bus, State, Event Pattern, Targets *(event-pattern rules only)* |

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
| EV126 | Transit Gateways & VPC Peering | `TransitGateway_VPCPeering_Config` | Kind, ID, Name, State, Owner Account, Peer Account, Peer VPC, Peer Region, Local VPC / Subnets, Association, Default Route Table, Notes |
| EV127 | Session Timeouts (ELB / Client VPN / SSM) | `Session_Timeout_Config` | Source, Resource ID, Resource Name, Setting, Value, Region |
| EV128 | Network Firewall Fail-Closed Config | `NetworkFirewall_FailClosed_Config` | Firewall Name, Firewall ARN, Policy ARN, Stream Exception Policy, Stateful Default Actions, Region |
| EV179 | AWS Client VPN | `ClientVPN_Config` | Endpoint ID, Description, Status, Client CIDR, Server Cert ARN, Authentication Types, Connection Log Enabled, Connection Log Group, Split Tunnel, Transport Protocol, DNS Servers, Self-Service Portal, Session Timeout Hours, Routes, Authorization Rules, Active Connections |
| EV180 | AWS Network Firewall | `NetworkFirewall_Config` | Firewall Name, Firewall ARN, VPC ID, Subnet IDs, Policy ARN, Policy Name, Stateless Default Actions, Stateless Fragment Actions, Stateful Rule Groups, Delete Protection, Subnet Change Protection, Policy Change Protection, Logging Flow Dest, Logging Alert Dest |
| EV181 | Route53 DNSSEC | `Route53_DNSSEC` | Zone ID, Zone Name, Private Zone, Signing Status, Status Message, KSK Count, KSK Names |

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
| EV132 | GuardDuty Runtime Coverage | `GuardDuty_Runtime_Coverage` | Detector ID, Resource Type, Resource ID, Coverage Status, Issue, Updated At, Region |
| EV133 | GuardDuty Malware Scan History | `GuardDuty_Malware_Scan_History` | Detector ID, Scan ID, Scan Type, Scan Status, Scan Start, Scan End, Total GB Scanned, Threats Found, Region |
| EV134 | AMI Default-Credential Scan | `AMI_Default_Credential_Scan` | Source, Resource ID, Finding Title, Compliance Status, Severity, First Observed, Region |
| EV182 | GuardDuty Full Configuration | `GuardDuty_Full_Config` | Detector ID, Status, Finding Publishing Frequency, S3 Logs, EKS Audit Logs, Malware Protection, Created At |
| EV183 | Inspector SBOM Export | `Inspector_SBOM_Export` | Report ID, Status, Format, S3 Bucket, S3 Key, Local Path, Error Message |
| EV184 | AWS Shield | `Shield_Config` | Record Type, Identifier, Detail Key, Detail Value |

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
| EV129 | SSM Application Allowlist | `SSM_Application_Allowlist` | Association ID, Association Name, Document Name, Targets, Schedule, Last Execution Date, Status, Detailed Status, Region |
| EV130 | SSM Automation Response Runbooks | `SSM_Automation_Response_Runbooks` | Document Name, Owner, Document Type, Document Format, Schema Version, Target Type, Tags, Created Date, Region |
| EV185 | SSM Session Manager Logs | `SSM_Sessions` | Session ID, Target, Owner, Document, Start, End, Status, Reason, Details |
| EV186 | SSM Software Inventory | `SSM_Software_Inventory` | Instance ID, Application Name, Version, Publisher, Architecture, Install Time, Package ID |

### Backup

| # | Name | Filename Prefix | Columns |
|---|------|----------------|---------|
| EV122 | AWS Backup Plans | `Backup_Plans_Config` | Plan ID, Plan Name, Version ID, Rules Count, Rules Summary |
| EV123 | Backup Vault Configuration | `Backup_Vault_Config` | Vault Name, Vault ARN, Encryption Key ARN, Recovery Points, Has Access Policy |
| EV131 | Documentation Repository Backup Config | `Doc_Repo_Backup_Config` | Kind, Name / ARN, Region, Versioning, Replication, Vault Recovery Points, Notes |

### Tagging & Inventory

| # | Name | Filename Prefix | Columns |
|---|------|----------------|---------|
| EV124 | Resource Tagging Configuration | `Resource_Tagging_Config` | Resource ARN, Resource Type, Owner, Environment, Data Classification, All Tags |

### Account & Service Limits

| # | Name | Filename Prefix | Columns |
|---|------|----------------|---------|
| EV187 | Service Quotas | `ServiceQuotas` | Service Code, Quota Code, Quota Name, Value, Unit, Adjustable, Global Quota, Source |
| EV188 | License Manager | `LicenseManager_Config` | Config ARN, Name, Description, License Count, License Count Hard Limit, License Counting Type, Status, Consumed Licenses, Owner Account |

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
| AWS collectors | 144 |
| Okta collectors | 24 |
| Jira collectors | 28 |
| Tenable collectors | 5 |
| Elastic collectors | 10 |
| Jamf collectors | 9 |
| GitHub collectors | 10 |
| **Total evidence collectors** | **220** |
| Asset Inventory asset types (Inventory feature) | 8 |

Counts are the number of distinct collector keys registered in each provider's `factory.rs`. AWS split by output type: 4 JSON (time-windowed) + 140 CSV.

### AWS Services Covered

Access Analyzer · ACM · API Gateway · Auto Scaling · Backup · CloudFormation ·
CloudFront · CloudTrail · CloudWatch · CloudWatch Logs · Config · DynamoDB ·
EBS · EC2 · ECR · ECS · EFS · EKS · ElastiCache · ELB/ALB/NLB · EventBridge ·
GuardDuty · IAM · Inspector2 · KMS · Lambda · Macie · Organizations ·
RDS · Route53 · Route53 Resolver · S3 · Secrets Manager · Security Hub ·
SNS · SSM · VPC · WAF / WAFv2
