pub mod ui;

use std::collections::HashSet;
use std::io;

use anyhow::Result;
use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::backend::CrosstermBackend;
use ratatui::Terminal;
use tokio::sync::mpsc;

use crate::app_config::{self, Account};

// ---------------------------------------------------------------------------
// Progress events sent from collector tasks → TUI
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub enum Progress {
    /// Signals the start of collection for a new account (multi-account mode).
    AccountStarted { name: String, index: usize, total: usize, collectors: Vec<String> },
    /// Signals that collection for an account has finished.
    AccountFinished { name: String },
    Started { collector: String },
    Done { collector: String, count: usize },
    Error { collector: String, message: String },
    /// Sent once all collectors finish; carries the list of written file paths.
    Finished { files: Vec<String> },
}

// ---------------------------------------------------------------------------
// Wizard screens
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
pub enum Screen {
    Welcome,
    SelectAccount,   // shown when TOML accounts are configured
    SelectProfile,   // legacy: pick from ~/.aws/config profiles
    SelectRegion,    // legacy: pick region
    SetDates,
    SelectCollectors,
    SetOptions,
    Confirm,
    /// Shown while building AWS SDK clients before collection starts.
    Preparing,
    Running,
    Results,
}

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
            let c = self.value[..self.cursor]
                .chars()
                .last()
                .unwrap();
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

// ---------------------------------------------------------------------------
// Main App state
// ---------------------------------------------------------------------------

pub struct App {
    pub screen: Screen,

    // TOML-configured accounts (empty = legacy flow)
    pub accounts: Vec<Account>,
    pub account_cursor: usize,
    pub selected_accounts: HashSet<usize>,

    // Multi-account progress tracking
    pub current_account_label: Option<String>,
    pub current_account_index: usize,
    pub total_account_count: usize,

    // Profile selection (legacy flow or fallback)
    pub profiles: Vec<String>,
    pub profile_cursor: usize,

    // Region selection
    pub regions: Vec<&'static str>,
    pub region_cursor: usize,
    pub region_custom: TextInput,
    pub region_use_custom: bool,
    /// When true, collect evidence from every enabled AWS region (round-robin).
    pub all_regions: bool,

    // Date inputs (computed from time_frame_cursor, not typed by user)
    pub start_date: TextInput,
    pub end_date: TextInput,
    pub time_frame_cursor: usize, // 0 = 1 Month, 1 = 2 Months, … 11 = 12 Months

    // Collector selection (multi-select)
    pub collector_items: Vec<(&'static str, &'static str)>, // (key, label)
    pub collector_cursor: usize,
    pub collector_selected: HashSet<usize>,

    // Options
    pub output_dir: TextInput,
    pub filter_input: TextInput,
    pub include_raw: bool,
    pub options_field: usize, // 0 = output_dir, 1 = filter, 2 = include_raw

    // Running / results
    pub collector_statuses: Vec<CollectorStatus>,
    pub result_files: Vec<String>,   // paths of files written
    pub error_messages: Vec<(String, String)>,  // (collector_name, error_message)
    pub progress_rx: Option<mpsc::UnboundedReceiver<Progress>>,

    // Validation error shown at bottom of a screen
    pub error_msg: Option<String>,

    pub tick: u64,
    /// Tick value when collection finished (used to freeze the Duration display).
    pub finished_tick: Option<u64>,

    // Scrollable results
    pub result_scroll: usize,

    // Preparing screen state (set by main before entering the setup loop)
    pub prep_log: Vec<String>,
    pub prep_current: usize,   // 1-based index of account currently being set up
    pub prep_total: usize,     // total number of accounts being prepared
}

impl App {
    pub fn new(profiles: Vec<String>) -> Self {
        let config = app_config::load_config().unwrap_or_default();

        let collector_items = vec![
            // ── App Layer & DNS ── (0..6)
            ("api-gateway",        "API Gateway              (current state, CSV)"),
            ("cloudfront",         "CloudFront Distributions (current state, CSV)"),
            ("lambda-config",      "Lambda Configuration     (current state, CSV)"),
            ("lambda-permissions", "Lambda Permissions       (current state, CSV)"),
            ("route53-zones",      "Route53 Hosted Zones     (current state, CSV)"),
            ("route53-resolver",   "Route53 Resolver Rules   (current state, CSV)"),
            // ── Audit Trail ── (6..23)
            ("config-recorder",    "AWS Config Recorder      (current state, CSV)"),
            ("config-rules",       "AWS Config Rules         (current state, CSV)"),
            ("cfn-drift",          "CloudFormation Drift     (current state, CSV)"),
            ("cloudtrail",         "CloudTrail API           (last 90 days, JSON)"),
            ("ct-changes",         "CloudTrail Change Events (last 7 days, CSV)"),
            ("cloudtrail-config",  "CloudTrail Configuration (current state, CSV)"),
            ("ct-selectors",       "CloudTrail Evt Selectors (current state, CSV)"),
            ("ct-full-config",     "CloudTrail Full Config   (current state, CSV)"),
            ("ct-validation",      "CloudTrail Log Validation(current state, CSV)"),
            ("s3",                 "CloudTrail S3            (7 months, requires s3-bucket, JSON)"),
            ("ct-s3-policy",       "CloudTrail S3 Policy     (current state, CSV)"),
            ("config-compliance",  "Config Compliance History(all rules, CSV)"),
            ("config-history",     "Config Resource History  (current state, CSV)"),
            ("config-timeline",    "Config Resource Timeline (last 5 per resource, CSV)"),
            ("config-snapshot",    "Config Snapshot (PiT)    (point-in-time, CSV)"),
            ("ct-config-changes",  "CT Config Change Events  (last 90 days, CSV)"),
            ("ct-iam-changes",     "CT IAM Changes (Hi-Risk) (last 90 days, CSV)"),
            // ── Compute ── (23..37)
            ("asg",                "Auto Scaling Groups      (current state, CSV)"),
            ("ec2-detailed",       "EC2 Details (AMI/IMDS)   (current state, CSV)"),
            ("ec2-config",         "EC2 Instance Config      (current state, CSV)"),
            ("ec2-instances",      "EC2 Instances            (current state, CSV)"),
            ("launch-templates",   "EC2 Launch Templates     (current state, CSV)"),
            ("ssm-maint-windows",  "SSM Maintenance Windows  (current state, CSV)"),
            ("ssm-instances",      "SSM Managed Instances    (current state, CSV)"),
            ("ssm-params",         "SSM Parameter Store      (current state, CSV)"),
            ("ssm-baselines",      "SSM Patch Baselines      (current state, CSV)"),
            ("ssm-patches",        "SSM Patch Compliance     (current state, CSV)"),
            ("ssm-patch-detail",   "SSM Patch Detail         (per instance, CSV)"),
            ("ssm-patch-exec",     "SSM Patch Executions     (command history, CSV)"),
            ("ssm-patch-summary",  "SSM Patch Summary        (per instance, CSV)"),
            ("time-sync",          "Time Sync Config (SSM)   (current state, CSV)"),
            // ── Containers ── (37..41)
            ("ecr-scan",           "ECR Image Scan Findings  (current state, CSV)"),
            ("ecr-config",         "ECR Repo Config          (current state, CSV)"),
            ("ecs",                "ECS Clusters             (current state, CSV)"),
            ("eks",                "EKS Clusters             (current state, CSV)"),
            // ── Database & Backup ── (41..48)
            ("backup",             "AWS Backup API           (native backup jobs, JSON)"),
            ("backup-plans",       "AWS Backup Plans         (current state, CSV)"),
            ("backup-vaults",      "Backup Vault Config      (current state, CSV)"),
            ("rds-backup-config",  "RDS Backup Config        (current state, CSV)"),
            ("rds-inventory",      "RDS Inventory            (current state, CSV)"),
            ("rds",                "RDS Snapshots            (last 30 days, JSON)"),
            ("rds-snapshots",      "RDS Snapshots            (current state, CSV)"),
            // ── Encryption & Secrets ── (48..55)
            ("ebs-encryption",     "EBS Default Encryption   (current state, CSV)"),
            ("ebs-config",         "EBS Encryption Config    (current state, CSV)"),
            ("kms-config",         "KMS Key Config (Full)    (current state, CSV)"),
            ("kms-policies",       "KMS Key Policies         (current state, CSV)"),
            ("kms",                "KMS Keys                 (current state, CSV)"),
            ("secrets",            "Secrets Manager          (current state, CSV)"),
            ("secrets-policies",   "Secrets Manager Policies (current state, CSV)"),
            // ── Identity & Access ── (55..67)
            ("access-analyzer",    "IAM Access Analyzer      (current state, CSV)"),
            ("iam-access-keys",    "IAM Access Keys          (current state, CSV)"),
            ("iam-account-summary","IAM Account Summary      (current state, CSV)"),
            ("iam-certs",          "IAM Certificates         (current state, CSV)"),
            ("iam-password-policy","IAM Password Policy      (current state, CSV)"),
            ("iam-policies",       "IAM Policies             (current state, CSV)"),
            ("iam-role-policies",  "IAM Role Policies        (current state, CSV)"),
            ("iam-trusts",         "IAM Role Trust Policies  (current state, CSV)"),
            ("iam-roles",          "IAM Roles                (current state, CSV)"),
            ("iam-user-policies",  "IAM User Policies        (current state, CSV)"),
            ("iam-users",          "IAM Users                (current state, CSV)"),
            ("saml-providers",     "SAML IdP Config          (current state, CSV)"),
            // ── Monitoring & Events ── (67..77)
            ("cw-alarms",          "CloudWatch Alarms        (current state, CSV)"),
            ("cw-log-groups",      "CloudWatch Log Groups    (current state, CSV)"),
            ("cw-config-alarms",   "CW Alarms (All)          (current state, CSV)"),
            ("cw-log-config",      "CW Log Group Config      (current state, CSV)"),
            ("change-event-rules", "EventBridge Change Rules (event-pattern, CSV)"),
            ("eventbridge-rules",  "EventBridge Rules        (current state, CSV)"),
            ("metric-filters",     "Log Metric Filters/Alarms(current state, CSV)"),
            ("metric-filter-config","Metric Filter Config    (current state, CSV)"),
            ("sns-policies",       "SNS Topic Policies       (current state, CSV)"),
            ("sns",                "SNS Topic Subscribers    (current state, CSV)"),
            // ── Network ── (77..97)
            ("acm",                "ACM Certificates         (current state, CSV)"),
            ("alb-logs",           "ALB Access Log Config    (current state, CSV)"),
            ("igw",                "Internet Gateways        (current state, CSV)"),
            ("elb-full-config",    "Load Balancer Full Config(current state, CSV)"),
            ("elb-listeners",      "Load Balancer Listeners  (current state, CSV)"),
            ("elb",                "Load Balancers           (current state, CSV)"),
            ("nat-gateways",       "NAT Gateways             (current state, CSV)"),
            ("nacl",               "Network ACLs             (current state, CSV)"),
            ("public-resources",   "Publicly Exposed Res.    (current state, CSV)"),
            ("rt-config",          "Route Table Config       (current state, CSV)"),
            ("route-tables",       "Route Tables             (current state, CSV)"),
            ("sg-config",          "Security Group Config    (current state, CSV)"),
            ("security-groups",    "Security Groups          (current state, CSV)"),
            ("vpc-config",         "VPC Configuration        (current state, CSV)"),
            ("vpc-endpoints",      "VPC Endpoints            (current state, CSV)"),
            ("vpc-flow-logs",      "VPC Flow Logging         (current state, CSV)"),
            ("vpc",                "VPCs                     (current state, CSV)"),
            ("waf-config",         "WAF Full Config          (current state, CSV)"),
            ("waf-logging",        "WAF Logging Config       (current state, CSV)"),
            ("waf",                "WAF Regional Web ACLs    (current state, CSV)"),
            // ── Organization & Account ── (97..101)
            ("account-contacts",   "Account Alt. Contacts    (current state, CSV)"),
            ("org-config",         "AWS Org Config           (requires org master, CSV)"),
            ("scp",                "Org SCPs                 (requires org admin, CSV)"),
            ("resource-tags",      "Resource Tags            (current state, CSV)"),
            // ── Security Detection ── (101..113)
            ("guardduty-config",   "GuardDuty Config         (current state, CSV)"),
            ("guardduty",          "GuardDuty Findings       (current state, CSV)"),
            ("gd-full-config",     "GuardDuty Full Config    (current state, CSV)"),
            ("guardduty-rules",    "GuardDuty Suppression    (current state, CSV)"),
            ("inspector-history",  "Inspector Findings Hist. (if enabled, CSV)"),
            ("inspector-config",   "Inspector2 Config        (if enabled, CSV)"),
            ("inspector-ecr",      "Inspector2 ECR Findings  (if enabled, CSV)"),
            ("inspector",          "Inspector2 Findings      (if enabled, CSV)"),
            ("macie",              "Macie Findings           (if enabled, CSV)"),
            ("securityhub",        "Security Hub Findings    (current state, CSV)"),
            ("sh-config",          "SecurityHub Config       (current state, CSV)"),
            ("sh-standards",       "SecurityHub Standards    (current state, CSV)"),
            // ── Storage ── (113..126)
            ("dynamodb",           "DynamoDB Tables          (current state, CSV)"),
            ("ebs",                "EBS Volumes              (current state, CSV)"),
            ("efs",                "EFS File Systems         (current state, CSV)"),
            ("elasticache",        "ElastiCache Clusters     (current state, CSV)"),
            ("elasticache-global", "ElastiCache Global DS    (current state, CSV)"),
            ("s3-logging",         "S3 Bucket Access Logging (current state, CSV)"),
            ("s3-policies",        "S3 Bucket Policies       (current state, CSV)"),
            ("s3-bucket-policy",   "S3 Bucket Policy (Full)  (current state, CSV)"),
            ("s3-config",          "S3 Buckets Config        (current state, CSV)"),
            ("s3-data-events",     "S3 Data Events Config    (current state, CSV)"),
            ("s3-encryption",      "S3 Encryption Config     (current state, CSV)"),
            ("s3-logging-config",  "S3 Logging Config        (current state, CSV)"),
            ("s3-public-access",   "S3 Public Access Block   (current state, CSV)"),
        ];

        // --- Collector selection defaults ---
        let total = collector_items.len();
        let mut collector_selected = HashSet::new();

        let hardcoded_optins = ["s3", "elasticache-global", "scp", "macie",
                                "inspector", "inspector-config", "org-config"];

        if let Some(ref enable_list) = config.defaults.collectors.enable {
            // Exclusive: ONLY enable listed collectors
            for (i, (key, _)) in collector_items.iter().enumerate() {
                if enable_list.iter().any(|k| k == key) {
                    collector_selected.insert(i);
                }
            }
        } else {
            // Start with all enabled
            for i in 0..total {
                collector_selected.insert(i);
            }
            // Remove hardcoded opt-ins
            for (i, (key, _)) in collector_items.iter().enumerate() {
                if hardcoded_optins.contains(key) {
                    collector_selected.remove(&i);
                }
            }
            // Apply config disable list
            if let Some(ref disable_list) = config.defaults.collectors.disable {
                for (i, (key, _)) in collector_items.iter().enumerate() {
                    if disable_list.iter().any(|k| k == key) {
                        collector_selected.remove(&i);
                    }
                }
            }
            // Apply config enable_extra list
            if let Some(ref extra) = config.defaults.collectors.enable_extra {
                for (i, (key, _)) in collector_items.iter().enumerate() {
                    if extra.iter().any(|k| k == key) {
                        collector_selected.insert(i);
                    }
                }
            }
        }

        // --- Profile cursor ---
        let profile_cursor = if let Some(ref needle) = config.defaults.profile_contains {
            profiles
                .iter()
                .position(|p| p.contains(needle.as_str()))
                .unwrap_or(0)
        } else {
            profiles
                .iter()
                .position(|p| p.contains("Prod"))
                .unwrap_or(0)
        };

        // --- Regions ---
        let regions = vec![
            "us-east-1",
            "us-east-2",
            "us-west-1",
            "us-west-2",
            "eu-west-1",
            "eu-central-1",
            "ap-southeast-1",
            "ap-northeast-1",
        ];

        let region_cursor = if let Some(ref default_region) = config.defaults.region {
            regions
                .iter()
                .position(|r| *r == default_region.as_str())
                .unwrap_or(0)
        } else {
            0
        };

        // --- Time frame cursor (default: derived from start_date_offset_days, else 2 = 3 months) ---
        let time_frame_cursor = if let Some(days) = config.defaults.start_date_offset_days {
            // Convert days to nearest whole month (1–12), clamp to 0-based index
            let months = ((days as f32) / 30.0).round() as usize;
            months.saturating_sub(1).min(11)
        } else {
            2 // default: 3 months
        };

        let include_raw = config.defaults.include_raw.unwrap_or(false);

        Self {
            screen: Screen::Welcome,
            accounts: config.account.clone(),
            account_cursor: 0,
            selected_accounts: HashSet::new(),
            current_account_label: None,
            current_account_index: 0,
            total_account_count: 0,
            profiles,
            profile_cursor,
            regions,
            region_cursor,
            region_custom: TextInput::default(),
            region_use_custom: false,
            all_regions: false,
            start_date: TextInput::new(
                &(chrono::Utc::now().date_naive()
                    - chrono::Months::new((time_frame_cursor as u32) + 1))
                    .format("%Y-%m-%d").to_string(),
            ),
            end_date: TextInput::new(
                &chrono::Utc::now().format("%Y-%m-%d").to_string(),
            ),
            time_frame_cursor,
            collector_items,
            collector_cursor: 0,
            collector_selected,
            output_dir: TextInput::new(
                config
                    .defaults
                    .output_dir
                    .as_deref()
                    .unwrap_or("."),
            ),
            filter_input: TextInput::default(),
            include_raw,
            options_field: 0,
            collector_statuses: vec![],
            result_files: vec![],
            error_messages: vec![],
            progress_rx: None,
            error_msg: None,
            tick: 0,
            finished_tick: None,
            result_scroll: 0,
            prep_log: Vec::new(),
            prep_current: 0,
            prep_total: 0,
        }
    }

    // ------------------------------------------------------------------
    // Derived values used by main.rs to kick off collection
    // ------------------------------------------------------------------

    pub fn selected_profile(&self) -> &str {
        self.profiles
            .get(self.profile_cursor)
            .map(|s| s.as_str())
            .unwrap_or("")
    }

    pub fn selected_region(&self) -> String {
        if self.region_use_custom {
            self.region_custom.value.clone()
        } else {
            self.regions
                .get(self.region_cursor)
                .map(|s| s.to_string())
                .unwrap_or_else(|| "us-east-1".to_string())
        }
    }

    pub fn selected_collectors(&self) -> Vec<String> {
        self.collector_selected
            .iter()
            .filter_map(|&i| self.collector_items.get(i).map(|(k, _)| k.to_string()))
            .collect()
    }

    /// True if TOML accounts are configured (multi-account flow).
    pub fn has_accounts(&self) -> bool {
        !self.accounts.is_empty()
    }

    /// Returns sorted list of selected account indices.
    pub fn selected_account_indices(&self) -> Vec<usize> {
        let mut sorted: Vec<usize> = self.selected_accounts.iter().copied().collect();
        sorted.sort();
        sorted
    }

    /// Compute per-account settings without mutating shared App state.
    /// Returns (profile, region, output_dir, collector_keys).
    pub fn resolve_account_settings(&self, index: usize) -> (String, String, Option<String>, Vec<String>) {
        let acct = &self.accounts[index];

        let profile = acct.profile.clone();
        let region = acct.region.clone().unwrap_or_else(|| {
            if self.region_use_custom {
                self.region_custom.value.clone()
            } else {
                self.regions.get(self.region_cursor)
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| "us-east-1".to_string())
            }
        });
        let output_dir = acct.output_dir.clone();

        // Start from the current global collector selection and apply per-account overrides.
        let mut selected = self.collector_selected.clone();
        if let Some(ref enable_list) = acct.collectors.enable {
            selected.clear();
            for (i, (key, _)) in self.collector_items.iter().enumerate() {
                if enable_list.iter().any(|k| k == key) {
                    selected.insert(i);
                }
            }
        } else {
            if let Some(ref disable_list) = acct.collectors.disable {
                for (i, (key, _)) in self.collector_items.iter().enumerate() {
                    if disable_list.iter().any(|k| k == key) {
                        selected.remove(&i);
                    }
                }
            }
            if let Some(ref extra) = acct.collectors.enable_extra {
                for (i, (key, _)) in self.collector_items.iter().enumerate() {
                    if extra.iter().any(|k| k == key) {
                        selected.insert(i);
                    }
                }
            }
        }

        let collector_keys: Vec<String> = selected
            .iter()
            .filter_map(|&i| self.collector_items.get(i).map(|(k, _)| k.to_string()))
            .collect();

        (profile, region, output_dir, collector_keys)
    }

    // ------------------------------------------------------------------
    // Time frame helpers
    // ------------------------------------------------------------------

    pub fn time_frame_months(&self) -> u32 {
        (self.time_frame_cursor as u32) + 1
    }

    pub fn apply_time_frame(&mut self) {
        let today = chrono::Utc::now().date_naive();
        let start = today - chrono::Months::new(self.time_frame_months());
        self.start_date = TextInput::new(&start.format("%Y-%m-%d").to_string());
        self.end_date = TextInput::new(&today.format("%Y-%m-%d").to_string());
    }

    // Navigation helpers
    // ------------------------------------------------------------------

    pub fn next_screen(&mut self) {
        self.error_msg = None;
        self.screen = match self.screen {
            Screen::Welcome => {
                if self.has_accounts() {
                    Screen::SelectAccount
                } else {
                    Screen::SelectProfile
                }
            }
            Screen::SelectAccount   => Screen::SetDates,
            Screen::SelectProfile   => Screen::SelectRegion,
            Screen::SelectRegion    => Screen::SetDates,
            Screen::SetDates        => Screen::SelectCollectors,
            Screen::SelectCollectors => Screen::SetOptions,
            Screen::SetOptions      => Screen::Confirm,
            Screen::Confirm         => Screen::Running,
            Screen::Preparing       => Screen::Running,
            Screen::Running         => Screen::Results,
            Screen::Results         => Screen::Results,
        };
    }

    pub fn prev_screen(&mut self) {
        self.error_msg = None;
        self.screen = match self.screen {
            Screen::SelectAccount   => Screen::Welcome,
            Screen::SelectProfile => {
                if self.has_accounts() {
                    Screen::SelectAccount
                } else {
                    Screen::Welcome
                }
            }
            Screen::SelectRegion    => Screen::SelectProfile,
            Screen::SetDates => {
                if self.has_accounts() {
                    Screen::SelectAccount
                } else {
                    Screen::SelectRegion
                }
            }
            Screen::SelectCollectors => Screen::SetDates,
            Screen::SetOptions      => Screen::SelectCollectors,
            Screen::Confirm         => Screen::SetOptions,
            _ => return,
        };
    }

    pub fn validate_current(&mut self) -> bool {
        match self.screen {
            Screen::SelectAccount => {
                if self.selected_accounts.is_empty() {
                    self.error_msg = Some("Select at least one account (Space to toggle)".into());
                    return false;
                }
                true
            }
            Screen::SelectProfile => {
                if self.profiles.is_empty() {
                    self.error_msg = Some("No AWS profiles found in ~/.aws/config".into());
                    return false;
                }
                true
            }
            Screen::SetDates => {
                self.apply_time_frame();
                true
            }
            Screen::SelectCollectors => {
                if self.collector_selected.is_empty() {
                    self.error_msg = Some("Select at least one collector (Space to toggle)".into());
                    return false;
                }
                true
            }
            _ => true,
        }
    }

    /// Drain any pending progress messages from the background task.
    pub fn poll_progress(&mut self) {
        if let Some(rx) = &mut self.progress_rx {
            while let Ok(msg) = rx.try_recv() {
                match msg {
                    Progress::AccountStarted { name, index, total, collectors } => {
                        self.current_account_label = Some(name);
                        self.current_account_index = index;
                        self.total_account_count = total;
                        self.collector_statuses = collectors
                            .into_iter()
                            .map(|n| CollectorStatus { name: n, state: CollectorState::Waiting })
                            .collect();
                    }
                    Progress::AccountFinished { .. } => {
                        // Nothing to do here; the next AccountStarted or
                        // Finished will drive the UI forward.
                    }
                    Progress::Started { collector } => {
                        if let Some(s) = self
                            .collector_statuses
                            .iter_mut()
                            .find(|s| s.name == collector)
                        {
                            s.state = CollectorState::Running;
                        }
                    }
                    Progress::Done { collector, count } => {
                        if let Some(s) = self
                            .collector_statuses
                            .iter_mut()
                            .find(|s| s.name == collector)
                        {
                            s.state = CollectorState::Done(count);
                        }
                    }
                    Progress::Error { collector, message } => {
                        self.error_messages.push((collector.clone(), message.clone()));
                        if let Some(s) = self
                            .collector_statuses
                            .iter_mut()
                            .find(|s| s.name == collector)
                        {
                            s.state = CollectorState::Failed(message);
                        }
                    }
                    Progress::Finished { files } => {
                        self.result_files = files;
                        self.finished_tick = Some(self.tick);
                        self.screen = Screen::Results;
                    }
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Read ~/.aws/config for available profiles
// ---------------------------------------------------------------------------

pub fn read_aws_profiles() -> Vec<String> {
    let path = dirs_next::home_dir()
        .map(|h| h.join(".aws").join("config"))
        .unwrap_or_default();

    let content = match std::fs::read_to_string(&path) {
        Ok(c) => c,
        Err(_) => return vec![],
    };

    content
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            if line.starts_with("[profile ") && line.ends_with(']') {
                Some(line[9..line.len() - 1].to_string())
            } else if line == "[default]" {
                Some("default".to_string())
            } else {
                None
            }
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Terminal setup / teardown
// ---------------------------------------------------------------------------

pub fn setup_terminal() -> Result<Terminal<CrosstermBackend<io::Stdout>>> {
    // Install a panic hook that restores the terminal before printing the panic message.
    // Without this, a panic leaves the terminal in raw/alternate-screen mode.
    let original_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let _ = disable_raw_mode();
        let _ = crossterm::execute!(io::stdout(), LeaveAlternateScreen);
        original_hook(info);
    }));

    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    Ok(Terminal::new(backend)?)
}

pub fn restore_terminal(terminal: &mut Terminal<CrosstermBackend<io::Stdout>>) -> Result<()> {
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Event loop
// ---------------------------------------------------------------------------

/// Returns the configured App when the user reaches the Confirm screen and
/// presses Enter, or None if they quit early.
pub fn run(mut app: App) -> Result<Option<App>> {
    let mut terminal = setup_terminal()?;

    let result = event_loop(&mut terminal, &mut app);

    restore_terminal(&mut terminal)?;
    result?;

    if app.screen == Screen::Running || app.screen == Screen::Results {
        Ok(Some(app))
    } else {
        Ok(None)
    }
}

fn event_loop(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    app: &mut App,
) -> Result<()> {
    loop {
        app.tick = app.tick.wrapping_add(1);

        // Drain progress channel if we're on the Running screen.
        if app.screen == Screen::Running {
            app.poll_progress();
        }

        terminal.draw(|f| ui::draw(f, app))?;

        // Non-blocking poll — 100 ms tick keeps the spinner animated.
        if event::poll(std::time::Duration::from_millis(100))? {
            if let Event::Key(key) = event::read()? {
                if key.kind != KeyEventKind::Press {
                    continue;
                }
                match handle_key(app, key.code, key.modifiers) {
                    Action::Quit => return Ok(()),
                    Action::StartCollection => return Ok(()),
                    Action::Continue => {}
                }
            }
        }

        if app.screen == Screen::Results {
            // Stay on results until user presses q / Esc
        }
    }
}

enum Action {
    Continue,
    Quit,
    StartCollection,
}

fn handle_key(app: &mut App, key: KeyCode, modifiers: KeyModifiers) -> Action {
    // Global quit
    if key == KeyCode::Char('q') && app.screen == Screen::Results {
        return Action::Quit;
    }

    match app.screen.clone() {
        Screen::Welcome => match key {
            KeyCode::Enter | KeyCode::Char(' ') => app.next_screen(),
            KeyCode::Char('q') | KeyCode::Esc => return Action::Quit,
            _ => {}
        },

        Screen::SelectAccount => match key {
            KeyCode::Up   => { if app.account_cursor > 0 { app.account_cursor -= 1; } }
            KeyCode::Down => {
                // accounts.len() entries + 1 "Other" option
                let max = app.accounts.len(); // "Other" is at index == len
                if app.account_cursor < max { app.account_cursor += 1; }
            }
            KeyCode::Char(' ') => {
                let i = app.account_cursor;
                if i < app.accounts.len() {
                    if app.selected_accounts.contains(&i) {
                        app.selected_accounts.remove(&i);
                    } else {
                        app.selected_accounts.insert(i);
                    }
                } else {
                    // "Other" → legacy flow
                    app.selected_accounts.clear();
                    app.screen = Screen::SelectProfile;
                }
            }
            KeyCode::Char('a') => {
                for i in 0..app.accounts.len() {
                    app.selected_accounts.insert(i);
                }
            }
            KeyCode::Char('d') => {
                app.selected_accounts.clear();
            }
            KeyCode::Enter => {
                if app.account_cursor == app.accounts.len() {
                    // "Other" → legacy flow
                    app.selected_accounts.clear();
                    app.screen = Screen::SelectProfile;
                } else {
                    // Auto-select cursor item if nothing toggled yet
                    if app.selected_accounts.is_empty() {
                        app.selected_accounts.insert(app.account_cursor);
                    }
                    if app.validate_current() { app.next_screen(); }
                }
            }
            KeyCode::Esc => app.prev_screen(),
            _ => {}
        },

        Screen::SelectProfile => match key {
            KeyCode::Up    => { if app.profile_cursor > 0 { app.profile_cursor -= 1; } }
            KeyCode::Down  => { if app.profile_cursor + 1 < app.profiles.len() { app.profile_cursor += 1; } }
            KeyCode::Enter => { if app.validate_current() { app.next_screen(); } }
            KeyCode::Esc   => app.prev_screen(),
            _ => {}
        },

        Screen::SelectRegion => match key {
            KeyCode::Up => {
                if app.region_use_custom {
                    app.region_use_custom = false;
                } else if app.region_cursor > 0 {
                    app.region_cursor -= 1;
                }
            }
            KeyCode::Down => {
                if !app.region_use_custom && app.region_cursor + 1 < app.regions.len() {
                    app.region_cursor += 1;
                } else {
                    app.region_use_custom = true;
                }
            }
            KeyCode::Char(c) if app.region_use_custom => app.region_custom.insert(c),
            KeyCode::Backspace if app.region_use_custom => app.region_custom.backspace(),
            KeyCode::Enter => { if app.validate_current() { app.next_screen(); } }
            KeyCode::Esc   => app.prev_screen(),
            _ => {}
        },

        Screen::SetDates => match key {
            KeyCode::Up   => { if app.time_frame_cursor > 0 { app.time_frame_cursor -= 1; } }
            KeyCode::Down => { if app.time_frame_cursor < 11 { app.time_frame_cursor += 1; } }
            KeyCode::Enter => { if app.validate_current() { app.next_screen(); } }
            KeyCode::Esc   => app.prev_screen(),
            _ => {}
        },

        Screen::SelectCollectors => match key {
            KeyCode::Up   => { if app.collector_cursor > 0 { app.collector_cursor -= 1; } }
            KeyCode::Down => { if app.collector_cursor + 1 < app.collector_items.len() { app.collector_cursor += 1; } }
            KeyCode::Char(' ') => {
                let i = app.collector_cursor;
                if app.collector_selected.contains(&i) {
                    app.collector_selected.remove(&i);
                } else {
                    app.collector_selected.insert(i);
                }
            }
            KeyCode::Char('a') => {
                for i in 0..app.collector_items.len() {
                    app.collector_selected.insert(i);
                }
            }
            KeyCode::Char('d') => {
                app.collector_selected.clear();
            }
            KeyCode::Enter => { if app.validate_current() { app.next_screen(); } }
            KeyCode::Esc   => app.prev_screen(),
            _ => {}
        },

        Screen::SetOptions => match key {
            // 3 fields: 0 = filter, 1 = include_raw toggle, 2 = all_regions toggle
            KeyCode::Tab => { app.options_field = (app.options_field + 1) % 3; }
            KeyCode::Char(' ') if app.options_field == 1 => {
                app.include_raw = !app.include_raw;
            }
            KeyCode::Char(' ') if app.options_field == 2 => {
                app.all_regions = !app.all_regions;
            }
            KeyCode::Char(c) if app.options_field == 0 => app.filter_input.insert(c),
            KeyCode::Backspace if app.options_field == 0 => app.filter_input.backspace(),
            KeyCode::Left  if app.options_field == 0 => app.filter_input.move_left(),
            KeyCode::Right if app.options_field == 0 => app.filter_input.move_right(),
            KeyCode::Enter => { if app.validate_current() { app.next_screen(); } }
            KeyCode::Esc   => app.prev_screen(),
            _ => {}
        },

        Screen::Confirm => match key {
            KeyCode::Enter => {
                app.next_screen(); // → Running
                return Action::StartCollection;
            }
            KeyCode::Esc => app.prev_screen(),
            _ => {}
        },

        Screen::Running => {
            // No navigation while running; collection drives screen transition.
        }

        Screen::Preparing => {
            // No key interaction during preparation.
        }

        Screen::Results => match key {
            KeyCode::Char('q') | KeyCode::Esc => return Action::Quit,
            _ => {}
        },
    }

    Action::Continue
}
