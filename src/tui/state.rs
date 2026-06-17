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
        /// Optional endpoint label (e.g. "Tenable.io (FedRAMP) — https://fedcloud.tenable.com").
        /// Displayed in the Running-screen header in place of the region for
        /// providers that aren't region-scoped.
        endpoint_label: Option<String>,
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
    /// Sent when a collector failed in a known-benign way (e.g. service not enabled,
    /// account lacks permission, expected timeout). Displayed in the "Skipped" panel
    /// rather than the red "Errors" panel.
    Skipped {
        collector: String,
        reason: String,
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
    // shown after Feature::Collectors is chosen; before account selection
    ProviderSelection,
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
    /// Tenable-only: pick commercial cloud.tenable.com vs FedRAMP fedcloud.tenable.com.
    TenableEndpoint,
    ScanSelection, // Tenable-only: pick which scans to include
    /// Jira-only: pick which projects to scope Issues collection to.
    JiraProjectSelection,
    SetOptions,
    Confirm,
    /// Shown while building AWS SDK clients before collection starts.
    Preparing,
    Running,
    Results,
}

/// User-selected Tenable endpoint. Overrides per-account `tenable_url`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TenableEndpointChoice {
    #[default]
    Commercial,
    Fedramp,
}

impl TenableEndpointChoice {
    pub fn url(self) -> &'static str {
        match self {
            Self::Commercial => "https://cloud.tenable.com",
            Self::Fedramp => "https://fedcloud.tenable.com",
        }
    }
    pub fn label(self) -> &'static str {
        match self {
            Self::Commercial => "Commercial — Tenable.io (cloud.tenable.com)",
            Self::Fedramp => "FedRAMP — Tenable.io (fedcloud.tenable.com)",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Default)]
pub enum ScanTimeFilter {
    #[default]
    Recent, // last 30 days
    Past12Months, // last 365 days
    AllTime,      // no date restriction
}

// ---------------------------------------------------------------------------
// Collector categories (used by two-panel SelectCollectors screen)
// ---------------------------------------------------------------------------

pub const COLLECTOR_CATEGORIES: &[(usize, &str)] = &[
    (0, "App & Network Services"),
    (6, "Audit Trail"),
    (29, "Compute"),
    (46, "Containers"),
    (51, "Database & Backup"),
    (64, "Encryption & Secrets"),
    (72, "Identity & Access"),
    (91, "Monitoring & Events"),
    (106, "Network"),
    (132, "Organization & Account"),
    (136, "Security Detection"),
    (160, "Storage"),
    (175, "Vulnerability Scanning"),
    (180, "Identity Provider"),
    (187, "Issue Tracker"),
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
    Skipped(String),
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

#[derive(Debug, Clone)]
pub struct JiraProjectItem {
    pub key: String,
    pub name: String,
}
