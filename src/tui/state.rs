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
    (114, "Storage"),
    (127, "Security Scanning"),
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
