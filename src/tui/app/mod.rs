mod methods;
mod nav;

use std::collections::HashSet;

use tokio::sync::mpsc;

use crate::app_config::{self, Account};
use crate::inventory_core::INVENTORY_ITEMS;
use crate::providers::CloudProvider;

use super::state::{
    CollectorFocus, CollectorStatus, Feature, PoamSummary, Progress, Screen, TextInput,
};
use crate::tui::collector_data::{AWS_REGIONS, COLLECTOR_ITEMS};

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
    pub current_region_label: Option<String>,

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
    pub collector_items: Vec<(&'static str, &'static str, CloudProvider)>, // (key, label, provider)
    pub collector_cursor: usize,
    pub collector_selected: HashSet<usize>,
    pub collector_category_cursor: usize,
    pub collector_focus: CollectorFocus,
    pub collector_search: TextInput,

    // Options
    pub output_dir: TextInput,
    pub filter_input: TextInput,
    pub include_raw: bool,
    pub options_field: usize, // 0=filter 1=include_raw 2=all_regions 3=zip 4=sign 5=skip_inventory_csv 6=region list
    pub options_region_cursor: usize,
    pub options_selected_regions: HashSet<usize>, // indices into self.regions

    // Options
    pub zip: bool,
    pub sign: bool,
    pub skip_inventory_csv: bool,
    pub skip_run_manifest: bool,
    pub skip_chain_of_custody: bool,

    // Running / results
    pub collector_statuses: Vec<CollectorStatus>,
    pub result_files: Vec<String>,  // paths of files written
    pub result_zip: Option<String>, // path to bundled zip (zip option)
    pub result_signing_manifest: Option<String>, // path to SIGNING-MANIFEST-*.json
    pub result_signing_key_path: Option<String>, // path to SIGNING-*.key
    pub error_messages: Vec<(String, String)>, // (collector_name, error_message)
    pub progress_rx: Option<mpsc::UnboundedReceiver<Progress>>,

    // Validation error shown at bottom of a screen
    pub error_msg: Option<String>,

    pub tick: u64,
    /// Tick value when collection finished (used to freeze the Duration display).
    pub finished_tick: Option<u64>,

    // Scrollable results
    pub result_scroll: usize,

    // Feature selection
    pub selected_feature: Feature,

    // POAM inputs/results
    pub poam_account_cursor: usize,
    pub poam_region_cursor: usize,
    pub poam_year: TextInput,
    pub poam_month_cursor: usize,
    pub poam_summary: Option<PoamSummary>,

    // Inventory asset-type selection (multi-select, Inventory flow only)
    pub inventory_items: Vec<(&'static str, &'static str)>, // (key, label)
    pub inventory_cursor: usize,
    pub inventory_selected: HashSet<usize>,

    // Preparing screen state (set by main before entering the setup loop)
    pub prep_log: Vec<String>,
    pub prep_current: usize, // 1-based index of account currently being set up
    pub prep_total: usize,   // total number of accounts being prepared
}

impl App {
    pub fn new(profiles: Vec<String>) -> Self {
        let config = app_config::load_config().unwrap_or_default();

        let collector_items = COLLECTOR_ITEMS.to_vec();

        // --- Collector selection defaults ---
        let total = collector_items.len();
        let mut collector_selected = HashSet::new();

        let hardcoded_optins = [
            "s3",
            "elasticache-global",
            "scp",
            "macie",
            "inspector",
            "inspector-config",
            "org-config",
        ];

        if let Some(ref enable_list) = config.defaults.collectors.enable {
            // Exclusive: ONLY enable listed collectors
            for (i, (key, _, _)) in collector_items.iter().enumerate() {
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
            for (i, (key, _, _)) in collector_items.iter().enumerate() {
                if hardcoded_optins.contains(key) {
                    collector_selected.remove(&i);
                }
            }
            // Apply config disable list
            if let Some(ref disable_list) = config.defaults.collectors.disable {
                for (i, (key, _, _)) in collector_items.iter().enumerate() {
                    if disable_list.iter().any(|k| k == key) {
                        collector_selected.remove(&i);
                    }
                }
            }
            // Apply config enable_extra list
            if let Some(ref extra) = config.defaults.collectors.enable_extra {
                for (i, (key, _, _)) in collector_items.iter().enumerate() {
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
        let regions = AWS_REGIONS.to_vec();

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
        let zip = config.defaults.zip.unwrap_or(false);
        let sign = config.defaults.sign.unwrap_or(false);

        Self {
            screen: Screen::Welcome,
            accounts: config.account.clone(),
            account_cursor: 0,
            selected_accounts: HashSet::new(),
            current_account_label: None,
            current_account_index: 0,
            total_account_count: 0,
            current_region_label: None,
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
                .format("%Y-%m-%d")
                .to_string(),
            ),
            end_date: TextInput::new(&chrono::Utc::now().format("%Y-%m-%d").to_string()),
            time_frame_cursor,
            collector_items,
            collector_cursor: 0,
            collector_selected,
            collector_category_cursor: 0,
            collector_focus: CollectorFocus::Categories,
            collector_search: TextInput::default(),
            output_dir: TextInput::new(config.defaults.output_dir.as_deref().unwrap_or(".")),
            filter_input: TextInput::default(),
            include_raw,
            zip,
            sign,
            skip_inventory_csv: false,
            skip_run_manifest: false,
            skip_chain_of_custody: false,
            options_field: 0,
            options_region_cursor: 0,
            options_selected_regions: HashSet::new(),
            collector_statuses: vec![],
            result_files: vec![],
            result_zip: None,
            result_signing_manifest: None,
            result_signing_key_path: None,
            error_messages: vec![],
            progress_rx: None,
            error_msg: None,
            tick: 0,
            finished_tick: None,
            result_scroll: 0,
            prep_log: Vec::new(),
            prep_current: 0,
            prep_total: 0,
            selected_feature: Feature::Collectors,
            poam_account_cursor: 0,
            poam_region_cursor: region_cursor,
            poam_year: TextInput::new(&chrono::Local::now().format("%Y").to_string()),
            poam_month_cursor: chrono::Local::now()
                .format("%m")
                .to_string()
                .parse::<usize>()
                .ok()
                .and_then(|m| m.checked_sub(1))
                .unwrap_or(0),
            poam_summary: None,
            inventory_items: INVENTORY_ITEMS.to_vec(),
            inventory_cursor: 0,
            inventory_selected: HashSet::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tui::state::COLLECTOR_CATEGORIES;

    fn make_app() -> App {
        App::new(vec![])
    }

    #[test]
    fn search_empty_matches_all_items() {
        let app = make_app();
        for i in 0..app.collector_items.len() {
            assert!(
                app.search_matches_item(i),
                "item {i} should match empty search"
            );
        }
    }

    #[test]
    fn search_matches_key_substring() {
        let mut app = make_app();
        app.collector_search.value = "iam".to_string();
        app.collector_search.cursor = 3;
        // "access-analyzer" label is "IAM Access Analyzer …" — matches via label
        assert!(app.search_matches_item(55));
        // "api-gateway" — neither key nor label contains "iam"
        assert!(!app.search_matches_item(0));
    }

    #[test]
    fn search_case_insensitive() {
        let mut app = make_app();
        app.collector_search.value = "IAM".to_string();
        app.collector_search.cursor = 3;
        assert!(app.search_matches_item(55));
    }

    #[test]
    fn search_matches_label_text() {
        let mut app = make_app();
        // "cloudtrail" appears in many keys/labels in the Audit Trail category
        app.collector_search.value = "cloudtrail".to_string();
        app.collector_search.cursor = 10;
        // index 9 is ("cloudtrail", "CloudTrail API …")
        assert!(app.search_matches_item(9));
        // index 0 is "api-gateway" — no "cloudtrail"
        assert!(!app.search_matches_item(0));
    }

    #[test]
    fn visible_categories_empty_search_returns_all() {
        let app = make_app();
        let visible = app.visible_categories();
        assert_eq!(visible.len(), COLLECTOR_CATEGORIES.len());
        assert_eq!(visible, (0..COLLECTOR_CATEGORIES.len()).collect::<Vec<_>>());
    }

    #[test]
    fn visible_categories_filters_to_matching_categories() {
        let mut app = make_app();
        app.collector_search.value = "iam".to_string();
        app.collector_search.cursor = 3;
        let visible = app.visible_categories();
        // "Identity & Access" (index 6) has IAM collectors — must be present
        assert!(visible.contains(&6));
        // "Audit Trail" (index 1) has "ct-iam-changes" — must be present
        assert!(visible.contains(&1));
        // "Containers" (index 3) has no IAM items — must be absent
        assert!(!visible.contains(&3));
        // "Database & Backup" (index 4) has no IAM items — must be absent
        assert!(!visible.contains(&4));
    }

    #[test]
    fn visible_items_empty_search_returns_full_category() {
        let app = make_app();
        let (start, end) = app.category_bounds(0);
        let visible = app.visible_items_in_category(0);
        assert_eq!(visible, (start..end).collect::<Vec<_>>());
    }

    #[test]
    fn visible_items_filters_within_category() {
        let mut app = make_app();
        app.collector_search.value = "iam".to_string();
        app.collector_search.cursor = 3;
        // Identity & Access category (index 6) — all items have "iam" in key or label
        let visible = app.visible_items_in_category(6);
        assert!(!visible.is_empty());
        for &i in &visible {
            assert!(app.search_matches_item(i), "item {i} should match 'iam'");
        }
        // Containers category (index 3) — no IAM items
        let visible_containers = app.visible_items_in_category(3);
        assert!(visible_containers.is_empty());
    }

    #[test]
    fn clamp_cursors_snaps_to_first_visible_category() {
        let mut app = make_app();
        // Force cursor to Containers (index 3), which has no IAM items
        app.collector_category_cursor = 3;
        app.collector_search.value = "iam".to_string();
        app.collector_search.cursor = 3;
        app.clamp_collector_cursors();
        let visible = app.visible_categories();
        assert!(
            visible.contains(&app.collector_category_cursor),
            "category_cursor should be in visible set after clamp"
        );
    }

    #[test]
    fn clamp_cursors_noop_on_empty_search() {
        let mut app = make_app();
        app.collector_category_cursor = 5;
        app.collector_cursor = 50;
        app.clamp_collector_cursors();
        // No-op when search is empty — all categories visible
        assert_eq!(app.collector_category_cursor, 5);
        assert_eq!(app.collector_cursor, 50);
    }
}
