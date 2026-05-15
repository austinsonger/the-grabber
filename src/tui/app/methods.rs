use crate::tui::state::{Feature, COLLECTOR_CATEGORIES};

use super::App;

impl App {
    pub fn selected_profile(&self) -> &str {
        self.profiles
            .get(self.profile_cursor)
            .map(|s| s.as_str())
            .unwrap_or("")
    }

    /// Returns the explicitly selected regions from the Options screen,
    /// in index order (preserving the geographic ordering from the list).
    /// Empty means "use the account's default single region".
    pub fn explicit_regions(&self) -> Vec<String> {
        let mut indices: Vec<usize> = self.options_selected_regions.iter().copied().collect();
        indices.sort_unstable();
        indices
            .iter()
            .filter_map(|&i| self.regions.get(i).map(|r| r.to_string()))
            .collect()
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

    pub fn poam_selected_region(&self) -> String {
        self.regions
            .get(self.poam_region_cursor)
            .map(|s| s.to_string())
            .unwrap_or_else(|| "us-east-1".to_string())
    }

    pub fn poam_month_name(&self) -> &'static str {
        const MONTHS: [&str; 12] = [
            "January",
            "February",
            "March",
            "April",
            "May",
            "June",
            "July",
            "August",
            "September",
            "October",
            "November",
            "December",
        ];
        MONTHS
            .get(self.poam_month_cursor)
            .copied()
            .unwrap_or("January")
    }

    pub fn poam_month_folder(&self) -> String {
        const FOLDERS: [&str; 12] = [
            "01-JAN", "02-FEB", "03-MAR", "04-APR", "05-MAY", "06-JUN", "07-JUL", "08-AUG",
            "09-SEP", "10-OCT", "11-NOV", "12-DEC",
        ];
        FOLDERS
            .get(self.poam_month_cursor)
            .copied()
            .unwrap_or("01-JAN")
            .to_string()
    }

    pub fn poam_year_value(&self) -> String {
        let trimmed = self.poam_year.value.trim();
        if trimmed.is_empty() {
            chrono::Local::now().format("%Y").to_string()
        } else {
            trimmed.to_string()
        }
    }

    /// Returns the evidence base directory for the selected POAM account,
    /// e.g. "evidence-output/federal/ops" or "evidence-output/security".
    pub fn poam_evidence_base(&self) -> String {
        if self.has_accounts() {
            self.accounts
                .get(self.poam_account_cursor)
                .and_then(|a| a.output_dir.as_deref())
                .unwrap_or("evidence-output/security")
                .trim_start_matches("./")
                .to_string()
        } else {
            "evidence-output/security".to_string()
        }
    }

    pub fn poam_evidence_path(&self) -> String {
        std::path::PathBuf::from(self.poam_evidence_base())
            .join(self.poam_selected_region())
            .join(self.poam_year_value())
            .join(self.poam_month_folder())
            .display()
            .to_string()
    }

    pub fn selected_collectors(&self) -> Vec<String> {
        self.collector_selected
            .iter()
            .filter_map(|&i| self.collector_items.get(i).map(|(k, _, _)| k.to_string()))
            .collect()
    }

    /// Return the (start, end) item indices for a given category.
    pub fn category_bounds(&self, cat_idx: usize) -> (usize, usize) {
        let start = COLLECTOR_CATEGORIES[cat_idx].0;
        let end = if cat_idx + 1 < COLLECTOR_CATEGORIES.len() {
            COLLECTOR_CATEGORIES[cat_idx + 1].0
        } else {
            self.collector_items.len()
        };
        (start, end)
    }

    /// Count selected items in a category.
    pub fn selected_in_category(&self, cat_idx: usize) -> usize {
        let (start, end) = self.category_bounds(cat_idx);
        (start..end)
            .filter(|i| self.collector_selected.contains(i))
            .count()
    }

    /// Select or deselect all items in a category.
    pub fn set_category_selection(&mut self, cat_idx: usize, selected: bool) {
        let (start, end) = self.category_bounds(cat_idx);
        for i in start..end {
            if selected {
                self.collector_selected.insert(i);
            } else {
                self.collector_selected.remove(&i);
            }
        }
    }

    /// Jump collector_cursor to the first item of a category.
    pub fn jump_to_category(&mut self, cat_idx: usize) {
        self.collector_category_cursor = cat_idx;
        let items = self.visible_items_in_category(cat_idx);
        if let Some(&first) = items.first() {
            self.collector_cursor = first;
        } else {
            let (start, _) = self.category_bounds(cat_idx);
            self.collector_cursor = start;
        }
    }

    /// True when `global_idx` passes both the provider filter and the current
    /// collector search filter.
    pub fn search_matches_item(&self, global_idx: usize) -> bool {
        let (key, label, provider) = &self.collector_items[global_idx];
        // Provider filter: only show collectors for the selected provider (Collectors feature only).
        if self.selected_feature == Feature::Collectors && *provider != self.selected_provider {
            return false;
        }
        // Search filter
        let term = self.collector_search.value.to_lowercase();
        if term.is_empty() {
            return true;
        }
        key.to_lowercase().contains(&term) || label.to_lowercase().contains(&term)
    }

    /// Returns raw indices into `self.accounts` matching `self.selected_provider`.
    /// Used by SelectAccount UI and event handler to show only provider-relevant accounts.
    pub fn provider_account_indices(&self) -> Vec<usize> {
        self.accounts
            .iter()
            .enumerate()
            .filter(|(_, a)| a.provider == self.selected_provider)
            .map(|(i, _)| i)
            .collect()
    }

    /// Returns indices of categories that contain at least one item matching the
    /// current search filter. Returns all category indices when search is empty.
    pub fn visible_categories(&self) -> Vec<usize> {
        (0..COLLECTOR_CATEGORIES.len())
            .filter(|&cat_idx| {
                let (start, end) = self.category_bounds(cat_idx);
                (start..end).any(|i| self.search_matches_item(i))
            })
            .collect()
    }

    /// Returns global item indices within `cat_idx` that pass the search filter.
    /// Returns all items in the category when search is empty.
    pub fn visible_items_in_category(&self, cat_idx: usize) -> Vec<usize> {
        let (start, end) = self.category_bounds(cat_idx);
        (start..end)
            .filter(|&i| self.search_matches_item(i))
            .collect()
    }

    /// After the search term changes, snaps `collector_category_cursor` to the
    /// first visible category (if the current one no longer matches) and snaps
    /// `collector_cursor` to the first visible item in that category.
    pub fn clamp_collector_cursors(&mut self) {
        let visible_cats = self.visible_categories();
        if visible_cats.is_empty() {
            return;
        }
        if !visible_cats.contains(&self.collector_category_cursor) {
            self.collector_category_cursor = visible_cats[0];
        }
        let visible_items = self.visible_items_in_category(self.collector_category_cursor);
        if visible_items.is_empty() {
            return;
        }
        if !visible_items.contains(&self.collector_cursor) {
            self.collector_cursor = visible_items[0];
        }
    }

    /// Returns the selected inventory asset-type keys in index order.
    pub fn selected_inventory_types(&self) -> Vec<String> {
        let mut indices: Vec<usize> = self.inventory_selected.iter().copied().collect();
        indices.sort_unstable();
        indices
            .iter()
            .filter_map(|&i| self.inventory_items.get(i).map(|(k, _)| k.to_string()))
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
    pub fn resolve_account_settings(
        &self,
        index: usize,
    ) -> (String, String, Option<String>, Vec<String>) {
        let acct = &self.accounts[index];

        let profile = acct.profile.clone().unwrap_or_default();
        let region = acct.region.clone().unwrap_or_else(|| {
            if self.region_use_custom {
                self.region_custom.value.clone()
            } else {
                self.regions
                    .get(self.region_cursor)
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| "us-east-1".to_string())
            }
        });
        let output_dir = acct.output_dir.clone();

        // Start from the current global collector selection and apply per-account overrides.
        let mut selected = self.collector_selected.clone();
        if let Some(ref enable_list) = acct.collectors.enable {
            selected.clear();
            for (i, (key, _, _)) in self.collector_items.iter().enumerate() {
                if enable_list.iter().any(|k| k == key) {
                    selected.insert(i);
                }
            }
        } else {
            if let Some(ref disable_list) = acct.collectors.disable {
                for (i, (key, _, _)) in self.collector_items.iter().enumerate() {
                    if disable_list.iter().any(|k| k == key) {
                        selected.remove(&i);
                    }
                }
            }
            if let Some(ref extra) = acct.collectors.enable_extra {
                for (i, (key, _, _)) in self.collector_items.iter().enumerate() {
                    if extra.iter().any(|k| k == key) {
                        selected.insert(i);
                    }
                }
            }
        }

        let collector_keys: Vec<String> = selected
            .iter()
            .filter_map(|&i| self.collector_items.get(i).map(|(k, _, _)| k.to_string()))
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

    /// Auto-select all TOML accounts that match `selected_provider`.
    /// Called when navigating past ProviderSelection for Tenable (which skips SelectAccount).
    pub fn auto_select_provider_accounts(&mut self) {
        self.selected_accounts.clear();
        for (i, acct) in self.accounts.iter().enumerate() {
            if acct.provider == self.selected_provider {
                self.selected_accounts.insert(i);
            }
        }
    }
}

use crate::tui::state::TextInput;
