use super::App;

use crate::providers::CloudProvider;
use crate::tui::state::{
    CollectorFocus, CollectorState, CollectorStatus, Feature, Progress, Screen,
};

impl App {
    pub fn next_screen(&mut self) {
        self.error_msg = None;
        self.screen = match self.screen {
            Screen::Welcome => Screen::FeatureSelection,
            Screen::FeatureSelection => match self.selected_feature {
                Feature::Poam => {
                    if self.has_accounts() {
                        Screen::PoamAccount
                    } else {
                        Screen::PoamRegion
                    }
                }
                Feature::Collectors => Screen::ProviderSelection,
                Feature::Inventory => {
                    if self.has_accounts() {
                        Screen::SelectAccount
                    } else {
                        Screen::SelectProfile
                    }
                }
            },
            Screen::PoamAccount => Screen::PoamRegion,
            Screen::SelectAccount => Screen::SetDates,
            Screen::SelectProfile => Screen::SelectRegion,
            Screen::SelectRegion => Screen::SetDates,
            Screen::SetDates => match self.selected_feature {
                Feature::Collectors => {
                    self.clamp_collector_cursors();
                    Screen::SelectCollectors
                }
                Feature::Inventory => Screen::Inventory,
                Feature::Poam => Screen::PoamRegion,
            },
            Screen::Inventory => Screen::SetOptions,
            Screen::PoamRegion => Screen::PoamYear,
            Screen::PoamYear => Screen::PoamMonth,
            Screen::PoamMonth => Screen::Confirm,
            Screen::TenableEndpoint => {
                self.clamp_collector_cursors();
                Screen::SelectCollectors
            }
            Screen::SelectCollectors => {
                if self.selected_provider == CloudProvider::Tenable {
                    Screen::ScanSelection
                } else if self.selected_provider == CloudProvider::Jira
                    && self
                        .selected_collectors()
                        .iter()
                        .any(|k| k == "jira-issues")
                {
                    Screen::JiraProjectSelection
                } else {
                    Screen::SetOptions
                }
            }
            Screen::JiraProjectSelection => Screen::SetOptions,
            Screen::ScanSelection => {
                #[cfg(feature = "tenable")]
                {
                    self.selected_scan_ids = self
                        .scan_selected
                        .iter()
                        .filter_map(|&i| self.scan_list.get(i))
                        .filter_map(|s| s.vm_id())
                        .collect();
                    self.selected_was_scan_ids = self
                        .scan_selected
                        .iter()
                        .filter_map(|&i| self.scan_list.get(i))
                        .filter_map(|s| s.was_scan_id())
                        .map(String::from)
                        .collect();
                }
                Screen::Confirm
            }
            Screen::SetOptions => {
                // Regions (and round-robin "All Regions") only apply to AWS
                // Collectors runs. Inventory is AWS-only today and keeps its
                // existing region behavior; force-clear regions only for a
                // non-AWS Collectors run so the runner doesn't attempt
                // region iteration where there is no region concept.
                let is_collectors_non_aws = self.selected_feature == Feature::Collectors
                    && self.selected_provider != CloudProvider::Aws;
                if is_collectors_non_aws {
                    self.all_regions = false;
                    self.options_selected_regions.clear();
                }
                Screen::Confirm
            }
            Screen::Confirm => Screen::Running,
            Screen::Preparing => Screen::Running,
            Screen::Running => Screen::Results,
            Screen::Results => Screen::Results,
            Screen::ProviderSelection => {
                if self.selected_provider == CloudProvider::Tenable {
                    self.auto_select_provider_accounts();
                    self.clamp_collector_cursors();
                    Screen::TenableEndpoint
                } else if self.selected_provider == CloudProvider::Okta
                    || self.selected_provider == CloudProvider::Jira
                    || self.selected_provider == CloudProvider::CrowdStrike
                    || self.selected_provider == CloudProvider::Elastic
                    || self.selected_provider == CloudProvider::Jamf
                    || self.selected_provider == CloudProvider::Github
                {
                    self.auto_select_provider_accounts();
                    self.clamp_collector_cursors();
                    Screen::SelectCollectors
                } else if self.has_accounts() {
                    Screen::SelectAccount
                } else {
                    Screen::SelectProfile
                }
            }
        };
    }

    pub fn prev_screen(&mut self) {
        self.error_msg = None;
        self.screen = match self.screen {
            Screen::FeatureSelection => Screen::Welcome,
            Screen::ProviderSelection => Screen::FeatureSelection,
            Screen::SelectAccount => Screen::ProviderSelection,
            Screen::SelectProfile => {
                if self.has_accounts() {
                    Screen::ProviderSelection
                } else {
                    Screen::FeatureSelection
                }
            }
            Screen::SelectRegion => Screen::SelectProfile,
            Screen::SetDates => {
                if self.selected_provider == CloudProvider::Tenable {
                    Screen::ProviderSelection
                } else if self.has_accounts() {
                    Screen::SelectAccount
                } else {
                    Screen::SelectRegion
                }
            }
            Screen::Inventory => Screen::SetDates,
            Screen::PoamAccount => Screen::FeatureSelection,
            Screen::PoamRegion => {
                if self.has_accounts() {
                    Screen::PoamAccount
                } else {
                    Screen::FeatureSelection
                }
            }
            Screen::PoamYear => Screen::PoamRegion,
            Screen::PoamMonth => Screen::PoamYear,
            Screen::SelectCollectors => {
                if self.selected_provider == CloudProvider::Tenable {
                    Screen::TenableEndpoint
                } else if self.selected_provider == CloudProvider::Okta
                    || self.selected_provider == CloudProvider::Jira
                    || self.selected_provider == CloudProvider::CrowdStrike
                    || self.selected_provider == CloudProvider::Elastic
                    || self.selected_provider == CloudProvider::Jamf
                    || self.selected_provider == CloudProvider::Github
                {
                    Screen::ProviderSelection
                } else {
                    Screen::SetDates
                }
            }
            Screen::TenableEndpoint => Screen::ProviderSelection,
            Screen::ScanSelection => Screen::SelectCollectors,
            Screen::JiraProjectSelection => Screen::SelectCollectors,
            Screen::SetOptions => match self.selected_feature {
                Feature::Collectors => Screen::SelectCollectors,
                Feature::Inventory => Screen::Inventory,
                Feature::Poam => Screen::PoamMonth,
            },
            Screen::Confirm => match self.selected_feature {
                Feature::Poam => Screen::PoamMonth,
                Feature::Collectors if self.selected_provider == CloudProvider::Tenable => {
                    Screen::ScanSelection
                }
                _ => Screen::SetOptions,
            },
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
                // At least one visible (provider-matching) collector must be selected.
                let any_provider_selected = self.collector_selected.iter().any(|&i| {
                    self.collector_items
                        .get(i)
                        .map(|(_, _, p)| {
                            self.selected_feature != Feature::Collectors
                                || *p == self.selected_provider
                        })
                        .unwrap_or(false)
                });
                if !any_provider_selected {
                    self.error_msg = Some("Select at least one collector (Space to toggle)".into());
                    return false;
                }
                true
            }
            Screen::ProviderSelection => {
                #[cfg(feature = "tenable")]
                if self.selected_provider == CloudProvider::Tenable {
                    let has_tenable = self
                        .accounts
                        .iter()
                        .any(|a| a.provider == CloudProvider::Tenable);
                    if !has_tenable {
                        self.error_msg =
                            Some("No Tenable accounts configured in tenable-config.toml".into());
                        return false;
                    }
                }
                #[cfg(feature = "okta")]
                if self.selected_provider == CloudProvider::Okta {
                    let has_okta = self
                        .accounts
                        .iter()
                        .any(|a| a.provider == CloudProvider::Okta);
                    if !has_okta {
                        self.error_msg =
                            Some("No Okta accounts configured in okta-config.toml".into());
                        return false;
                    }
                }
                #[cfg(feature = "jira")]
                if self.selected_provider == CloudProvider::Jira {
                    let has_jira = self
                        .accounts
                        .iter()
                        .any(|a| a.provider == CloudProvider::Jira);
                    if !has_jira {
                        self.error_msg =
                            Some("No Jira accounts configured in jira-config.toml".into());
                        return false;
                    }
                }
                #[cfg(feature = "crowdstrike")]
                if self.selected_provider == CloudProvider::CrowdStrike {
                    let has_crowdstrike = self
                        .accounts
                        .iter()
                        .any(|a| a.provider == CloudProvider::CrowdStrike);
                    if !has_crowdstrike {
                        self.error_msg = Some(
                            "No CrowdStrike accounts configured in crowdstrike-config.toml".into(),
                        );
                        return false;
                    }
                }
                #[cfg(feature = "elastic")]
                if self.selected_provider == CloudProvider::Elastic {
                    let has_elastic = self
                        .accounts
                        .iter()
                        .any(|a| a.provider == CloudProvider::Elastic);
                    if !has_elastic {
                        self.error_msg =
                            Some("No Elastic accounts configured in elastic-config.toml".into());
                        return false;
                    }
                }
                #[cfg(feature = "jamf")]
                if self.selected_provider == CloudProvider::Jamf {
                    let has_jamf = self
                        .accounts
                        .iter()
                        .any(|a| a.provider == CloudProvider::Jamf);
                    if !has_jamf {
                        self.error_msg =
                            Some("No Jamf accounts configured in jamf-config.toml".into());
                        return false;
                    }
                }
                #[cfg(feature = "github")]
                if self.selected_provider == CloudProvider::Github {
                    let has_github = self
                        .accounts
                        .iter()
                        .any(|a| a.provider == CloudProvider::Github);
                    if !has_github {
                        self.error_msg =
                            Some("No GitHub accounts configured in github-config.toml".into());
                        return false;
                    }
                }
                true
            }
            Screen::Inventory => {
                if self.inventory_selected.is_empty() {
                    self.error_msg =
                        Some("Select at least one asset type (Space to toggle)".into());
                    return false;
                }
                true
            }
            Screen::PoamYear => {
                let year = self.poam_year.value.trim();
                if year.len() != 4 || year.parse::<u32>().is_err() {
                    self.error_msg = Some("Enter a 4-digit findings year (e.g., 2026)".into());
                    return false;
                }
                true
            }
            Screen::ScanSelection => {
                if self.scan_selected.is_empty() {
                    self.error_msg = Some("Select at least one scan (Space to toggle)".into());
                    return false;
                }
                true
            }
            _ => true,
        }
    }

    /// Reset collection state so the wizard can be re-run without relaunching.
    /// User configuration (dates, profile, region, selected collectors) is preserved.
    pub fn reset(&mut self) {
        self.screen = Screen::Welcome;
        self.collector_statuses.clear();
        self.result_files.clear();
        self.result_zip = None;
        self.result_signing_manifest = None;
        self.result_signing_key_path = None;
        self.error_messages.clear();
        self.progress_rx = None;
        self.finished_tick = None;
        self.current_account_label = None;
        self.current_account_index = 0;
        self.total_account_count = 0;
        self.current_region_label = None;
        self.current_endpoint_label = None;
        self.result_scroll = 0;
        self.error_msg = None;
        self.prep_log.clear();
        self.prep_current = 0;
        self.prep_total = 0;
        self.options_region_cursor = 0;
        self.inventory_cursor = 0;
        self.inventory_selected.clear();
        self.collector_category_cursor = 0;
        self.collector_focus = CollectorFocus::Categories;
        self.collector_search.clear();
        self.scan_cursor = 0;
        self.scan_selected.clear();
        self.scan_filter = crate::tui::state::ScanTimeFilter::default();
        self.selected_scan_ids.clear();
        self.selected_was_scan_ids.clear();
        // scan_list intentionally preserved (pre-fetched once per session)
        self.poam_summary = None;
        self.selected_feature = Feature::Collectors;
        self.selected_provider = CloudProvider::Aws;
        self.provider_cursor = 0;
        // Preserve options_selected_regions so the user's choices carry over.
    }

    /// Drain any pending progress messages from the background task.
    pub fn poll_progress(&mut self) {
        if let Some(rx) = &mut self.progress_rx {
            while let Ok(msg) = rx.try_recv() {
                match msg {
                    Progress::AccountStarted {
                        name,
                        index,
                        total,
                        region,
                        collectors,
                        endpoint_label,
                    } => {
                        self.current_account_label = Some(name);
                        self.current_account_index = index;
                        self.total_account_count = total;
                        self.current_region_label = if region.is_empty() {
                            None
                        } else {
                            Some(region)
                        };
                        self.current_endpoint_label = endpoint_label;
                        self.collector_statuses = collectors
                            .into_iter()
                            .map(|n| CollectorStatus {
                                name: n,
                                state: CollectorState::Waiting,
                            })
                            .collect();
                    }
                    Progress::AccountFinished { .. } => {
                        // Nothing to do here; the next AccountStarted or
                        // Finished will drive the UI forward.
                    }
                    Progress::RegionStarted { region } => {
                        self.current_region_label = Some(region);
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
                        self.error_messages
                            .push((collector.clone(), message.clone()));
                        if let Some(s) = self
                            .collector_statuses
                            .iter_mut()
                            .find(|s| s.name == collector)
                        {
                            s.state = CollectorState::Failed(message);
                        }
                    }
                    Progress::Skipped { collector, reason } => {
                        self.skipped_messages
                            .push((collector.clone(), reason.clone()));
                        if let Some(s) = self
                            .collector_statuses
                            .iter_mut()
                            .find(|s| s.name == collector)
                        {
                            s.state = CollectorState::Skipped(reason);
                        }
                    }
                    Progress::Finished {
                        files,
                        zip_path,
                        signing_manifest,
                        signing_key_path,
                        poam_summary,
                    } => {
                        self.result_files = files;
                        self.result_zip = zip_path;
                        self.result_signing_manifest = signing_manifest;
                        self.result_signing_key_path = signing_key_path;
                        self.poam_summary = poam_summary;
                        self.finished_tick = Some(self.tick);
                        self.screen = Screen::Results;
                    }
                }
            }
        }
    }
}
