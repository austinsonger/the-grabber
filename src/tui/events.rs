use std::io;

use anyhow::Result;
use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use ratatui::backend::CrosstermBackend;
use ratatui::Terminal;

use super::{App, CollectorFocus, Feature, Screen};

enum Action {
    Continue,
    Quit,
    StartCollection,
    NewCollection,
}

pub(crate) fn event_loop(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    app: &mut App,
) -> Result<()> {
    loop {
        app.tick = app.tick.wrapping_add(1);

        if app.screen == Screen::Running {
            app.poll_progress();
        }

        terminal.draw(|f| super::ui::draw(f, app))?;

        if event::poll(std::time::Duration::from_millis(100))? {
            if let Event::Key(key) = event::read()? {
                if key.kind != KeyEventKind::Press {
                    continue;
                }
                match handle_key(app, key.code, key.modifiers) {
                    Action::Quit => return Ok(()),
                    Action::StartCollection => return Ok(()),
                    Action::NewCollection => {
                        app.reset();
                    }
                    Action::Continue => {}
                }
            }
        }

        if app.screen == Screen::Results {
            // Stay on results until user presses q / Esc
        }
    }
}

fn handle_key(app: &mut App, key: KeyCode, modifiers: KeyModifiers) -> Action {
    if key == KeyCode::Char('q') && app.screen == Screen::Results {
        return Action::Quit;
    }

    match app.screen.clone() {
        Screen::Welcome => handle_welcome(app, key),
        Screen::FeatureSelection => handle_feature_selection(app, key),
        Screen::SelectAccount => handle_select_account(app, key),
        Screen::SelectProfile => handle_select_profile(app, key),
        Screen::SelectRegion => handle_select_region(app, key),
        Screen::SetDates => handle_set_dates(app, key),
        Screen::PoamAccount => handle_poam_account(app, key),
        Screen::PoamRegion => handle_poam_region(app, key),
        Screen::PoamYear => handle_poam_year(app, key),
        Screen::PoamMonth => handle_poam_month(app, key),
        Screen::SelectCollectors => handle_select_collectors(app, key),
        Screen::ScanSelection => handle_scan_selection(app, key),
        Screen::JiraProjectSelection => handle_jira_project_selection(app, key),
        Screen::Inventory => handle_inventory(app, key),
        Screen::SetOptions => handle_set_options(app, key),
        Screen::Confirm => return handle_confirm(app, key),
        Screen::Running | Screen::Preparing => {}
        Screen::Results => return handle_results(app, key),
        Screen::ProviderSelection => handle_provider_selection(app, key),
        Screen::TenableEndpoint => handle_tenable_endpoint(app, key),
        Screen::StigRemediationAccount => handle_stig_remediation_account(app, key),
        Screen::StigRemediationScanning | Screen::StigRemediationApplying => {}
        Screen::StigRemediationList => handle_stig_remediation_list(app, key),
        Screen::StigRemediationResults => return handle_stig_remediation_results(app, key),
    }

    let _ = modifiers;
    Action::Continue
}

// ─── Per-screen handlers ────────────────────────────────────────────────────

fn handle_welcome(app: &mut App, key: KeyCode) {
    match key {
        KeyCode::Enter | KeyCode::Char(' ') => app.next_screen(),
        _ => {}
    }
}

fn handle_feature_selection(app: &mut App, key: KeyCode) {
    match key {
        KeyCode::Up | KeyCode::Left => {
            app.selected_feature = match app.selected_feature {
                Feature::Collectors => Feature::StigRemediation,
                Feature::Inventory => Feature::Collectors,
                Feature::Poam => Feature::Inventory,
                Feature::StigRemediation => Feature::Poam,
            };
        }
        KeyCode::Down | KeyCode::Right => {
            app.selected_feature = match app.selected_feature {
                Feature::Collectors => Feature::Inventory,
                Feature::Inventory => Feature::Poam,
                Feature::Poam => Feature::StigRemediation,
                Feature::StigRemediation => Feature::Collectors,
            };
        }
        KeyCode::Enter | KeyCode::Char(' ') => app.next_screen(),
        KeyCode::Esc => app.prev_screen(),
        _ => {}
    }
}

fn handle_select_account(app: &mut App, key: KeyCode) {
    let indices = app.provider_account_indices();
    let filtered_len = indices.len();

    match key {
        KeyCode::Up => {
            if app.account_cursor > 0 {
                app.account_cursor -= 1;
            }
        }
        KeyCode::Down => {
            if app.account_cursor < filtered_len {
                app.account_cursor += 1;
            }
        }
        KeyCode::Char(' ') => {
            if app.account_cursor < filtered_len {
                let real = indices[app.account_cursor];
                if app.selected_accounts.contains(&real) {
                    app.selected_accounts.remove(&real);
                } else {
                    app.selected_accounts.insert(real);
                }
            } else {
                // "Other" — fall back to legacy profile picker
                app.selected_accounts.clear();
                app.screen = Screen::SelectProfile;
            }
        }
        KeyCode::Char('a') => {
            for &i in &indices {
                app.selected_accounts.insert(i);
            }
        }
        KeyCode::Char('d') => {
            app.selected_accounts.clear();
        }
        KeyCode::Enter => {
            if app.account_cursor == filtered_len {
                app.selected_accounts.clear();
                app.screen = Screen::SelectProfile;
            } else {
                if app.selected_accounts.is_empty() {
                    app.selected_accounts.insert(indices[app.account_cursor]);
                }
                if app.validate_current() {
                    app.next_screen();
                }
            }
        }
        KeyCode::Esc => app.prev_screen(),
        _ => {}
    }
}

fn handle_select_profile(app: &mut App, key: KeyCode) {
    match key {
        KeyCode::Up => {
            if app.profile_cursor > 0 {
                app.profile_cursor -= 1;
            }
        }
        KeyCode::Down => {
            if app.profile_cursor + 1 < app.profiles.len() {
                app.profile_cursor += 1;
            }
        }
        KeyCode::Enter => {
            if app.validate_current() {
                app.next_screen();
            }
        }
        KeyCode::Esc => app.prev_screen(),
        _ => {}
    }
}

fn handle_select_region(app: &mut App, key: KeyCode) {
    match key {
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
        KeyCode::Enter => {
            if app.validate_current() {
                app.next_screen();
            }
        }
        KeyCode::Esc => app.prev_screen(),
        _ => {}
    }
}

fn handle_set_dates(app: &mut App, key: KeyCode) {
    match key {
        KeyCode::Up => {
            if app.time_frame_cursor > 0 {
                app.time_frame_cursor -= 1;
            }
        }
        KeyCode::Down => {
            if app.time_frame_cursor < 11 {
                app.time_frame_cursor += 1;
            }
        }
        KeyCode::Enter => {
            if app.validate_current() {
                app.next_screen();
            }
        }
        KeyCode::Esc => app.prev_screen(),
        _ => {}
    }
}

fn handle_poam_account(app: &mut App, key: KeyCode) {
    match key {
        KeyCode::Up => {
            if app.poam_account_cursor > 0 {
                app.poam_account_cursor -= 1;
            }
        }
        KeyCode::Down => {
            if app.poam_account_cursor + 1 < app.accounts.len() {
                app.poam_account_cursor += 1;
            }
        }
        KeyCode::Enter => app.next_screen(),
        KeyCode::Esc => app.prev_screen(),
        _ => {}
    }
}

fn handle_poam_region(app: &mut App, key: KeyCode) {
    match key {
        KeyCode::Up => {
            if app.poam_region_cursor > 0 {
                app.poam_region_cursor -= 1;
            }
        }
        KeyCode::Down => {
            if app.poam_region_cursor + 1 < app.regions.len() {
                app.poam_region_cursor += 1;
            }
        }
        KeyCode::Enter => {
            if app.validate_current() {
                app.next_screen();
            }
        }
        KeyCode::Esc => app.prev_screen(),
        _ => {}
    }
}

fn handle_poam_year(app: &mut App, key: KeyCode) {
    match key {
        KeyCode::Char(c) if c.is_ascii_digit() => app.poam_year.insert(c),
        KeyCode::Backspace => app.poam_year.backspace(),
        KeyCode::Left => app.poam_year.move_left(),
        KeyCode::Right => app.poam_year.move_right(),
        KeyCode::Enter => {
            if app.validate_current() {
                app.next_screen();
            }
        }
        KeyCode::Esc => app.prev_screen(),
        _ => {}
    }
}

fn handle_poam_month(app: &mut App, key: KeyCode) {
    match key {
        KeyCode::Up => {
            if app.poam_month_cursor > 0 {
                app.poam_month_cursor -= 1;
            }
        }
        KeyCode::Down => {
            if app.poam_month_cursor < 11 {
                app.poam_month_cursor += 1;
            }
        }
        KeyCode::Enter => {
            if app.validate_current() {
                app.next_screen();
            }
        }
        KeyCode::Esc => app.prev_screen(),
        _ => {}
    }
}

fn handle_select_collectors(app: &mut App, key: KeyCode) {
    match key {
        // ── Panel switching ──────────────────────────────────────────────
        KeyCode::Tab => {
            app.collector_focus = match app.collector_focus {
                CollectorFocus::Search => CollectorFocus::Categories,
                CollectorFocus::Categories => CollectorFocus::Items,
                CollectorFocus::Items => CollectorFocus::Search,
            };
        }
        KeyCode::Left | KeyCode::Right if app.collector_focus != CollectorFocus::Search => {
            app.collector_focus = match app.collector_focus {
                CollectorFocus::Categories => CollectorFocus::Items,
                CollectorFocus::Items | CollectorFocus::Search => CollectorFocus::Categories,
            };
        }

        // ── Search panel ─────────────────────────────────────────────────
        KeyCode::Left if app.collector_focus == CollectorFocus::Search => {
            app.collector_search.move_left();
        }
        KeyCode::Right if app.collector_focus == CollectorFocus::Search => {
            app.collector_search.move_right();
        }
        KeyCode::Char(c) if app.collector_focus == CollectorFocus::Search => {
            app.collector_search.insert(c);
            app.clamp_collector_cursors();
        }
        KeyCode::Backspace if app.collector_focus == CollectorFocus::Search => {
            app.collector_search.backspace();
            app.clamp_collector_cursors();
        }
        KeyCode::Down if app.collector_focus == CollectorFocus::Search => {
            app.collector_focus = CollectorFocus::Categories;
        }
        KeyCode::Esc
            if app.collector_focus == CollectorFocus::Search
                && !app.collector_search.value.is_empty() =>
        {
            app.collector_search.clear();
            app.clamp_collector_cursors();
        }

        // ── Category panel navigation ────────────────────────────────────
        KeyCode::Up if app.collector_focus == CollectorFocus::Categories => {
            let visible = app.visible_categories();
            if let Some(pos) = visible
                .iter()
                .position(|&c| c == app.collector_category_cursor)
            {
                if pos > 0 {
                    app.collector_category_cursor = visible[pos - 1];
                    let items = app.visible_items_in_category(app.collector_category_cursor);
                    if let Some(&first) = items.first() {
                        app.collector_cursor = first;
                    }
                }
            }
        }
        KeyCode::Down if app.collector_focus == CollectorFocus::Categories => {
            let visible = app.visible_categories();
            if let Some(pos) = visible
                .iter()
                .position(|&c| c == app.collector_category_cursor)
            {
                if pos + 1 < visible.len() {
                    app.collector_category_cursor = visible[pos + 1];
                    let items = app.visible_items_in_category(app.collector_category_cursor);
                    if let Some(&first) = items.first() {
                        app.collector_cursor = first;
                    }
                }
            }
        }
        KeyCode::Char(c)
            if c.is_ascii_digit() && app.collector_focus == CollectorFocus::Categories =>
        {
            let digit = c as usize - '0' as usize;
            if digit > 0 && digit <= app.current_categories.len() {
                app.jump_to_category(digit - 1);
            }
        }

        // ── Item panel navigation ────────────────────────────────────────
        KeyCode::Up if app.collector_focus == CollectorFocus::Items => {
            let items = app.visible_items_in_category(app.collector_category_cursor);
            if let Some(pos) = items.iter().position(|&i| i == app.collector_cursor) {
                if pos > 0 {
                    app.collector_cursor = items[pos - 1];
                } else {
                    let visible_cats = app.visible_categories();
                    if let Some(cat_pos) = visible_cats
                        .iter()
                        .position(|&c| c == app.collector_category_cursor)
                    {
                        if cat_pos > 0 {
                            app.collector_category_cursor = visible_cats[cat_pos - 1];
                            let prev_items =
                                app.visible_items_in_category(app.collector_category_cursor);
                            if let Some(&last) = prev_items.last() {
                                app.collector_cursor = last;
                            }
                        }
                    }
                }
            }
        }
        KeyCode::Down if app.collector_focus == CollectorFocus::Items => {
            let items = app.visible_items_in_category(app.collector_category_cursor);
            if let Some(pos) = items.iter().position(|&i| i == app.collector_cursor) {
                if pos + 1 < items.len() {
                    app.collector_cursor = items[pos + 1];
                } else {
                    let visible_cats = app.visible_categories();
                    if let Some(cat_pos) = visible_cats
                        .iter()
                        .position(|&c| c == app.collector_category_cursor)
                    {
                        if cat_pos + 1 < visible_cats.len() {
                            app.collector_category_cursor = visible_cats[cat_pos + 1];
                            let next_items =
                                app.visible_items_in_category(app.collector_category_cursor);
                            if let Some(&first) = next_items.first() {
                                app.collector_cursor = first;
                            }
                        }
                    }
                }
            }
        }

        // ── Toggle (Space) ───────────────────────────────────────────────
        KeyCode::Char(' ') if app.collector_focus == CollectorFocus::Items => {
            let i = app.collector_cursor;
            if app.collector_selected.contains(&i) {
                app.collector_selected.remove(&i);
            } else {
                app.collector_selected.insert(i);
            }
            app.persist_collector_selected_to_provider();
        }
        KeyCode::Char(' ') if app.collector_focus == CollectorFocus::Categories => {
            let sel = app.selected_in_category(app.collector_category_cursor);
            let (start, end) = app.category_bounds(app.collector_category_cursor);
            let total = end.saturating_sub(start);
            app.set_category_selection(app.collector_category_cursor, sel < total);
        }

        // ── Select / Deselect all ────────────────────────────────────────
        KeyCode::Char('a') if app.collector_focus != CollectorFocus::Search => {
            app.set_category_selection(app.collector_category_cursor, true);
        }
        KeyCode::Char('d') if app.collector_focus != CollectorFocus::Search => {
            app.set_category_selection(app.collector_category_cursor, false);
        }

        KeyCode::Enter => {
            if app.validate_current() {
                app.next_screen();
            }
        }
        KeyCode::Esc => app.prev_screen(),
        _ => {}
    }
}

fn handle_inventory(app: &mut App, key: KeyCode) {
    match key {
        KeyCode::Up => {
            if app.inventory_cursor > 0 {
                app.inventory_cursor -= 1;
            }
        }
        KeyCode::Down => {
            if app.inventory_cursor + 1 < app.inventory_items.len() {
                app.inventory_cursor += 1;
            }
        }
        KeyCode::Char(' ') => {
            let i = app.inventory_cursor;
            if app.inventory_selected.contains(&i) {
                app.inventory_selected.remove(&i);
            } else {
                app.inventory_selected.insert(i);
            }
        }
        KeyCode::Char('a') => {
            for i in 0..app.inventory_items.len() {
                app.inventory_selected.insert(i);
            }
        }
        KeyCode::Char('d') => {
            app.inventory_selected.clear();
        }
        KeyCode::Enter => {
            if app.validate_current() {
                app.next_screen();
            }
        }
        KeyCode::Esc => app.prev_screen(),
        _ => {}
    }
}

/// AWS regions (and the "All Regions" round-robin toggle) only make sense for
/// a Collectors run against the AWS provider. Inventory is AWS-only today, so
/// it is intentionally excluded here and keeps its existing region behavior.
fn is_aws_regional(app: &App) -> bool {
    app.selected_feature == Feature::Collectors
        && app.selected_provider == crate::providers::CloudProvider::Aws
}

fn handle_set_options(app: &mut App, key: KeyCode) {
    let is_inventory = app.selected_feature == Feature::Inventory;
    let region_field = if is_inventory {
        6
    } else if is_aws_regional(app) {
        7
    } else {
        // No region list for non-AWS Collectors runs; use a value the
        // options_field counter can never reach so Up/Down/Space handlers
        // below stay inert.
        usize::MAX
    };

    match key {
        KeyCode::Tab => {
            let total = if is_inventory {
                7
            } else if is_aws_regional(app) {
                8
            } else {
                7
            };
            let mut next = (app.options_field + 1) % total;
            if next == 2 && !is_inventory && !is_aws_regional(app) {
                next = 3;
            }
            app.options_field = next;
        }
        KeyCode::Char(' ') if app.options_field == 1 => {
            app.include_raw = !app.include_raw;
        }
        KeyCode::Char(' ') if app.options_field == 2 && (is_inventory || is_aws_regional(app)) => {
            app.all_regions = !app.all_regions;
            if app.all_regions {
                app.options_selected_regions.clear();
            }
        }
        KeyCode::Char(' ') if app.options_field == 3 => {
            app.zip = !app.zip;
        }
        KeyCode::Char(' ') if app.options_field == 4 => {
            app.sign = !app.sign;
        }
        KeyCode::Char(' ') if app.options_field == 5 => {
            if app.selected_feature == Feature::Inventory {
                app.skip_inventory_csv = !app.skip_inventory_csv;
            } else {
                app.write_run_manifest = !app.write_run_manifest;
            }
        }
        KeyCode::Char(' ')
            if app.options_field == 6 && app.selected_feature == Feature::Collectors =>
        {
            app.write_chain_of_custody = !app.write_chain_of_custody;
        }
        KeyCode::Up if app.options_field == region_field => {
            if app.options_region_cursor > 0 {
                app.options_region_cursor -= 1;
            }
        }
        KeyCode::Down if app.options_field == region_field => {
            if app.options_region_cursor + 1 < app.regions.len() {
                app.options_region_cursor += 1;
            }
        }
        KeyCode::Char(' ') if app.options_field == region_field => {
            let i = app.options_region_cursor;
            if app.options_selected_regions.contains(&i) {
                app.options_selected_regions.remove(&i);
            } else {
                app.options_selected_regions.insert(i);
                app.all_regions = false;
            }
        }
        KeyCode::Char(c) if app.options_field == 0 => app.filter_input.insert(c),
        KeyCode::Backspace if app.options_field == 0 => app.filter_input.backspace(),
        KeyCode::Left if app.options_field == 0 => app.filter_input.move_left(),
        KeyCode::Right if app.options_field == 0 => app.filter_input.move_right(),
        KeyCode::Enter => {
            if app.validate_current() {
                app.next_screen();
            }
        }
        KeyCode::Esc => app.prev_screen(),
        _ => {}
    }
}

fn handle_confirm(app: &mut App, key: KeyCode) -> Action {
    match key {
        KeyCode::Enter => {
            app.next_screen();
            Action::StartCollection
        }
        KeyCode::Esc => {
            app.prev_screen();
            Action::Continue
        }
        _ => Action::Continue,
    }
}

fn handle_results(app: &mut App, key: KeyCode) -> Action {
    let len = app.result_files.len();
    match key {
        KeyCode::Char('q') | KeyCode::Esc => Action::Quit,
        KeyCode::Char('n') => Action::NewCollection,
        KeyCode::Up => {
            if app.result_scroll > 0 {
                app.result_scroll -= 1;
            }
            Action::Continue
        }
        KeyCode::Down => {
            if app.result_scroll + 1 < len {
                app.result_scroll += 1;
            }
            Action::Continue
        }
        KeyCode::Home => {
            app.result_scroll = 0;
            Action::Continue
        }
        KeyCode::End => {
            app.result_scroll = len.saturating_sub(1);
            Action::Continue
        }
        KeyCode::PageUp => {
            app.result_scroll = app.result_scroll.saturating_sub(10);
            Action::Continue
        }
        KeyCode::PageDown => {
            app.result_scroll = (app.result_scroll + 10).min(len.saturating_sub(1));
            Action::Continue
        }
        _ => Action::Continue,
    }
}

fn handle_stig_remediation_account(app: &mut App, key: KeyCode) {
    let len = app.stig_account_list.len();
    match key {
        KeyCode::Up => {
            if app.stig_account_cursor > 0 {
                app.stig_account_cursor -= 1;
            }
        }
        KeyCode::Down => {
            if app.stig_account_cursor + 1 < len {
                app.stig_account_cursor += 1;
            }
        }
        KeyCode::Enter => app.next_screen(),
        KeyCode::Esc => app.prev_screen(),
        _ => {}
    }
}

fn handle_stig_remediation_list(app: &mut App, key: KeyCode) {
    let actionable: Vec<usize> = app
        .stig_findings
        .iter()
        .enumerate()
        .filter(|(_, r)| r.status.is_actionable())
        .map(|(i, _)| i)
        .collect();

    if app.stig_confirm_pending {
        let needs_text = actionable
            .get(app.stig_finding_cursor)
            .and_then(|&i| app.stig_findings.get(i))
            .and_then(|r| r.remediation.first())
            .map(|t| t.needs_text_input())
            .unwrap_or(false);

        match key {
            KeyCode::Char(c) if needs_text => app.stig_text_input.insert(c),
            KeyCode::Backspace if needs_text => app.stig_text_input.backspace(),
            KeyCode::Left if needs_text => app.stig_text_input.move_left(),
            KeyCode::Right if needs_text => app.stig_text_input.move_right(),
            KeyCode::Enter => {
                if needs_text && app.stig_text_input.value.trim().is_empty() {
                    app.error_msg = Some("Enter the text to apply, or Esc to cancel".into());
                    return;
                }
                app.screen = crate::tui::state::Screen::StigRemediationApplying;
            }
            KeyCode::Char('y') if !needs_text => {
                app.screen = crate::tui::state::Screen::StigRemediationApplying;
            }
            KeyCode::Esc | KeyCode::Char('n') => {
                app.stig_confirm_pending = false;
                app.stig_text_input.clear();
            }
            _ => {}
        }
        return;
    }

    match key {
        KeyCode::Up => {
            if app.stig_finding_cursor > 0 {
                app.stig_finding_cursor -= 1;
            }
        }
        KeyCode::Down => {
            if app.stig_finding_cursor + 1 < actionable.len() {
                app.stig_finding_cursor += 1;
            }
        }
        KeyCode::Enter => {
            if !actionable.is_empty() {
                app.stig_confirm_pending = true;
            }
        }
        KeyCode::Char('q') => app.next_screen(), // → StigRemediationResults
        KeyCode::Esc => app.prev_screen(),
        _ => {}
    }
}

fn handle_stig_remediation_results(_app: &mut App, key: KeyCode) -> Action {
    match key {
        KeyCode::Char('n') => Action::NewCollection,
        KeyCode::Char('q') | KeyCode::Esc => Action::Quit,
        _ => Action::Continue,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_results_app(file_count: usize) -> App {
        let mut app = App::new(vec![]);
        app.screen = Screen::Results;
        app.result_files = (0..file_count).map(|i| format!("file-{i}.json")).collect();
        app
    }

    #[test]
    fn results_scroll_clamps_with_arrow_keys() {
        let mut app = make_results_app(3);

        assert!(matches!(
            handle_results(&mut app, KeyCode::Down),
            Action::Continue
        ));
        assert_eq!(app.result_scroll, 1);

        assert!(matches!(
            handle_results(&mut app, KeyCode::Down),
            Action::Continue
        ));
        assert_eq!(app.result_scroll, 2);

        assert!(matches!(
            handle_results(&mut app, KeyCode::Down),
            Action::Continue
        ));
        assert_eq!(app.result_scroll, 2);

        assert!(matches!(
            handle_results(&mut app, KeyCode::Up),
            Action::Continue
        ));
        assert_eq!(app.result_scroll, 1);

        assert!(matches!(
            handle_results(&mut app, KeyCode::Up),
            Action::Continue
        ));
        assert_eq!(app.result_scroll, 0);

        assert!(matches!(
            handle_results(&mut app, KeyCode::Up),
            Action::Continue
        ));
        assert_eq!(app.result_scroll, 0);
    }

    #[test]
    fn results_home_end_page_keys_clamp_bounds() {
        let mut app = make_results_app(5);

        assert!(matches!(
            handle_results(&mut app, KeyCode::End),
            Action::Continue
        ));
        assert_eq!(app.result_scroll, 4);

        assert!(matches!(
            handle_results(&mut app, KeyCode::PageUp),
            Action::Continue
        ));
        assert_eq!(app.result_scroll, 0);

        assert!(matches!(
            handle_results(&mut app, KeyCode::PageDown),
            Action::Continue
        ));
        assert_eq!(app.result_scroll, 4);

        assert!(matches!(
            handle_results(&mut app, KeyCode::Home),
            Action::Continue
        ));
        assert_eq!(app.result_scroll, 0);
    }

    #[test]
    fn results_keys_are_safe_with_empty_file_list() {
        let mut app = make_results_app(0);

        assert!(matches!(
            handle_results(&mut app, KeyCode::End),
            Action::Continue
        ));
        assert_eq!(app.result_scroll, 0);

        assert!(matches!(
            handle_results(&mut app, KeyCode::PageDown),
            Action::Continue
        ));
        assert_eq!(app.result_scroll, 0);
    }
}

fn handle_scan_selection(app: &mut App, key: KeyCode) {
    use crate::tui::state::ScanTimeFilter;

    let visible = app.visible_scans();

    match key {
        KeyCode::Up => {
            if app.scan_cursor > 0 {
                app.scan_cursor -= 1;
            }
        }
        KeyCode::Down => {
            if app.scan_cursor + 1 < visible.len() {
                app.scan_cursor += 1;
            }
        }
        KeyCode::Tab => {
            app.scan_filter = match app.scan_filter {
                ScanTimeFilter::Recent => ScanTimeFilter::Past12Months,
                ScanTimeFilter::Past12Months => ScanTimeFilter::AllTime,
                ScanTimeFilter::AllTime => ScanTimeFilter::Recent,
            };
            app.scan_cursor = 0;
            app.scan_selected.clear();
        }
        KeyCode::Char(' ') => {
            if let Some(&real_idx) = visible.get(app.scan_cursor) {
                if app.scan_selected.contains(&real_idx) {
                    app.scan_selected.remove(&real_idx);
                } else {
                    app.scan_selected.insert(real_idx);
                }
            }
        }
        KeyCode::Enter => {
            if app.validate_current() {
                app.next_screen();
            }
        }
        KeyCode::Esc => app.prev_screen(),
        _ => {}
    }
}

fn handle_jira_project_selection(app: &mut App, key: KeyCode) {
    let len = app.jira_project_list.len();
    match key {
        KeyCode::Up => {
            if app.jira_project_cursor > 0 {
                app.jira_project_cursor -= 1;
            }
        }
        KeyCode::Down => {
            if app.jira_project_cursor + 1 < len {
                app.jira_project_cursor += 1;
            }
        }
        KeyCode::Char(' ') => {
            if app.jira_project_cursor < len {
                let idx = app.jira_project_cursor;
                if app.jira_project_selected.contains(&idx) {
                    app.jira_project_selected.remove(&idx);
                } else {
                    app.jira_project_selected.insert(idx);
                }
            }
        }
        KeyCode::Enter => {
            if app.jira_project_selected.is_empty() {
                app.error_msg = Some("Select at least one Jira project (Space to toggle)".into());
                return;
            }
            app.selected_jira_project_keys = app
                .jira_project_selected
                .iter()
                .filter_map(|&i| app.jira_project_list.get(i))
                .map(|p| p.key.clone())
                .collect();
            app.next_screen();
        }
        KeyCode::Esc => app.prev_screen(),
        _ => {}
    }
}

fn handle_provider_selection(app: &mut App, key: KeyCode) {
    use crate::providers::CloudProvider;
    let providers = CloudProvider::available();
    match key {
        KeyCode::Up => {
            if app.provider_cursor > 0 {
                app.provider_cursor -= 1;
                app.selected_provider = providers[app.provider_cursor];
            }
        }
        KeyCode::Down => {
            if app.provider_cursor + 1 < providers.len() {
                app.provider_cursor += 1;
                app.selected_provider = providers[app.provider_cursor];
            }
        }
        KeyCode::Enter | KeyCode::Char(' ') => {
            if app.validate_current() {
                app.load_menu_for_current_provider();
                app.next_screen();
            }
        }
        KeyCode::Esc => app.prev_screen(),
        _ => {}
    }
}

fn handle_tenable_endpoint(app: &mut App, key: KeyCode) {
    use crate::tui::state::TenableEndpointChoice;
    const OPTIONS: [TenableEndpointChoice; 2] = [
        TenableEndpointChoice::Commercial,
        TenableEndpointChoice::Fedramp,
    ];
    match key {
        KeyCode::Up => {
            if app.tenable_endpoint_cursor > 0 {
                app.tenable_endpoint_cursor -= 1;
                app.tenable_endpoint = OPTIONS[app.tenable_endpoint_cursor];
            }
        }
        KeyCode::Down => {
            if app.tenable_endpoint_cursor + 1 < OPTIONS.len() {
                app.tenable_endpoint_cursor += 1;
                app.tenable_endpoint = OPTIONS[app.tenable_endpoint_cursor];
            }
        }
        KeyCode::Enter | KeyCode::Char(' ') => {
            app.tenable_endpoint = OPTIONS[app.tenable_endpoint_cursor];
            if app.validate_current() {
                app.next_screen();
            }
        }
        KeyCode::Esc => app.prev_screen(),
        _ => {}
    }
}
