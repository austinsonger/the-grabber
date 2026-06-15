use std::io;

use anyhow::Result;
use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use ratatui::backend::CrosstermBackend;
use ratatui::Terminal;

use super::{App, CollectorFocus, Feature, Screen, COLLECTOR_CATEGORIES};

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
        Screen::Inventory => handle_inventory(app, key),
        Screen::SetOptions => handle_set_options(app, key),
        Screen::Confirm => return handle_confirm(app, key),
        Screen::Running | Screen::Preparing => {}
        Screen::Results => return handle_results(app, key),
        Screen::ProviderSelection => handle_provider_selection(app, key),
        Screen::TenableEndpoint => handle_tenable_endpoint(app, key),
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
                Feature::Collectors => Feature::Poam,
                Feature::Inventory => Feature::Collectors,
                Feature::Poam => Feature::Inventory,
            };
        }
        KeyCode::Down | KeyCode::Right => {
            app.selected_feature = match app.selected_feature {
                Feature::Collectors => Feature::Inventory,
                Feature::Inventory => Feature::Poam,
                Feature::Poam => Feature::Collectors,
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
            if digit > 0 && digit <= COLLECTOR_CATEGORIES.len() {
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

fn handle_set_options(app: &mut App, key: KeyCode) {
    let region_field = if app.selected_feature == Feature::Inventory {
        6
    } else {
        7
    };

    match key {
        KeyCode::Tab => {
            let total = if app.selected_feature == Feature::Inventory {
                7
            } else {
                8
            };
            app.options_field = (app.options_field + 1) % total;
        }
        KeyCode::Char(' ') if app.options_field == 1 => {
            app.include_raw = !app.include_raw;
        }
        KeyCode::Char(' ') if app.options_field == 2 => {
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
                app.skip_run_manifest = !app.skip_run_manifest;
            }
        }
        KeyCode::Char(' ')
            if app.options_field == 6 && app.selected_feature == Feature::Collectors =>
        {
            app.skip_chain_of_custody = !app.skip_chain_of_custody;
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

fn handle_results(_app: &mut App, key: KeyCode) -> Action {
    match key {
        KeyCode::Char('q') | KeyCode::Esc => Action::Quit,
        KeyCode::Char('n') => Action::NewCollection,
        _ => Action::Continue,
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

fn handle_provider_selection(app: &mut App, key: KeyCode) {
    use crate::providers::CloudProvider;
    // Keep this list in sync with `draw_provider_selection` in src/tui/ui/account_screens.rs —
    // both must enumerate the same providers in the same order or arrow-key navigation
    // will desynchronize from the rendered tiles.
    let providers: Vec<CloudProvider> = {
        let mut v = vec![CloudProvider::Aws];
        #[cfg(feature = "azure")]
        v.push(CloudProvider::Azure);
        #[cfg(feature = "gcp")]
        v.push(CloudProvider::Gcp);
        #[cfg(feature = "tenable")]
        v.push(CloudProvider::Tenable);
        #[cfg(feature = "okta")]
        v.push(CloudProvider::Okta);
        #[cfg(feature = "jira")]
        v.push(CloudProvider::Jira);
        v
    };
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
