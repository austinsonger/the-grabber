use ratatui::layout::{Constraint, Layout};
use ratatui::style::Style;
use ratatui::widgets::{Block, BorderType};
use ratatui::Frame;

use super::{App, CollectorFocus, CollectorState, Feature, Screen};

mod account_screens;
mod collectors;
mod confirm;
mod frame;
mod options;
mod poam_screens;
mod results;
mod running;
mod setup;
pub(super) mod theme;
mod widgets;

use self::frame::{
    draw_footer, draw_header, draw_separator, draw_step_indicator, get_hints, screen_to_step,
    STEPS_INV_ACCOUNTS, STEPS_INV_LEGACY, STEPS_POAM, STEPS_POAM_NO_ACCOUNTS,
    STEPS_PROVIDER_ACCOUNTS, STEPS_PROVIDER_LEGACY, STEPS_TENABLE,
};
use self::theme::{BG_DARK, BG_MAIN, CYAN_DIM};
use self::widgets::draw_error_banner;

// Re-export theme constants so sub-modules can continue using `super::*` imports
use self::theme::{
    AMBER, BG_ELEVATED, BG_SELECTED, BORDER_SUBTLE, CYAN, GREEN, LOGO, LOGO_COLORS, PURPLE, RED,
    RED_BG, SPINNER_FRAMES, TEXT_BRIGHT, TEXT_DIM, TEXT_NORMAL,
};
// Re-export state items sub-modules reference via super::
use crate::tui::state::COLLECTOR_CATEGORIES;

pub fn draw(f: &mut Frame, app: &App) {
    let area = f.area();

    f.render_widget(Block::default().style(Style::default().bg(BG_DARK)), area);

    let outer_block = Block::bordered()
        .border_type(BorderType::Double)
        .border_style(Style::default().fg(CYAN_DIM))
        .style(Style::default().bg(BG_MAIN));
    let inner = outer_block.inner(area);
    f.render_widget(outer_block, area);

    let show_steps = !matches!(
        app.screen,
        Screen::Welcome
            | Screen::FeatureSelection
            | Screen::ProviderSelection
            | Screen::Preparing
            | Screen::Results
    );
    let step_height = if show_steps { 2 } else { 0 };

    let layout = Layout::vertical([
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Length(step_height),
        Constraint::Length(if show_steps { 1 } else { 0 }),
        Constraint::Fill(1),
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Length(1),
    ])
    .split(inner);

    let step_info = screen_to_step(
        &app.screen,
        app.has_accounts(),
        &app.selected_feature,
        app.selected_provider,
    );
    let steps = match app.selected_feature {
        Feature::Collectors => {
            use crate::providers::CloudProvider;
            if app.selected_provider == CloudProvider::Tenable {
                STEPS_TENABLE
            } else if app.has_accounts() {
                STEPS_PROVIDER_ACCOUNTS
            } else {
                STEPS_PROVIDER_LEGACY
            }
        }
        Feature::Inventory => {
            if app.has_accounts() {
                STEPS_INV_ACCOUNTS
            } else {
                STEPS_INV_LEGACY
            }
        }
        Feature::Poam => {
            if app.has_accounts() {
                STEPS_POAM
            } else {
                STEPS_POAM_NO_ACCOUNTS
            }
        }
    };

    draw_header(
        f,
        layout[1],
        step_info.map(|s| (s + 1, steps.len())),
        &app.screen,
    );
    draw_separator(f, layout[2]);

    if show_steps {
        if let Some(step) = step_info {
            draw_step_indicator(f, layout[3], step, steps);
        }
        draw_separator(f, layout[4]);
    }

    let content = layout[5];
    match app.screen {
        Screen::Welcome => setup::draw_welcome(f, content),
        Screen::FeatureSelection => setup::draw_feature_selection(f, content, app),
        Screen::ProviderSelection => account_screens::draw_provider_selection(f, content, app),
        Screen::SelectAccount => account_screens::draw_select_account(f, content, app),
        Screen::SelectProfile => account_screens::draw_profile(f, content, app),
        Screen::SelectRegion => account_screens::draw_region(f, content, app),
        Screen::PoamAccount => poam_screens::draw_poam_account(f, content, app),
        Screen::PoamRegion => poam_screens::draw_poam_region(f, content, app),
        Screen::PoamYear => poam_screens::draw_poam_year(f, content, app),
        Screen::PoamMonth => poam_screens::draw_poam_month(f, content, app),
        Screen::SetDates => setup::draw_dates(f, content, app),
        Screen::Inventory => setup::draw_inventory_selection(f, content, app),
        Screen::SelectCollectors => collectors::draw_collectors(f, content, app),
        Screen::SetOptions => options::draw_options(f, content, app),
        Screen::Confirm => confirm::draw_confirm(f, content, app),
        Screen::Preparing => confirm::draw_preparing(f, content, app),
        Screen::Running => running::draw_running(f, content, app),
        Screen::Results => results::draw_results(f, content, app),
    }

    draw_separator(f, layout[6]);
    draw_footer(f, layout[7], &get_hints(&app.screen));

    if let Some(ref msg) = app.error_msg {
        draw_error_banner(f, area, msg);
    }
}
