use ratatui::layout::{Alignment, Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, Paragraph};
use ratatui::Frame;

use super::{App, CollectorFocus, CollectorState, Feature, Screen, COLLECTOR_CATEGORIES};

mod collectors;
mod confirm;
mod results;
mod running;
mod setup;
mod widgets;

use self::widgets::draw_error_banner;

// ═══════════════════════════════════════════════════════════════════════════
// Color palette — RGB true color
// ═══════════════════════════════════════════════════════════════════════════

// Background layers
const BG_DARK: Color = Color::Rgb(15, 17, 26);
const BG_MAIN: Color = Color::Rgb(24, 28, 39);
const BG_ELEVATED: Color = Color::Rgb(35, 40, 55);
const BG_SELECTED: Color = Color::Rgb(45, 52, 70);

// Primary accent — teal / sky
const CYAN: Color = Color::Rgb(80, 200, 255);
const CYAN_DIM: Color = Color::Rgb(40, 100, 140);

// Secondary accent — warm amber
const AMBER: Color = Color::Rgb(255, 195, 55);

// Semantic
const GREEN: Color = Color::Rgb(72, 213, 150);
const RED: Color = Color::Rgb(245, 108, 108);
const RED_BG: Color = Color::Rgb(60, 30, 30);
const PURPLE: Color = Color::Rgb(160, 140, 245);
const TEAL: Color = Color::Rgb(50, 180, 200);

// Text hierarchy
const TEXT_BRIGHT: Color = Color::Rgb(234, 238, 245);
const TEXT_NORMAL: Color = Color::Rgb(169, 177, 190);
const TEXT_DIM: Color = Color::Rgb(90, 98, 112);

// Borders
const BORDER_SUBTLE: Color = Color::Rgb(50, 56, 72);

// ═══════════════════════════════════════════════════════════════════════════
// Logo
// ═══════════════════════════════════════════════════════════════════════════

const LOGO: &[&str] = &[
    r" ██████╗ ██████╗  █████╗ ██████╗ ██████╗ ███████╗██████╗ ",
    r"██╔════╝ ██╔══██╗██╔══██╗██╔══██╗██╔══██╗██╔════╝██╔══██╗",
    r"██║  ███╗██████╔╝███████║██████╔╝██████╔╝█████╗  ██████╔╝",
    r"██║   ██║██╔══██╗██╔══██║██╔══██╗██╔══██╗██╔══╝  ██╔══██╗",
    r"╚██████╔╝██║  ██║██║  ██║██████╔╝██████╔╝███████╗██║  ██║",
    r" ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ ╚═════╝ ╚══════╝╚═╝  ╚═╝",
];

const LOGO_COLORS: &[Color] = &[CYAN, CYAN, TEAL, TEAL, PURPLE, PURPLE];

// ═══════════════════════════════════════════════════════════════════════════
// Spinner
// ═══════════════════════════════════════════════════════════════════════════

const SPINNER_FRAMES: &[&str] = &["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];

// ═══════════════════════════════════════════════════════════════════════════
// Step definitions
// ═══════════════════════════════════════════════════════════════════════════

const STEPS_ACCOUNTS: &[&str] = &[
    "Account",
    "Dates",
    "Collectors",
    "Options",
    "Confirm",
    "Run",
];
const STEPS_LEGACY: &[&str] = &[
    "Profile",
    "Region",
    "Dates",
    "Collectors",
    "Options",
    "Confirm",
    "Run",
];
const STEPS_INV_ACCOUNTS: &[&str] = &["Account", "Dates", "Inventory", "Options", "Confirm", "Run"];
const STEPS_INV_LEGACY: &[&str] = &[
    "Profile",
    "Region",
    "Dates",
    "Inventory",
    "Options",
    "Confirm",
    "Run",
];
const STEPS_POAM: &[&str] = &["Account", "Region", "Year", "Month", "Confirm", "Run"];
const STEPS_POAM_NO_ACCOUNTS: &[&str] = &["Region", "Year", "Month", "Confirm", "Run"];

fn screen_to_step(screen: &Screen, has_accounts: bool, feature: &Feature) -> Option<usize> {
    match feature {
        Feature::Collectors => {
            if has_accounts {
                match screen {
                    Screen::SelectAccount => Some(0),
                    Screen::SetDates => Some(1),
                    Screen::SelectCollectors => Some(2),
                    Screen::SetOptions => Some(3),
                    Screen::Confirm => Some(4),
                    Screen::Running => Some(5),
                    _ => None,
                }
            } else {
                match screen {
                    Screen::SelectProfile => Some(0),
                    Screen::SelectRegion => Some(1),
                    Screen::SetDates => Some(2),
                    Screen::SelectCollectors => Some(3),
                    Screen::SetOptions => Some(4),
                    Screen::Confirm => Some(5),
                    Screen::Running => Some(6),
                    _ => None,
                }
            }
        }
        Feature::Inventory => {
            if has_accounts {
                match screen {
                    Screen::SelectAccount => Some(0),
                    Screen::SetDates => Some(1),
                    Screen::Inventory => Some(2),
                    Screen::SetOptions => Some(3),
                    Screen::Confirm => Some(4),
                    Screen::Running => Some(5),
                    _ => None,
                }
            } else {
                match screen {
                    Screen::SelectProfile => Some(0),
                    Screen::SelectRegion => Some(1),
                    Screen::SetDates => Some(2),
                    Screen::Inventory => Some(3),
                    Screen::SetOptions => Some(4),
                    Screen::Confirm => Some(5),
                    Screen::Running => Some(6),
                    _ => None,
                }
            }
        }
        Feature::Poam => {
            if has_accounts {
                match screen {
                    Screen::PoamAccount => Some(0),
                    Screen::PoamRegion => Some(1),
                    Screen::PoamYear => Some(2),
                    Screen::PoamMonth => Some(3),
                    Screen::Confirm => Some(4),
                    Screen::Running => Some(5),
                    _ => None,
                }
            } else {
                match screen {
                    Screen::PoamRegion => Some(0),
                    Screen::PoamYear => Some(1),
                    Screen::PoamMonth => Some(2),
                    Screen::Confirm => Some(3),
                    Screen::Running => Some(4),
                    _ => None,
                }
            }
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Entry point
// ═══════════════════════════════════════════════════════════════════════════

pub fn draw(f: &mut Frame, app: &App) {
    let area = f.area();

    // Deep background fill
    f.render_widget(Block::default().style(Style::default().bg(BG_DARK)), area);

    // Outer double-border frame
    let outer_block = Block::bordered()
        .border_type(BorderType::Double)
        .border_style(Style::default().fg(CYAN_DIM))
        .style(Style::default().bg(BG_MAIN));
    let inner = outer_block.inner(area);
    f.render_widget(outer_block, area);

    let show_steps = !matches!(
        app.screen,
        Screen::Welcome | Screen::FeatureSelection | Screen::Preparing | Screen::Results
    );
    let step_height = if show_steps { 2 } else { 0 };

    let layout = Layout::vertical([
        Constraint::Length(1),                              // top padding
        Constraint::Length(1),                              // header
        Constraint::Length(1),                              // separator
        Constraint::Length(step_height),                    // step indicator
        Constraint::Length(if show_steps { 1 } else { 0 }), // content separator
        Constraint::Fill(1),                                // content
        Constraint::Length(1),                              // content separator
        Constraint::Length(1),                              // footer
        Constraint::Length(1),                              // bottom padding
    ])
    .split(inner);

    // Header
    let step_info = screen_to_step(&app.screen, app.has_accounts(), &app.selected_feature);
    let steps = match app.selected_feature {
        Feature::Collectors => {
            if app.has_accounts() {
                STEPS_ACCOUNTS
            } else {
                STEPS_LEGACY
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

    // Separator
    draw_separator(f, layout[2]);

    // Step indicator
    if show_steps {
        if let Some(step) = step_info {
            draw_step_indicator(f, layout[3], step, steps);
        }
        draw_separator(f, layout[4]);
    }

    // Content
    let content = layout[5];
    match app.screen {
        Screen::Welcome => setup::draw_welcome(f, content),
        Screen::FeatureSelection => setup::draw_feature_selection(f, content, app),
        Screen::SelectAccount => setup::draw_select_account(f, content, app),
        Screen::SelectProfile => setup::draw_profile(f, content, app),
        Screen::SelectRegion => setup::draw_region(f, content, app),
        Screen::PoamAccount => setup::draw_poam_account(f, content, app),
        Screen::PoamRegion => setup::draw_poam_region(f, content, app),
        Screen::PoamYear => setup::draw_poam_year(f, content, app),
        Screen::PoamMonth => setup::draw_poam_month(f, content, app),
        Screen::SetDates => setup::draw_dates(f, content, app),
        Screen::Inventory => setup::draw_inventory_selection(f, content, app),
        Screen::SelectCollectors => collectors::draw_collectors(f, content, app),
        Screen::SetOptions => collectors::draw_options(f, content, app),
        Screen::Confirm => confirm::draw_confirm(f, content, app),
        Screen::Preparing => confirm::draw_preparing(f, content, app),
        Screen::Running => running::draw_running(f, content, app),
        Screen::Results => results::draw_results(f, content, app),
    }

    // Bottom separator + footer
    draw_separator(f, layout[6]);
    draw_footer(f, layout[7], &get_hints(&app.screen));

    // Error banner overlays footer
    if let Some(ref msg) = app.error_msg {
        draw_error_banner(f, area, msg);
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Frame components
// ═══════════════════════════════════════════════════════════════════════════

fn draw_header(f: &mut Frame, area: Rect, step: Option<(usize, usize)>, screen: &Screen) {
    let left = vec![
        Span::styled(" ◆ ", Style::default().fg(CYAN)),
        Span::styled(
            "THE GRABBER",
            Style::default().fg(CYAN).add_modifier(Modifier::BOLD),
        ),
        Span::styled("   ", Style::default()),
        Span::styled(
            "AWS Compliance Evidence Collector",
            Style::default().fg(TEXT_NORMAL),
        ),
    ];

    let right = match screen {
        Screen::Running => vec![
            Span::styled(
                "Collecting...",
                Style::default().fg(AMBER).add_modifier(Modifier::BOLD),
            ),
            Span::raw("  "),
        ],
        Screen::Results => vec![
            Span::styled("✓ ", Style::default().fg(GREEN)),
            Span::styled(
                "Complete",
                Style::default().fg(GREEN).add_modifier(Modifier::BOLD),
            ),
            Span::raw("  "),
        ],
        _ => {
            if let Some((current, total)) = step {
                vec![
                    Span::styled("Step ", Style::default().fg(TEXT_DIM)),
                    Span::styled(
                        current.to_string(),
                        Style::default().fg(AMBER).add_modifier(Modifier::BOLD),
                    ),
                    Span::styled(format!(" of {total}"), Style::default().fg(TEXT_DIM)),
                    Span::raw("  "),
                ]
            } else {
                vec![Span::raw("  ")]
            }
        }
    };

    // Render left-aligned and right-aligned on same line
    let cols = Layout::horizontal([Constraint::Fill(1), Constraint::Min(20)]).split(area);
    f.render_widget(Paragraph::new(Line::from(left)), cols[0]);
    f.render_widget(
        Paragraph::new(Line::from(right)).alignment(Alignment::Right),
        cols[1],
    );
}

fn draw_step_indicator(f: &mut Frame, area: Rect, current: usize, steps: &[&str]) {
    // Line 1: labels with dots
    let mut spans = vec![Span::raw("   ")];
    for (i, label) in steps.iter().enumerate() {
        let (icon, style) = if i < current {
            ("● ", Style::default().fg(GREEN))
        } else if i == current {
            (
                "◉ ",
                Style::default().fg(AMBER).add_modifier(Modifier::BOLD),
            )
        } else {
            ("○ ", Style::default().fg(TEXT_DIM))
        };
        spans.push(Span::styled(icon, style));
        spans.push(Span::styled(*label, style));
        if i < steps.len() - 1 {
            spans.push(Span::styled("   ", Style::default()));
        }
    }
    f.render_widget(Paragraph::new(Line::from(spans)), area);

    // Line 2: progress bar
    if area.height > 1 {
        let bar_area = Rect {
            y: area.y + 1,
            height: 1,
            ..area
        };
        let bar_width = area.width.saturating_sub(6) as usize;
        if steps.len() > 1 && bar_width > 0 {
            let segment = bar_width / steps.len();
            let filled = segment * current + segment / 2;
            let mut bar_spans = vec![Span::raw("   ")];
            let bar_str: String = (0..bar_width)
                .map(|i| if i == filled { '●' } else { '━' })
                .collect();
            // Color the bar: green for completed, amber for current pos, dim for future
            for (i, ch) in bar_str.chars().enumerate() {
                let color = if ch == '●' {
                    AMBER
                } else if i < filled {
                    GREEN
                } else {
                    BORDER_SUBTLE
                };
                bar_spans.push(Span::styled(ch.to_string(), Style::default().fg(color)));
            }
            f.render_widget(Paragraph::new(Line::from(bar_spans)), bar_area);
        }
    }
}

fn draw_separator(f: &mut Frame, area: Rect) {
    let width = area.width.saturating_sub(4) as usize;
    let line = "┄".repeat(width);
    f.render_widget(
        Paragraph::new(Span::styled(
            format!("  {line}"),
            Style::default().fg(BORDER_SUBTLE),
        )),
        area,
    );
}

fn draw_footer(f: &mut Frame, area: Rect, hints: &[(&str, &str)]) {
    let mut spans = vec![Span::raw("  ")];
    for (key, desc) in hints {
        spans.push(Span::styled(
            format!(" {key} "),
            Style::default()
                .fg(TEXT_BRIGHT)
                .bg(BG_ELEVATED)
                .add_modifier(Modifier::BOLD),
        ));
        spans.push(Span::styled(
            format!(" {desc}  "),
            Style::default().fg(TEXT_DIM),
        ));
    }

    let cols = Layout::horizontal([Constraint::Fill(1), Constraint::Min(12)]).split(area);
    f.render_widget(Paragraph::new(Line::from(spans)), cols[0]);
    f.render_widget(
        Paragraph::new(Span::styled("v0.1.0  ", Style::default().fg(TEXT_DIM)))
            .alignment(Alignment::Right),
        cols[1],
    );
}

fn get_hints(screen: &Screen) -> Vec<(&'static str, &'static str)> {
    match screen {
        Screen::Welcome => vec![("⏎", "Begin"), ("Esc", "Quit")],
        Screen::FeatureSelection => vec![("↑↓", "Navigate"), ("⏎", "Select"), ("Esc", "Back")],
        Screen::SelectAccount => vec![
            ("↑↓", "Navigate"),
            ("␣", "Toggle"),
            ("a", "All"),
            ("d", "None"),
            ("⏎", "Confirm"),
            ("Esc", "Back"),
        ],
        Screen::SelectProfile => vec![("↑↓", "Navigate"), ("⏎", "Select"), ("Esc", "Back")],
        Screen::SelectRegion => vec![
            ("↑↓", "Navigate"),
            ("↓", "Custom"),
            ("⏎", "Confirm"),
            ("Esc", "Back"),
        ],
        Screen::PoamAccount => vec![("↑↓", "Navigate"), ("⏎", "Confirm"), ("Esc", "Back")],
        Screen::PoamRegion => vec![("↑↓", "Navigate"), ("⏎", "Confirm"), ("Esc", "Back")],
        Screen::PoamYear => vec![
            ("0-9", "Type Year"),
            ("⌫", "Delete"),
            ("⏎", "Confirm"),
            ("Esc", "Back"),
        ],
        Screen::PoamMonth => vec![("↑↓", "Navigate"), ("⏎", "Confirm"), ("Esc", "Back")],
        Screen::SetDates => vec![("↑↓", "Navigate"), ("⏎", "Confirm"), ("Esc", "Back")],
        Screen::Inventory => vec![
            ("↑↓", "Navigate"),
            ("␣", "Toggle"),
            ("a", "Select All"),
            ("d", "Deselect All"),
            ("⏎", "Confirm"),
            ("Esc", "Back"),
        ],
        Screen::SelectCollectors => vec![
            ("↑↓", "Navigate"),
            ("␣", "Toggle"),
            ("a", "Select All"),
            ("d", "Deselect All"),
            ("⏎", "Confirm"),
            ("Esc", "Back"),
        ],
        Screen::SetOptions => vec![
            ("⇥", "Switch Field"),
            ("↑↓", "Navigate Regions"),
            ("␣", "Toggle"),
            ("⏎", "Confirm"),
            ("Esc", "Back"),
        ],
        Screen::Confirm => vec![("⏎", "Start"), ("Esc", "Back")],
        Screen::Preparing => vec![],
        Screen::Running => vec![],
        Screen::Results => vec![("n", "New Collection"), ("q", "Quit"), ("Esc", "Exit")],
    }
}
