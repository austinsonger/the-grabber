use ratatui::layout::{Alignment, Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::{
    Block, BorderType, Clear, Gauge, List, ListItem, ListState, Padding,
    Paragraph,
};
use ratatui::Frame;

use super::{App, CollectorState, Feature, Screen};

// ═══════════════════════════════════════════════════════════════════════════
// Color palette — RGB true color
// ═══════════════════════════════════════════════════════════════════════════

// Background layers
const BG_DARK:      Color = Color::Rgb(15, 17, 26);
const BG_MAIN:      Color = Color::Rgb(24, 28, 39);
const BG_ELEVATED:  Color = Color::Rgb(35, 40, 55);
const BG_SELECTED:  Color = Color::Rgb(45, 52, 70);

// Primary accent — teal / sky
const CYAN:         Color = Color::Rgb(80, 200, 255);
const CYAN_DIM:     Color = Color::Rgb(40, 100, 140);

// Secondary accent — warm amber
const AMBER:        Color = Color::Rgb(255, 195, 55);

// Semantic
const GREEN:        Color = Color::Rgb(72, 213, 150);
const RED:          Color = Color::Rgb(245, 108, 108);
const RED_BG:       Color = Color::Rgb(60, 30, 30);
const PURPLE:       Color = Color::Rgb(160, 140, 245);
const TEAL:         Color = Color::Rgb(50, 180, 200);

// Text hierarchy
const TEXT_BRIGHT:   Color = Color::Rgb(234, 238, 245);
const TEXT_NORMAL:   Color = Color::Rgb(169, 177, 190);
const TEXT_DIM:      Color = Color::Rgb(90, 98, 112);

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

const STEPS_ACCOUNTS: &[&str] = &["Account", "Dates", "Collectors", "Options", "Confirm", "Run"];
const STEPS_LEGACY:   &[&str] = &["Profile", "Region", "Dates", "Collectors", "Options", "Confirm", "Run"];
const STEPS_INV_ACCOUNTS: &[&str] = &["Account", "Dates", "Inventory", "Options", "Confirm", "Run"];
const STEPS_INV_LEGACY:   &[&str] = &["Profile", "Region", "Dates", "Inventory", "Options", "Confirm", "Run"];

fn screen_to_step(screen: &Screen, has_accounts: bool, feature: &Feature) -> Option<usize> {
    match feature {
        Feature::Collectors => {
            if has_accounts {
                match screen {
                    Screen::SelectAccount    => Some(0),
                    Screen::SetDates         => Some(1),
                    Screen::SelectCollectors => Some(2),
                    Screen::SetOptions       => Some(3),
                    Screen::Confirm          => Some(4),
                    Screen::Running          => Some(5),
                    _ => None,
                }
            } else {
                match screen {
                    Screen::SelectProfile    => Some(0),
                    Screen::SelectRegion     => Some(1),
                    Screen::SetDates         => Some(2),
                    Screen::SelectCollectors => Some(3),
                    Screen::SetOptions       => Some(4),
                    Screen::Confirm          => Some(5),
                    Screen::Running          => Some(6),
                    _ => None,
                }
            }
        }
        Feature::Inventory => {
            if has_accounts {
                match screen {
                    Screen::SelectAccount => Some(0),
                    Screen::SetDates      => Some(1),
                    Screen::Inventory     => Some(2),
                    Screen::SetOptions    => Some(3),
                    Screen::Confirm       => Some(4),
                    Screen::Running       => Some(5),
                    _ => None,
                }
            } else {
                match screen {
                    Screen::SelectProfile => Some(0),
                    Screen::SelectRegion  => Some(1),
                    Screen::SetDates      => Some(2),
                    Screen::Inventory     => Some(3),
                    Screen::SetOptions    => Some(4),
                    Screen::Confirm       => Some(5),
                    Screen::Running       => Some(6),
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
    f.render_widget(
        Block::default().style(Style::default().bg(BG_DARK)),
        area,
    );

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
        Constraint::Length(1),           // top padding
        Constraint::Length(1),           // header
        Constraint::Length(1),           // separator
        Constraint::Length(step_height), // step indicator
        Constraint::Length(if show_steps { 1 } else { 0 }), // content separator
        Constraint::Fill(1),            // content
        Constraint::Length(1),           // content separator
        Constraint::Length(1),           // footer
        Constraint::Length(1),           // bottom padding
    ])
    .split(inner);

    // Header
    let step_info = screen_to_step(&app.screen, app.has_accounts(), &app.selected_feature);
    let steps = match app.selected_feature {
        Feature::Collectors => {
            if app.has_accounts() { STEPS_ACCOUNTS } else { STEPS_LEGACY }
        }
        Feature::Inventory => {
            if app.has_accounts() { STEPS_INV_ACCOUNTS } else { STEPS_INV_LEGACY }
        }
    };
    draw_header(f, layout[1], step_info.map(|s| (s + 1, steps.len())), &app.screen);

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
        Screen::Welcome          => draw_welcome(f, content),
        Screen::FeatureSelection => draw_feature_selection(f, content, app),
        Screen::SelectAccount    => draw_select_account(f, content, app),
        Screen::SelectProfile    => draw_profile(f, content, app),
        Screen::SelectRegion     => draw_region(f, content, app),
        Screen::SetDates         => draw_dates(f, content, app),
        Screen::Inventory        => draw_inventory_selection(f, content, app),
        Screen::SelectCollectors => draw_collectors(f, content, app),
        Screen::SetOptions       => draw_options(f, content, app),
        Screen::Confirm          => draw_confirm(f, content, app),
        Screen::Preparing        => draw_preparing(f, content, app),
        Screen::Running          => draw_running(f, content, app),
        Screen::Results          => draw_results(f, content, app),
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
        Span::styled("THE GRABBER", Style::default().fg(CYAN).add_modifier(Modifier::BOLD)),
        Span::styled("   ", Style::default()),
        Span::styled(
            "AWS Compliance Evidence Collector",
            Style::default().fg(TEXT_NORMAL),
        ),
    ];

    let right = match screen {
        Screen::Running => vec![
            Span::styled("Collecting...", Style::default().fg(AMBER).add_modifier(Modifier::BOLD)),
            Span::raw("  "),
        ],
        Screen::Results => vec![
            Span::styled("✓ ", Style::default().fg(GREEN)),
            Span::styled("Complete", Style::default().fg(GREEN).add_modifier(Modifier::BOLD)),
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
            ("◉ ", Style::default().fg(AMBER).add_modifier(Modifier::BOLD))
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
            let bar_str: String = (0..bar_width).map(|i| {
                if i == filled { '●' } else { '━' }
            }).collect();
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
            Style::default().fg(TEXT_BRIGHT).bg(BG_ELEVATED).add_modifier(Modifier::BOLD),
        ));
        spans.push(Span::styled(format!(" {desc}  "), Style::default().fg(TEXT_DIM)));
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
        Screen::Welcome          => vec![("⏎", "Begin"), ("Esc", "Quit")],
        Screen::FeatureSelection => vec![("↑↓", "Navigate"), ("⏎", "Select"), ("Esc", "Quit")],
        Screen::SelectAccount    => vec![("↑↓", "Navigate"), ("␣", "Toggle"), ("a", "All"), ("d", "None"), ("⏎", "Confirm"), ("Esc", "Quit")],
        Screen::SelectProfile    => vec![("↑↓", "Navigate"), ("⏎", "Select"), ("Esc", "Back")],
        Screen::SelectRegion     => vec![("↑↓", "Navigate"), ("↓", "Custom"), ("⏎", "Confirm"), ("Esc", "Back")],
        Screen::SetDates         => vec![("↑↓", "Navigate"), ("⏎", "Confirm"), ("Esc", "Back")],
        Screen::Inventory        => vec![("↑↓", "Navigate"), ("␣", "Toggle"), ("a", "Select All"), ("d", "Deselect All"), ("⏎", "Confirm"), ("Esc", "Back")],
        Screen::SelectCollectors => vec![("↑↓", "Navigate"), ("␣", "Toggle"), ("a", "Select All"), ("d", "Deselect All"), ("⏎", "Confirm"), ("Esc", "Back")],
        Screen::SetOptions       => vec![("⇥", "Switch Field"), ("↑↓", "Navigate Regions"), ("␣", "Toggle"), ("⏎", "Confirm"), ("Esc", "Back")],
        Screen::Confirm          => vec![("⏎", "Start"), ("Esc", "Back")],
        Screen::Preparing        => vec![],
        Screen::Running          => vec![],
        Screen::Results          => vec![("n", "New Collection"), ("q", "Quit"), ("Esc", "Exit")],
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Welcome
// ═══════════════════════════════════════════════════════════════════════════

fn draw_welcome(f: &mut Frame, area: Rect) {
    let chunks = Layout::vertical([
        Constraint::Fill(1),
        Constraint::Length(6),  // logo
        Constraint::Length(1),  // blank
        Constraint::Length(1),  // decorative divider
        Constraint::Length(1),  // blank
        Constraint::Length(1),  // title
        Constraint::Length(1),  // blank
        Constraint::Length(2),  // description
        Constraint::Length(2),  // blank
        Constraint::Length(1),  // CTA
        Constraint::Fill(1),
    ])
    .split(area);

    // Logo with gradient colors
    let logo_lines: Vec<Line> = LOGO
        .iter()
        .enumerate()
        .map(|(i, line)| {
            let color = LOGO_COLORS.get(i).copied().unwrap_or(CYAN);
            Line::from(Span::styled(*line, Style::default().fg(color)))
        })
        .collect();
    f.render_widget(
        Paragraph::new(Text::from(logo_lines)).alignment(Alignment::Center),
        chunks[1],
    );

    // Decorative divider
    f.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled("──────── ", Style::default().fg(CYAN_DIM)),
            Span::styled("◆", Style::default().fg(CYAN)),
            Span::styled(" ────────", Style::default().fg(CYAN_DIM)),
        ]))
        .alignment(Alignment::Center),
        chunks[3],
    );

    // Title
    f.render_widget(
        Paragraph::new(Span::styled(
            "The Grabber",
            Style::default().fg(TEXT_BRIGHT).add_modifier(Modifier::BOLD),
        ))
        .alignment(Alignment::Center),
        chunks[5],
    );

    // Description
    f.render_widget(
        Paragraph::new(Text::from(vec![
            Line::from(Span::styled(
                "Collect audit evidence from CloudTrail, AWS Backup,",
                Style::default().fg(TEXT_NORMAL),
            )),
            Line::from(Span::styled(
                "RDS Snapshots, S3 logs, and 120+ AWS service configs.",
                Style::default().fg(TEXT_NORMAL),
            )),
        ]))
        .alignment(Alignment::Center),
        chunks[7],
    );

    // CTA
    f.render_widget(
        Paragraph::new(Span::styled(
            "▸▸  Press Enter to begin  ◂◂",
            Style::default().fg(AMBER).add_modifier(Modifier::BOLD),
        ))
        .alignment(Alignment::Center),
        chunks[9],
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// Feature Selection
// ═══════════════════════════════════════════════════════════════════════════

fn draw_feature_selection(f: &mut Frame, area: Rect, app: &App) {
    let chunks = Layout::vertical([
        Constraint::Fill(1),
        Constraint::Length(1), // title
        Constraint::Length(1), // subtitle
        Constraint::Length(2), // blank
        Constraint::Length(5), // Collectors card
        Constraint::Length(1), // gap
        Constraint::Length(5), // Inventory card
        Constraint::Fill(1),
    ])
    .split(area);

    f.render_widget(
        Paragraph::new(Span::styled(
            "What would you like to do?",
            Style::default().fg(TEXT_BRIGHT).add_modifier(Modifier::BOLD),
        ))
        .alignment(Alignment::Center),
        chunks[1],
    );
    f.render_widget(
        Paragraph::new(Span::styled(
            "Use ↑↓ to select a feature, then press Enter",
            Style::default().fg(TEXT_DIM),
        ))
        .alignment(Alignment::Center),
        chunks[2],
    );

    let options = [
        (
            Feature::Collectors,
            "◆  Collectors",
            "Run 100+ compliance evidence collectors (CloudTrail, S3, IAM, RDS, …)",
        ),
        (
            Feature::Inventory,
            "◆  Inventory",
            "Build a unified asset-inventory CSV across selected AWS resource types",
        ),
    ];

    let card_areas = [chunks[4], chunks[6]];
    for (idx, (feature, label, desc)) in options.iter().enumerate() {
        let selected = app.selected_feature == *feature;
        let border_style = if selected {
            Style::default().fg(CYAN)
        } else {
            Style::default().fg(BORDER_SUBTLE)
        };
        let label_style = if selected {
            Style::default().fg(CYAN).add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(TEXT_NORMAL)
        };

        let card_block = Block::bordered()
            .border_type(if selected { BorderType::Thick } else { BorderType::Plain })
            .border_style(border_style)
            .style(Style::default().bg(if selected { BG_ELEVATED } else { BG_MAIN }));
        let inner = card_block.inner(card_areas[idx]);
        f.render_widget(card_block, card_areas[idx]);

        let inner_layout = Layout::vertical([
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Length(1),
        ])
        .split(inner);

        let indicator = if selected { " ▶ " } else { "   " };
        f.render_widget(
            Paragraph::new(Line::from(vec![
                Span::styled(indicator, Style::default().fg(AMBER)),
                Span::styled(*label, label_style),
            ])),
            inner_layout[0],
        );
        f.render_widget(
            Paragraph::new(Span::styled(*desc, Style::default().fg(TEXT_DIM))),
            inner_layout[2],
        );
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Inventory Asset-Type Selection
// ═══════════════════════════════════════════════════════════════════════════

fn draw_inventory_selection(f: &mut Frame, area: Rect, app: &App) {
    let chunks = Layout::vertical([
        Constraint::Length(2),
        Constraint::Fill(1),
    ])
    .split(content_inset(area));

    let count_text = format!(
        "Select AWS asset type(s) for the inventory CSV:  ({} of {} selected)",
        app.inventory_selected.len(),
        app.inventory_items.len(),
    );
    f.render_widget(
        Paragraph::new(Span::styled(count_text, Style::default().fg(TEXT_DIM))),
        chunks[0],
    );

    let items: Vec<ListItem> = app
        .inventory_items
        .iter()
        .enumerate()
        .map(|(i, (_, label))| {
            let is_cursor = i == app.inventory_cursor;
            let is_selected = app.inventory_selected.contains(&i);

            let checkbox = if is_selected { "[✓]" } else { "[ ]" };
            let check_style = if is_selected {
                Style::default().fg(GREEN).add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(TEXT_DIM)
            };
            let label_style = if is_cursor {
                Style::default().fg(CYAN).add_modifier(Modifier::BOLD)
            } else if is_selected {
                Style::default().fg(TEXT_BRIGHT)
            } else {
                Style::default().fg(TEXT_NORMAL)
            };
            let cursor_indicator = if is_cursor { " ▶ " } else { "   " };
            let line = Line::from(vec![
                Span::styled(cursor_indicator, Style::default().fg(AMBER)),
                Span::styled(checkbox, check_style),
                Span::raw(" "),
                Span::styled(*label, label_style),
            ]);
            ListItem::new(line)
        })
        .collect();

    let list = List::new(items).block(Block::default());
    f.render_widget(list, chunks[1]);
}

// ═══════════════════════════════════════════════════════════════════════════
// Select Account (NEW)
// ═══════════════════════════════════════════════════════════════════════════

fn draw_select_account(f: &mut Frame, area: Rect, app: &App) {
    let chunks = Layout::vertical([
        Constraint::Length(2),
        Constraint::Fill(1),
    ])
    .split(content_inset(area));

    let count_text = format!(
        "Select AWS account(s) to collect evidence from:  ({} of {} selected)",
        app.selected_accounts.len(),
        app.accounts.len(),
    );
    f.render_widget(
        Paragraph::new(Span::styled(
            count_text,
            Style::default().fg(TEXT_DIM),
        )),
        chunks[0],
    );

    // Build list items: accounts + separator + "Other"
    let total_entries = app.accounts.len() + 2; // accounts + separator + "Other"
    let mut items: Vec<ListItem> = Vec::with_capacity(total_entries);

    for (i, acct) in app.accounts.iter().enumerate() {
        let at_cursor = i == app.account_cursor;
        let checked = app.selected_accounts.contains(&i);
        let cursor_icon = if at_cursor { "▸ " } else { "  " };
        let checkbox = if checked { "[x] " } else { "[ ] " };

        let name_style = if at_cursor {
            Style::default().fg(AMBER).add_modifier(Modifier::BOLD).bg(BG_SELECTED)
        } else {
            Style::default().fg(TEXT_BRIGHT).add_modifier(Modifier::BOLD)
        };

        let checkbox_style = if checked {
            Style::default().fg(GREEN)
        } else {
            Style::default().fg(TEXT_DIM)
        };

        let detail = format!(
            "      {} · {} · {}",
            acct.account_id.as_deref().unwrap_or(""),
            acct.profile,
            acct.region.as_deref().unwrap_or("us-east-1"),
        );

        items.push(ListItem::new(Text::from(vec![
            Line::from(vec![
                Span::styled(cursor_icon, Style::default().fg(AMBER)),
                Span::styled(checkbox, checkbox_style),
                Span::styled(&acct.name, name_style),
            ]),
            Line::from(Span::styled(detail, Style::default().fg(TEXT_DIM))),
            Line::raw(""),
        ])));
    }

    // Separator line
    let sep_width = chunks[1].width.saturating_sub(6) as usize;
    items.push(ListItem::new(Line::from(Span::styled(
        format!("  {}", "┄".repeat(sep_width)),
        Style::default().fg(BORDER_SUBTLE),
    ))));

    // "Other" option
    let other_selected = app.account_cursor == app.accounts.len();
    let other_icon = if other_selected { "▸ " } else { "  " };
    let other_style = if other_selected {
        Style::default().fg(AMBER).add_modifier(Modifier::BOLD).bg(BG_SELECTED)
    } else {
        Style::default().fg(TEXT_NORMAL)
    };
    items.push(ListItem::new(Text::from(vec![
        Line::from(vec![
            Span::styled(other_icon, Style::default().fg(AMBER)),
            Span::styled("Other (pick from AWS profiles)", other_style),
        ]),
        Line::from(Span::styled(
            "    Select any profile from ~/.aws/config",
            Style::default().fg(TEXT_DIM),
        )),
    ])));

    let list_block = Block::bordered()
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(BORDER_SUBTLE))
        .padding(Padding::horizontal(1));

    f.render_widget(List::new(items).block(list_block), chunks[1]);
}

// ═══════════════════════════════════════════════════════════════════════════
// Select Profile (legacy)
// ═══════════════════════════════════════════════════════════════════════════

fn draw_profile(f: &mut Frame, area: Rect, app: &App) {
    let chunks = Layout::vertical([
        Constraint::Length(2),
        Constraint::Fill(1),
    ])
    .split(content_inset(area));

    f.render_widget(
        Paragraph::new(Span::styled(
            "Select the AWS profile to use for evidence collection:",
            Style::default().fg(TEXT_DIM),
        )),
        chunks[0],
    );

    let items: Vec<ListItem> = app
        .profiles
        .iter()
        .enumerate()
        .map(|(i, p)| {
            let selected = i == app.profile_cursor;
            let icon = if selected { "▸ " } else { "  " };
            let style = if selected {
                Style::default().fg(AMBER).add_modifier(Modifier::BOLD).bg(BG_SELECTED)
            } else {
                Style::default().fg(TEXT_NORMAL)
            };
            ListItem::new(Line::from(vec![
                Span::styled(icon, Style::default().fg(AMBER)),
                Span::styled(p.as_str(), style),
            ]))
        })
        .collect();

    let mut state = ListState::default();
    state.select(Some(app.profile_cursor));

    let block = Block::bordered()
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(BORDER_SUBTLE))
        .padding(Padding::horizontal(1));

    f.render_stateful_widget(
        List::new(items)
            .highlight_style(Style::default())
            .highlight_symbol("")
            .block(block),
        chunks[1],
        &mut state,
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// Select Region (legacy)
// ═══════════════════════════════════════════════════════════════════════════

fn draw_region(f: &mut Frame, area: Rect, app: &App) {
    let region_names: &[(&str, &str)] = &[
        ("us-east-1",      "N. Virginia"),
        ("us-east-2",      "Ohio"),
        ("us-west-1",      "N. California"),
        ("us-west-2",      "Oregon"),
        ("eu-west-1",      "Ireland"),
        ("eu-central-1",   "Frankfurt"),
        ("ap-southeast-1", "Singapore"),
        ("ap-northeast-1", "Tokyo"),
    ];

    let chunks = Layout::vertical([
        Constraint::Length(2),
        Constraint::Fill(1),
        Constraint::Length(3),
    ])
    .split(content_inset(area));

    f.render_widget(
        Paragraph::new(Span::styled(
            "Select or type a custom AWS region:",
            Style::default().fg(TEXT_DIM),
        )),
        chunks[0],
    );

    let items: Vec<ListItem> = app
        .regions
        .iter()
        .enumerate()
        .map(|(i, r)| {
            let selected = !app.region_use_custom && i == app.region_cursor;
            let icon = if selected { "▸ " } else { "  " };
            let friendly = region_names.iter()
                .find(|(code, _)| code == r)
                .map(|(_, name)| *name)
                .unwrap_or("");
            let style = if selected {
                Style::default().fg(AMBER).add_modifier(Modifier::BOLD).bg(BG_SELECTED)
            } else {
                Style::default().fg(TEXT_NORMAL)
            };
            ListItem::new(Line::from(vec![
                Span::styled(icon, Style::default().fg(AMBER)),
                Span::styled(format!("{:<18}", r), style),
                Span::styled(format!("({})", friendly), Style::default().fg(TEXT_DIM)),
            ]))
        })
        .collect();

    let mut state = ListState::default();
    if !app.region_use_custom {
        state.select(Some(app.region_cursor));
    }

    let list_block = Block::bordered()
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(BORDER_SUBTLE))
        .title(Span::styled(" Available Regions ", Style::default().fg(CYAN_DIM)))
        .padding(Padding::horizontal(1));

    f.render_stateful_widget(List::new(items).block(list_block), chunks[1], &mut state);

    // Custom region input
    let custom_focused = app.region_use_custom;
    draw_text_field(f, chunks[2], "Custom Region", &app.region_custom.value, custom_focused);
}

// ═══════════════════════════════════════════════════════════════════════════
// Set Dates
// ═══════════════════════════════════════════════════════════════════════════

fn draw_dates(f: &mut Frame, area: Rect, app: &App) {
    let chunks = Layout::vertical([
        Constraint::Length(2),
        Constraint::Fill(1),
    ])
    .split(content_inset(area));

    f.render_widget(
        Paragraph::new(Span::styled(
            "Select how far back to collect evidence:",
            Style::default().fg(TEXT_DIM),
        )),
        chunks[0],
    );

    const MONTH_LABELS: [&str; 12] = [
        "1 Month", "2 Months", "3 Months", "4 Months",
        "5 Months", "6 Months", "7 Months", "8 Months",
        "9 Months", "10 Months", "11 Months", "12 Months",
    ];

    let items: Vec<ListItem> = MONTH_LABELS
        .iter()
        .enumerate()
        .map(|(i, label)| {
            let selected = i == app.time_frame_cursor;
            let icon = if selected { "▸ " } else { "  " };
            let style = if selected {
                Style::default().fg(AMBER).add_modifier(Modifier::BOLD).bg(BG_SELECTED)
            } else {
                Style::default().fg(TEXT_NORMAL)
            };
            ListItem::new(Line::from(vec![
                Span::styled(icon, Style::default().fg(AMBER)),
                Span::styled(*label, style),
            ]))
        })
        .collect();

    let block = Block::bordered()
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(BORDER_SUBTLE))
        .title(Span::styled(" Time Frame ", Style::default().fg(CYAN_DIM)))
        .padding(Padding::horizontal(1));

    let mut state = ListState::default();
    state.select(Some(app.time_frame_cursor));

    f.render_stateful_widget(
        List::new(items)
            .highlight_style(Style::default())
            .highlight_symbol("")
            .block(block),
        chunks[1],
        &mut state,
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// Select Collectors
// ═══════════════════════════════════════════════════════════════════════════

/// Category boundaries for section headers.
const COLLECTOR_CATEGORIES: &[(usize, &str)] = &[
    (0,   "App Layer & DNS"),
    (6,   "Audit Trail"),
    (23,  "Compute"),
    (37,  "Containers"),
    (41,  "Database & Backup"),
    (48,  "Encryption & Secrets"),
    (55,  "Identity & Access"),
    (67,  "Monitoring & Events"),
    (77,  "Network"),
    (97,  "Organization & Account"),
    (101, "Security Detection"),
    (113, "Storage"),
];

fn draw_collectors(f: &mut Frame, area: Rect, app: &App) {
    let selected_count = app.collector_selected.len();
    let total_count = app.collector_items.len();

    let title = format!(
        " Collectors ─────────── {} of {} selected ",
        selected_count, total_count,
    );

    // Build list items with section headers
    let mut items: Vec<ListItem> = Vec::new();
    let mut visual_to_data: Vec<Option<usize>> = Vec::new(); // maps visual row → data index
    let _ = visual_to_data; // we use ListState with data cursor

    for (i, (key, label)) in app.collector_items.iter().enumerate() {
        // Check if we need a section header before this item
        if let Some((_, cat_name)) = COLLECTOR_CATEGORIES.iter().find(|(idx, _)| *idx == i) {
            let sep_width = area.width.saturating_sub(12) as usize;
            let header_line = format!("── {} {}", cat_name, "─".repeat(sep_width.saturating_sub(cat_name.len() + 4)));
            let max_chars = (area.width as usize).saturating_sub(6);
            let truncated: String = header_line.chars().take(max_chars).collect();
            items.push(ListItem::new(Line::from(Span::styled(
                format!("   {truncated}"),
                Style::default().fg(TEXT_DIM),
            ))));
        }

        let checked = app.collector_selected.contains(&i);
        let focused = i == app.collector_cursor;

        let checkbox = if checked { "[✓]" } else { "[ ]" };
        let cursor_icon = if focused { "▸" } else { " " };

        let checkbox_style = if checked {
            Style::default().fg(GREEN).add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(TEXT_DIM)
        };

        let name_style = if focused {
            Style::default().fg(AMBER).add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(TEXT_NORMAL)
        };

        // Split label into name and description parts
        let parts: Vec<&str> = label.splitn(2, '(').collect();
        let name = parts[0].trim();
        let desc = if parts.len() > 1 {
            format!("({}",  parts[1])
        } else {
            String::new()
        };

        let mut line_spans = vec![
            Span::styled(format!(" {} ", cursor_icon), Style::default().fg(AMBER)),
            Span::styled(format!("{} ", checkbox), checkbox_style),
            Span::styled(format!("{:<30}", name), name_style),
        ];
        if !desc.is_empty() {
            line_spans.push(Span::styled(desc, Style::default().fg(TEXT_DIM)));
        }

        let item = ListItem::new(Line::from(line_spans));
        let item = if focused {
            item.style(Style::default().bg(BG_SELECTED))
        } else {
            item
        };
        items.push(item);
    }

    let block = Block::bordered()
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(BORDER_SUBTLE))
        .title(Line::from(vec![
            Span::styled(&title, Style::default().fg(CYAN_DIM)),
        ]));

    // We need to calculate the offset to account for section headers
    // above the current cursor position
    let headers_before_cursor = COLLECTOR_CATEGORIES
        .iter()
        .filter(|(idx, _)| *idx <= app.collector_cursor)
        .count();
    let visual_cursor = app.collector_cursor + headers_before_cursor;

    let mut state = ListState::default();
    state.select(Some(visual_cursor));

    f.render_stateful_widget(
        List::new(items).block(block).highlight_symbol(""),
        content_inset(area),
        &mut state,
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// Options
// ═══════════════════════════════════════════════════════════════════════════

fn draw_options(f: &mut Frame, area: Rect, app: &App) {
    // Seven fields: 0=filter 1=include_raw 2=all_regions 3=zip 4=sign 5=skip_inventory_csv 6=region list.
    let chunks = Layout::vertical([
        Constraint::Length(2), // [0] heading
        Constraint::Length(3), // [1] filter
        Constraint::Length(1), // [2] spacer
        Constraint::Length(3), // [3] include raw
        Constraint::Length(1), // [4] spacer
        Constraint::Length(3), // [5] all regions toggle
        Constraint::Length(1), // [6] spacer
        Constraint::Length(3), // [7] zip bundle toggle
        Constraint::Length(1), // [8] spacer
        Constraint::Length(3), // [9] sign output toggle
        Constraint::Length(1), // [10] spacer
        Constraint::Length(3), // [11] skip inventory CSV toggle
        Constraint::Length(1), // [12] spacer
        Constraint::Fill(1),   // [13] region list
    ])
    .split(content_inset(area));

    f.render_widget(
        Paragraph::new(Span::styled(
            "Configure output options:",
            Style::default().fg(TEXT_DIM),
        )),
        chunks[0],
    );

    draw_text_field(f, chunks[1], "Filter (optional)", &app.filter_input.value, app.options_field == 0);

    // ── Include Raw JSON toggle (field 1) ─────────────────────────────────────
    {
        let focused = app.options_field == 1;
        let border_style = if focused { Style::default().fg(CYAN) } else { Style::default().fg(BORDER_SUBTLE) };
        let title_style  = if focused { Style::default().fg(CYAN) } else { Style::default().fg(TEXT_DIM) };
        let (off_style, on_style) = if app.include_raw {
            (Style::default().fg(TEXT_DIM), Style::default().fg(AMBER).add_modifier(Modifier::BOLD))
        } else {
            (Style::default().fg(AMBER).add_modifier(Modifier::BOLD), Style::default().fg(TEXT_DIM))
        };
        let off_icon = if !app.include_raw { "●" } else { "○" };
        let on_icon  = if  app.include_raw { "●" } else { "○" };
        f.render_widget(
            Paragraph::new(Line::from(vec![
                Span::styled(format!("   {} ", off_icon), off_style),
                Span::styled("Disabled", off_style),
                Span::styled("    ", Style::default()),
                Span::styled(format!("{} ", on_icon), on_style),
                Span::styled("Enabled", on_style),
            ]))
            .block(Block::bordered()
                .border_type(BorderType::Rounded)
                .border_style(border_style)
                .title(Span::styled(" Include Raw JSON ", title_style))),
            chunks[3],
        );
    }

    // ── All Regions (round-robin) toggle (field 2) ────────────────────────────
    {
        let focused = app.options_field == 2;
        let border_style = if focused { Style::default().fg(CYAN) } else { Style::default().fg(BORDER_SUBTLE) };
        let title_style  = if focused { Style::default().fg(CYAN) } else { Style::default().fg(TEXT_DIM) };
        let (off_style, on_style) = if app.all_regions {
            (Style::default().fg(TEXT_DIM), Style::default().fg(AMBER).add_modifier(Modifier::BOLD))
        } else {
            (Style::default().fg(AMBER).add_modifier(Modifier::BOLD), Style::default().fg(TEXT_DIM))
        };
        let off_icon = if !app.all_regions { "●" } else { "○" };
        let on_icon  = if  app.all_regions { "●" } else { "○" };
        f.render_widget(
            Paragraph::new(Line::from(vec![
                Span::styled(format!("   {} ", off_icon), off_style),
                Span::styled("Single Region", off_style),
                Span::styled("    ", Style::default()),
                Span::styled(format!("{} ", on_icon), on_style),
                Span::styled("All Regions (round-robin discovery)", on_style),
            ]))
            .block(Block::bordered()
                .border_type(BorderType::Rounded)
                .border_style(border_style)
                .title(Span::styled(" All Regions ", title_style))),
            chunks[5],
        );
    }

    // ── Zip Bundle toggle (field 3) ───────────────────────────────────────────
    {
        let focused = app.options_field == 3;
        let border_style = if focused { Style::default().fg(CYAN) } else { Style::default().fg(BORDER_SUBTLE) };
        let title_style  = if focused { Style::default().fg(CYAN) } else { Style::default().fg(TEXT_DIM) };
        let (off_style, on_style) = if app.zip {
            (Style::default().fg(TEXT_DIM), Style::default().fg(GREEN).add_modifier(Modifier::BOLD))
        } else {
            (Style::default().fg(GREEN).add_modifier(Modifier::BOLD), Style::default().fg(TEXT_DIM))
        };
        let off_icon = if !app.zip { "●" } else { "○" };
        let on_icon  = if  app.zip { "●" } else { "○" };
        f.render_widget(
            Paragraph::new(Line::from(vec![
                Span::styled(format!("   {} ", off_icon), off_style),
                Span::styled("Disabled", off_style),
                Span::styled("    ", Style::default()),
                Span::styled(format!("{} ", on_icon), on_style),
                Span::styled("Enabled — bundle output into a dated .zip", on_style),
            ]))
            .block(Block::bordered()
                .border_type(BorderType::Rounded)
                .border_style(border_style)
                .title(Span::styled(" Zip Package ", title_style))),
            chunks[7],
        );
    }

    // ── Sign Output toggle (field 4) ──────────────────────────────────────────
    {
        let focused = app.options_field == 4;
        let border_style = if focused { Style::default().fg(CYAN) } else { Style::default().fg(BORDER_SUBTLE) };
        let title_style  = if focused { Style::default().fg(CYAN) } else { Style::default().fg(TEXT_DIM) };
        let (off_style, on_style) = if app.sign {
            (Style::default().fg(TEXT_DIM), Style::default().fg(PURPLE).add_modifier(Modifier::BOLD))
        } else {
            (Style::default().fg(PURPLE).add_modifier(Modifier::BOLD), Style::default().fg(TEXT_DIM))
        };
        let off_icon = if !app.sign { "●" } else { "○" };
        let on_icon  = if  app.sign { "●" } else { "○" };
        f.render_widget(
            Paragraph::new(Line::from(vec![
                Span::styled(format!("   {} ", off_icon), off_style),
                Span::styled("Disabled", off_style),
                Span::styled("    ", Style::default()),
                Span::styled(format!("{} ", on_icon), on_style),
                Span::styled("Enabled — HMAC-SHA256 sign all output files", on_style),
            ]))
            .block(Block::bordered()
                .border_type(BorderType::Rounded)
                .border_style(border_style)
                .title(Span::styled(" Sign Output ", title_style))),
            chunks[9],
        );
    }

    // ── Skip Inventory CSV toggle (field 5) ──────────────────────────────────
    {
        let focused = app.options_field == 5;
        let border_style = if focused { Style::default().fg(CYAN) } else { Style::default().fg(BORDER_SUBTLE) };
        let title_style  = if focused { Style::default().fg(CYAN) } else { Style::default().fg(TEXT_DIM) };
        let (off_style, on_style) = if app.skip_inventory_csv {
            (Style::default().fg(TEXT_DIM), Style::default().fg(AMBER).add_modifier(Modifier::BOLD))
        } else {
            (Style::default().fg(AMBER).add_modifier(Modifier::BOLD), Style::default().fg(TEXT_DIM))
        };
        let off_icon = if !app.skip_inventory_csv { "●" } else { "○" };
        let on_icon  = if  app.skip_inventory_csv { "●" } else { "○" };
        f.render_widget(
            Paragraph::new(Line::from(vec![
                Span::styled(format!("   {} ", off_icon), off_style),
                Span::styled("CSV + Excel", off_style),
                Span::styled("    ", Style::default()),
                Span::styled(format!("{} ", on_icon), on_style),
                Span::styled("Excel only — skip intermediate CSV", on_style),
            ]))
            .block(Block::bordered()
                .border_type(BorderType::Rounded)
                .border_style(border_style)
                .title(Span::styled(" Inventory Output Format ", title_style))),
            chunks[11],
        );
    }

    // ── Region multi-select list (field 6) ────────────────────────────────────
    {
        let focused = app.options_field == 6;
        let dimmed  = app.all_regions; // when all_regions is ON, list is informational only

        let border_style = if dimmed {
            Style::default().fg(BORDER_SUBTLE)
        } else if focused {
            Style::default().fg(CYAN)
        } else {
            Style::default().fg(BORDER_SUBTLE)
        };
        let title_style = if focused && !dimmed {
            Style::default().fg(CYAN)
        } else {
            Style::default().fg(TEXT_DIM)
        };

        let selected_count = app.options_selected_regions.len();
        let title = if dimmed {
            " Specific Regions — disabled while All Regions is ON ".to_string()
        } else if selected_count == 0 {
            " Specific Regions (optional — leave empty to use account default) ".to_string()
        } else {
            format!(" Specific Regions — {} selected ", selected_count)
        };

        let items: Vec<ListItem> = app.regions.iter().enumerate().map(|(i, region)| {
            let is_selected = app.options_selected_regions.contains(&i);
            let is_cursor   = focused && i == app.options_region_cursor;

            let check_style = if dimmed {
                Style::default().fg(TEXT_DIM)
            } else if is_selected {
                Style::default().fg(GREEN).add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(TEXT_DIM)
            };
            let name_style = if dimmed {
                Style::default().fg(TEXT_DIM)
            } else if is_selected {
                Style::default().fg(TEXT_NORMAL).add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(TEXT_NORMAL)
            };

            let check = if is_selected { "[✓]" } else { "[ ]" };
            let prefix = if is_cursor && !dimmed { " ▶ " } else { "   " };

            ListItem::new(Line::from(vec![
                Span::styled(prefix, Style::default().fg(CYAN)),
                Span::styled(check, check_style),
                Span::styled(format!("  {}", region), name_style),
            ]))
        }).collect();

        let block = Block::bordered()
            .border_type(BorderType::Rounded)
            .border_style(border_style)
            .title(Span::styled(title, title_style));

        let mut list_state = ListState::default();
        if focused && !dimmed {
            list_state.select(Some(app.options_region_cursor));
        }

        f.render_stateful_widget(
            List::new(items).block(block),
            chunks[13],
            &mut list_state,
        );
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Confirm
// ═══════════════════════════════════════════════════════════════════════════

fn draw_confirm(f: &mut Frame, area: Rect, app: &App) {
    let chunks = Layout::vertical([
        Constraint::Length(1),
        Constraint::Fill(1),
        Constraint::Length(3),
        Constraint::Length(1),
    ])
    .split(content_inset(area));

    let region = app.selected_region();

    // Build account/profile lines depending on selection mode.
    let sorted_accounts = app.selected_account_indices();
    let account_display = if sorted_accounts.len() > 1 {
        let names: Vec<&str> = sorted_accounts.iter()
            .map(|&i| app.accounts[i].name.as_str())
            .collect();
        format!("{} selected ({})", sorted_accounts.len(), names.join(", "))
    } else {
        String::new()
    };

    let mut rows: Vec<Line> = vec![Line::raw("")];

    if !sorted_accounts.is_empty() {
        if sorted_accounts.len() == 1 {
            let acct = &app.accounts[sorted_accounts[0]];
            rows.push(kv_line("Account", &acct.name));
            rows.push(kv_line("Profile", &acct.profile));
            rows.push(kv_line("Region", acct.region.as_deref().unwrap_or(&region)));
        } else {
            rows.push(kv_line_colored("Accounts", &account_display, AMBER));
        }
    } else {
        rows.push(kv_line("Profile", app.selected_profile()));
        rows.push(kv_line("Region", &region));
    }

    let time_frame_label = format!(
        "{} Month{}",
        app.time_frame_months(),
        if app.time_frame_months() == 1 { "" } else { "s" },
    );
    rows.extend_from_slice(&[
        kv_line("Time Frame", &time_frame_label),
        kv_line("Start Date", &app.start_date.value),
        kv_line("End Date", &app.end_date.value),
    ]);

    // Pre-compute display strings so they outlive the match arms below.
    let collectors_display = format!("{} selected", app.collector_selected.len());
    let filter_display = if app.filter_input.value.is_empty() {
        "none".to_string()
    } else {
        app.filter_input.value.clone()
    };
    let explicit_regions = app.explicit_regions();
    let explicit_regions_display = explicit_regions.join(", ");

    let mut inv_indices: Vec<usize> = app.inventory_selected.iter().copied().collect();
    inv_indices.sort_unstable();
    let inv_labels: Vec<&str> = inv_indices
        .iter()
        .filter_map(|&i| app.inventory_items.get(i).map(|(_, label)| *label))
        .collect();
    let assets_display = format!("{} selected ({})", inv_indices.len(), inv_labels.join(", "));

    match app.selected_feature {
        Feature::Collectors => {
            let regions_line = if app.all_regions {
                kv_line("Regions", "all — round-robin every enabled region")
            } else if explicit_regions.is_empty() {
                kv_line("Regions", "account default (single region)")
            } else {
                kv_line_colored("Regions", &explicit_regions_display, CYAN)
            };
            rows.extend_from_slice(&[
                kv_line_colored("Collectors", &collectors_display, AMBER),
                kv_line("Output Dir", &app.output_dir.value),
                kv_line("Filter", &filter_display),
                kv_line("Include Raw", if app.include_raw { "yes" } else { "no" }),
                kv_line("Zip Package", if app.zip { "yes — bundle output into a dated .zip" } else { "no" }),
                kv_line("Sign Output", if app.sign { "yes — HMAC-SHA256 manifest + key file" } else { "no" }),
                regions_line,
            ]);
        }
        Feature::Inventory => {
            rows.extend_from_slice(&[
                kv_line("Feature", "Inventory"),
                kv_line_colored("Asset Types", &assets_display, AMBER),
                kv_line("Output Dir", &app.output_dir.value),
                kv_line("Output Format", if app.skip_inventory_csv { "Excel only (CSV skipped)" } else { "CSV + Excel" }),
            ]);
        }
    }
    rows.push(Line::raw(""));

    let summary_block = Block::bordered()
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(CYAN_DIM))
        .title(Span::styled(
            " Configuration Summary ",
            Style::default().fg(CYAN_DIM),
        ));

    f.render_widget(
        Paragraph::new(Text::from(rows)).block(summary_block),
        chunks[1],
    );

    // Start button
    let button_block = Block::bordered()
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(AMBER));

    let button_label = match app.selected_feature {
        Feature::Collectors => "▸▸  Start Collection  ◂◂",
        Feature::Inventory  => "▸▸  Start Inventory   ◂◂",
    };
    f.render_widget(
        Paragraph::new(Span::styled(
            button_label,
            Style::default().fg(AMBER).add_modifier(Modifier::BOLD),
        ))
        .alignment(Alignment::Center)
        .block(button_block),
        chunks[2],
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// Preparing
// ═══════════════════════════════════════════════════════════════════════════

fn draw_preparing(f: &mut Frame, area: Rect, app: &App) {
    let inset = content_inset(area);

    let chunks = Layout::vertical([
        Constraint::Length(3),  // title
        Constraint::Fill(1),    // log lines
    ])
    .split(inset);

    // Title / progress indicator
    let title = if app.prep_total > 0 {
        format!(
            "  Preparing account {}/{}  —  building AWS SDK clients…",
            app.prep_current.max(1),
            app.prep_total,
        )
    } else {
        "  Preparing AWS SDK clients…".to_string()
    };

    let progress_pct = if app.prep_total > 0 {
        ((app.prep_current.saturating_sub(1)) as f64 / app.prep_total as f64 * 100.0) as u16
    } else {
        0
    };

    let gauge = Gauge::default()
        .block(Block::default())
        .gauge_style(Style::default().fg(CYAN).bg(BG_ELEVATED))
        .percent(progress_pct)
        .label(title);
    f.render_widget(gauge, chunks[0]);

    // Scrollable log — show the last N lines that fit in the area
    let log_height = chunks[1].height as usize;
    let lines: Vec<ListItem> = app
        .prep_log
        .iter()
        .rev()
        .take(log_height)
        .rev()
        .map(|line| {
            let style = if line.starts_with("  ✓") {
                Style::default().fg(GREEN)
            } else if line.starts_with("  ✗") || line.starts_with("  ERROR") {
                Style::default().fg(RED)
            } else if line.starts_with("    Region") || line.starts_with("    All ") || line.starts_with("    Building") {
                Style::default().fg(TEXT_DIM)
            } else if line.starts_with("  [") {
                Style::default().fg(CYAN).add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(TEXT_NORMAL)
            };
            ListItem::new(line.as_str()).style(style)
        })
        .collect();

    let log_widget = List::new(lines)
        .block(
            Block::bordered()
                .border_style(Style::default().fg(BORDER_SUBTLE))
                .title(Span::styled(" Setup Log ", Style::default().fg(TEXT_DIM)))
                .padding(Padding::horizontal(1)),
        );
    f.render_widget(log_widget, chunks[1]);
}

// ═══════════════════════════════════════════════════════════════════════════
// Running
// ═══════════════════════════════════════════════════════════════════════════

fn draw_running(f: &mut Frame, area: Rect, app: &App) {
    let inset = content_inset(area);

    // Always show a status line when we have account or region info.
    let multi_account = app.total_account_count > 1;
    let has_status = multi_account || app.current_region_label.is_some();
    let (status_area, rest) = if has_status {
        let parts = Layout::vertical([
            Constraint::Length(1), // status line
            Constraint::Length(1), // blank
            Constraint::Fill(1),  // rest
        ])
        .split(inset);
        (Some(parts[0]), parts[2])
    } else {
        (None, inset)
    };

    if let Some(area) = status_area {
        let mut spans: Vec<Span> = Vec::new();

        if multi_account {
            let label = app.current_account_label.as_deref().unwrap_or("…");
            spans.push(Span::styled(
                format!("Account {} of {}: {}", app.current_account_index, app.total_account_count, label),
                Style::default().fg(AMBER).add_modifier(Modifier::BOLD),
            ));
        }

        if let Some(region) = &app.current_region_label {
            if !spans.is_empty() {
                spans.push(Span::styled("   ·   ", Style::default().fg(TEXT_DIM)));
            }
            spans.push(Span::styled("Region: ", Style::default().fg(TEXT_DIM)));
            spans.push(Span::styled(
                region.clone(),
                Style::default().fg(CYAN).add_modifier(Modifier::BOLD),
            ));
        }

        f.render_widget(Paragraph::new(Line::from(spans)), area);
    }

    if rest.width >= 90 {
        // Two-column layout
        let columns = Layout::horizontal([
            Constraint::Percentage(60),
            Constraint::Percentage(40),
        ])
        .split(rest);
        draw_running_progress(f, columns[0], app);
        draw_running_stats(f, columns[1], app);
    } else {
        // Single-column: inline stats + progress list
        let rows = Layout::vertical([
            Constraint::Length(1), // inline stats
            Constraint::Length(1), // blank
            Constraint::Length(1), // gauge
            Constraint::Length(1), // blank
            Constraint::Fill(1),  // list
        ])
        .split(rest);
        draw_running_inline_stats(f, rows[0], app);
        draw_running_gauge(f, rows[2], app);
        draw_running_list(f, rows[4], app);
    }
}

fn draw_running_progress(f: &mut Frame, area: Rect, app: &App) {
    let chunks = Layout::vertical([
        Constraint::Length(3), // gauge
        Constraint::Length(1), // blank
        Constraint::Fill(1),  // list
    ])
    .split(area);

    draw_running_gauge(f, chunks[0], app);
    draw_running_list(f, chunks[2], app);
}

fn draw_running_gauge(f: &mut Frame, area: Rect, app: &App) {
    let total = app.collector_statuses.len().max(1);
    let completed = app
        .collector_statuses
        .iter()
        .filter(|s| matches!(s.state, CollectorState::Done(_) | CollectorState::Failed(_)))
        .count();

    let ratio = completed as f64 / total as f64;
    let label = format!("{} / {} collectors", completed, total);

    let gauge_block = Block::bordered()
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(BORDER_SUBTLE))
        .title(Span::styled(" Progress ", Style::default().fg(CYAN_DIM)));

    f.render_widget(
        Gauge::default()
            .block(gauge_block)
            .gauge_style(Style::default().fg(CYAN).bg(BG_ELEVATED))
            .ratio(ratio.min(1.0))
            .label(Span::styled(label, Style::default().fg(TEXT_BRIGHT).add_modifier(Modifier::BOLD))),
        area,
    );
}

fn draw_running_list(f: &mut Frame, area: Rect, app: &App) {
    let spinner = SPINNER_FRAMES[(app.tick as usize / 2) % SPINNER_FRAMES.len()];

    let items: Vec<ListItem> = app
        .collector_statuses
        .iter()
        .map(|s| {
            let (icon, status_text, icon_style, name_style, status_style) = match &s.state {
                CollectorState::Waiting => (
                    "· ",
                    "waiting".to_string(),
                    Style::default().fg(TEXT_DIM),
                    Style::default().fg(TEXT_DIM),
                    Style::default().fg(TEXT_DIM),
                ),
                CollectorState::Running => (
                    spinner,
                    "running".to_string(),
                    Style::default().fg(AMBER),
                    Style::default().fg(AMBER).add_modifier(Modifier::BOLD),
                    Style::default().fg(AMBER),
                ),
                CollectorState::Done(n) => (
                    "✓ ",
                    format_number(*n),
                    Style::default().fg(GREEN),
                    Style::default().fg(TEXT_NORMAL),
                    Style::default().fg(GREEN),
                ),
                CollectorState::Failed(m) => (
                    "✗ ",
                    m.clone(),
                    Style::default().fg(RED),
                    Style::default().fg(TEXT_NORMAL),
                    Style::default().fg(RED),
                ),
            };

            // Dot leader between name and status
            let name = &s.name;
            let available = area.width.saturating_sub(12) as usize;
            let name_len = name.len().min(30);
            let status_len = status_text.len().min(20);
            let dots = available.saturating_sub(name_len + status_len + 2);
            let leader = " ".to_string() + &"·".repeat(dots) + " ";

            ListItem::new(Line::from(vec![
                Span::styled(format!("  {} ", icon), icon_style),
                Span::styled(&name[..name_len], name_style),
                Span::styled(leader, Style::default().fg(BORDER_SUBTLE)),
                Span::styled(status_text, status_style),
            ]))
        })
        .collect();

    let block = Block::bordered()
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(BORDER_SUBTLE));

    // Auto-scroll to show the currently-running item
    let running_idx = app
        .collector_statuses
        .iter()
        .position(|s| matches!(s.state, CollectorState::Running))
        .unwrap_or(0);

    let mut state = ListState::default();
    state.select(Some(running_idx));

    f.render_stateful_widget(
        List::new(items).block(block).highlight_symbol(""),
        area,
        &mut state,
    );
}

fn draw_running_stats(f: &mut Frame, area: Rect, app: &App) {
    let chunks = Layout::vertical([
        Constraint::Length(8),
        Constraint::Fill(1),
    ])
    .split(area);

    // Statistics card
    let completed = app
        .collector_statuses
        .iter()
        .filter(|s| matches!(s.state, CollectorState::Done(_) | CollectorState::Failed(_)))
        .count();
    let total = app.collector_statuses.len();
    let total_records: usize = app
        .collector_statuses
        .iter()
        .filter_map(|s| if let CollectorState::Done(n) = s.state { Some(n) } else { None })
        .sum();
    let errors = app
        .collector_statuses
        .iter()
        .filter(|s| matches!(s.state, CollectorState::Failed(_)))
        .count();
    let elapsed = format_duration(app.tick);

    let error_style = if errors > 0 {
        Style::default().fg(RED).add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(TEXT_BRIGHT).add_modifier(Modifier::BOLD)
    };

    let completed_str = format!("{} / {}", completed, total);
    let records_str = format_number(total_records);
    let errors_str = errors.to_string();

    let stats_rows = vec![
        Line::raw(""),
        stat_line("Elapsed", &elapsed),
        stat_line("Completed", &completed_str),
        stat_line("Records", &records_str),
        Line::from(vec![
            Span::styled("    Errors       ", Style::default().fg(TEXT_DIM)),
            Span::styled(errors_str.as_str(), error_style),
        ]),
        Line::raw(""),
    ];

    let stats_block = Block::bordered()
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(BORDER_SUBTLE))
        .title(Span::styled(" Statistics ", Style::default().fg(CYAN_DIM)));

    f.render_widget(
        Paragraph::new(Text::from(stats_rows)).block(stats_block),
        chunks[0],
    );

    // Activity log
    let mut log_lines: Vec<Line> = Vec::new();
    for s in app.collector_statuses.iter().rev() {
        match &s.state {
            CollectorState::Done(n) => {
                log_lines.push(Line::from(vec![
                    Span::styled("  ✓ ", Style::default().fg(GREEN)),
                    Span::styled(
                        format!("{}: {}", s.name, format_number(*n)),
                        Style::default().fg(TEXT_NORMAL),
                    ),
                ]));
            }
            CollectorState::Failed(m) => {
                log_lines.push(Line::from(vec![
                    Span::styled("  ✗ ", Style::default().fg(RED)),
                    Span::styled(
                        format!("{}: {}", s.name, m),
                        Style::default().fg(RED),
                    ),
                ]));
            }
            CollectorState::Running => {
                log_lines.push(Line::from(vec![
                    Span::styled("  ▸ ", Style::default().fg(AMBER)),
                    Span::styled(
                        format!("{} started", s.name),
                        Style::default().fg(AMBER),
                    ),
                ]));
            }
            _ => {}
        }
        if log_lines.len() >= 20 {
            break;
        }
    }

    let log_block = Block::bordered()
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(BORDER_SUBTLE))
        .title(Span::styled(" Activity ", Style::default().fg(CYAN_DIM)));

    f.render_widget(
        Paragraph::new(Text::from(log_lines)).block(log_block),
        chunks[1],
    );
}

fn draw_running_inline_stats(f: &mut Frame, area: Rect, app: &App) {
    let completed = app
        .collector_statuses
        .iter()
        .filter(|s| matches!(s.state, CollectorState::Done(_) | CollectorState::Failed(_)))
        .count();
    let total = app.collector_statuses.len();
    let total_records: usize = app
        .collector_statuses
        .iter()
        .filter_map(|s| if let CollectorState::Done(n) = s.state { Some(n) } else { None })
        .sum();
    let errors = app
        .collector_statuses
        .iter()
        .filter(|s| matches!(s.state, CollectorState::Failed(_)))
        .count();
    let elapsed = format_duration(app.tick);

    f.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled("  Elapsed ", Style::default().fg(TEXT_DIM)),
            Span::styled(&elapsed, Style::default().fg(TEXT_BRIGHT).add_modifier(Modifier::BOLD)),
            Span::styled("   Done ", Style::default().fg(TEXT_DIM)),
            Span::styled(
                format!("{}/{}", completed, total),
                Style::default().fg(TEXT_BRIGHT).add_modifier(Modifier::BOLD),
            ),
            Span::styled("   Records ", Style::default().fg(TEXT_DIM)),
            Span::styled(
                format_number(total_records),
                Style::default().fg(TEXT_BRIGHT).add_modifier(Modifier::BOLD),
            ),
            Span::styled("   Errors ", Style::default().fg(TEXT_DIM)),
            Span::styled(
                errors.to_string(),
                if errors > 0 {
                    Style::default().fg(RED).add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(TEXT_BRIGHT).add_modifier(Modifier::BOLD)
                },
            ),
        ])),
        area,
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// Results
// ═══════════════════════════════════════════════════════════════════════════

fn draw_results(f: &mut Frame, area: Rect, app: &App) {
    let inset = content_inset(area);

    let has_errors = !app.error_messages.is_empty();
    let has_zip = app.result_zip.is_some();
    let has_sign = app.result_signing_manifest.is_some();
    let error_height = if has_errors {
        // Show up to 8 error lines, plus border
        (app.error_messages.len().min(8) as u16) + 2
    } else {
        0
    };

    let chunks = Layout::vertical([
        Constraint::Length(3),                                  // [0] success banner
        Constraint::Length(1),                                  // [1] blank
        Constraint::Length(5),                                  // [2] stat cards
        Constraint::Length(1),                                  // [3] blank
        Constraint::Fill(1),                                    // [4] file list
        Constraint::Length(if has_zip { 1 } else { 0 }),       // [5] blank before zip
        Constraint::Length(if has_zip { 3 } else { 0 }),       // [6] zip path banner
        Constraint::Length(if has_sign { 1 } else { 0 }),      // [7] blank before sign
        Constraint::Length(if has_sign { 4 } else { 0 }),      // [8] sign manifest+key banner
        Constraint::Length(if has_errors { 1 } else { 0 }),    // [9] blank before errors
        Constraint::Length(error_height),                       // [10] error list
    ])
    .split(inset);

    // Success banner — change color/text if there were errors
    let (banner_text, banner_color) = if has_errors {
        ("!  Collection Complete (with errors)", AMBER)
    } else {
        ("✓  Collection Complete", GREEN)
    };
    let banner_block = Block::bordered()
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(banner_color));
    f.render_widget(
        Paragraph::new(Span::styled(
            banner_text,
            Style::default().fg(banner_color).add_modifier(Modifier::BOLD),
        ))
        .alignment(Alignment::Center)
        .block(banner_block),
        chunks[0],
    );

    // Stat cards
    let total_records: usize = app
        .collector_statuses
        .iter()
        .filter_map(|s| if let CollectorState::Done(n) = s.state { Some(n) } else { None })
        .sum();
    let elapsed = format_duration(app.finished_tick.unwrap_or(app.tick));
    let error_count = app.error_messages.len();

    let cards = Layout::horizontal([
        Constraint::Ratio(1, 4),
        Constraint::Ratio(1, 4),
        Constraint::Ratio(1, 4),
        Constraint::Ratio(1, 4),
    ])
    .split(chunks[2]);

    draw_stat_card(f, cards[0], "Files", &app.result_files.len().to_string(), CYAN);
    draw_stat_card(f, cards[1], "Records", &format_number(total_records), AMBER);
    draw_stat_card(f, cards[2], "Errors", &error_count.to_string(), if error_count > 0 { RED } else { GREEN });
    draw_stat_card(f, cards[3], "Duration", &elapsed, PURPLE);

    // File list
    let file_items: Vec<ListItem> = app
        .result_files
        .iter()
        .enumerate()
        .map(|(i, path)| {
            let bg = if i % 2 == 0 { BG_MAIN } else { BG_ELEVATED };
            ListItem::new(Line::from(vec![
                Span::styled("  ✓ ", Style::default().fg(GREEN)),
                Span::styled(path.as_str(), Style::default().fg(TEXT_NORMAL)),
            ]))
            .style(Style::default().bg(bg))
        })
        .collect();

    let file_block = Block::bordered()
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(BORDER_SUBTLE))
        .title(Span::styled(" Output Files ", Style::default().fg(CYAN_DIM)));

    let mut state = ListState::default();
    if !app.result_files.is_empty() {
        state.select(Some(app.result_scroll.min(app.result_files.len() - 1)));
    }

    f.render_stateful_widget(
        List::new(file_items).block(file_block).highlight_symbol(""),
        chunks[4],
        &mut state,
    );

    // Zip path banner (only shown when a bundle was created)
    if let Some(zip) = &app.result_zip {
        f.render_widget(
            Paragraph::new(Line::from(vec![
                Span::styled("  ⬇ ", Style::default().fg(GREEN)),
                Span::styled("Zip bundle: ", Style::default().fg(TEXT_DIM)),
                Span::styled(zip.as_str(), Style::default().fg(GREEN).add_modifier(Modifier::BOLD)),
            ]))
            .block(Block::bordered()
                .border_type(BorderType::Rounded)
                .border_style(Style::default().fg(GREEN))
                .title(Span::styled(" Zip Package Ready ", Style::default().fg(GREEN)))),
            chunks[6],
        );
    }

    // Signing banner (only shown when signing was performed)
    if let Some(manifest) = &app.result_signing_manifest {
        let key_line = app.result_signing_key_path
            .as_deref()
            .unwrap_or("(see stderr log)");
        f.render_widget(
            Paragraph::new(vec![
                Line::from(vec![
                    Span::styled("  ✎ ", Style::default().fg(PURPLE)),
                    Span::styled("Manifest:  ", Style::default().fg(TEXT_DIM)),
                    Span::styled(manifest.as_str(), Style::default().fg(PURPLE).add_modifier(Modifier::BOLD)),
                ]),
                Line::from(vec![
                    Span::styled("  ⚠ ", Style::default().fg(AMBER)),
                    Span::styled("Key file:  ", Style::default().fg(TEXT_DIM)),
                    Span::styled(key_line, Style::default().fg(AMBER).add_modifier(Modifier::BOLD)),
                    Span::styled("  ← store securely, separate from evidence", Style::default().fg(TEXT_DIM)),
                ]),
            ])
            .block(Block::bordered()
                .border_type(BorderType::Rounded)
                .border_style(Style::default().fg(PURPLE))
                .title(Span::styled(" Signing Manifest Ready ", Style::default().fg(PURPLE)))),
            chunks[8],
        );
    }

    // Error list (only shown if there are errors)
    if has_errors {
        let error_items: Vec<ListItem> = app
            .error_messages
            .iter()
            .enumerate()
            .map(|(i, (name, msg))| {
                let bg = if i % 2 == 0 { BG_MAIN } else { RED_BG };
                ListItem::new(Line::from(vec![
                    Span::styled("  ✗ ", Style::default().fg(RED)),
                    Span::styled(format!("{}: ", name), Style::default().fg(AMBER)),
                    Span::styled(msg.as_str(), Style::default().fg(TEXT_DIM)),
                ]))
                .style(Style::default().bg(bg))
            })
            .collect();

        let error_block = Block::bordered()
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(RED))
            .title(Span::styled(
                format!(" Errors ({}) ", error_count),
                Style::default().fg(RED),
            ));

        f.render_widget(List::new(error_items).block(error_block), chunks[10]);
    }
}

fn draw_stat_card(f: &mut Frame, area: Rect, title: &str, value: &str, color: Color) {
    let block = Block::bordered()
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(BORDER_SUBTLE))
        .title(Span::styled(format!(" {title} "), Style::default().fg(TEXT_DIM)));

    f.render_widget(
        Paragraph::new(Span::styled(
            value,
            Style::default().fg(color).add_modifier(Modifier::BOLD),
        ))
        .alignment(Alignment::Center)
        .block(block.padding(Padding::vertical(1))),
        area,
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// Shared helpers
// ═══════════════════════════════════════════════════════════════════════════

fn draw_text_field(f: &mut Frame, area: Rect, label: &str, value: &str, focused: bool) {
    let border_style = if focused {
        Style::default().fg(CYAN)
    } else {
        Style::default().fg(BORDER_SUBTLE)
    };
    let title_style = if focused {
        Style::default().fg(CYAN)
    } else {
        Style::default().fg(TEXT_DIM)
    };

    let block = Block::bordered()
        .border_type(BorderType::Rounded)
        .border_style(border_style)
        .title(Span::styled(format!(" {label} "), title_style))
        .padding(Padding::horizontal(1));

    f.render_widget(
        Paragraph::new(Span::styled(value, Style::default().fg(TEXT_BRIGHT))).block(block),
        area,
    );

    if focused {
        // Cursor position: border(1) + padding(1) + value length
        f.set_cursor_position((
            area.x + 2 + value.len() as u16,
            area.y + 1,
        ));
    }
}

fn draw_error_banner(f: &mut Frame, area: Rect, msg: &str) {
    let banner = Rect {
        x: area.x,
        y: area.y + area.height.saturating_sub(1),
        width: area.width,
        height: 1,
    };
    f.render_widget(Clear, banner);
    f.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled(" ✗  ", Style::default().fg(RED)),
            Span::styled(msg, Style::default().fg(TEXT_BRIGHT)),
        ]))
        .style(Style::default().bg(RED_BG)),
        banner,
    );
}

fn kv_line<'a>(key: &'a str, value: &'a str) -> Line<'a> {
    Line::from(vec![
        Span::styled(format!("   {:>14}     ", key), Style::default().fg(TEXT_DIM)),
        Span::styled(value, Style::default().fg(TEXT_BRIGHT).add_modifier(Modifier::BOLD)),
    ])
}

fn kv_line_colored<'a>(key: &'a str, value: &'a str, color: Color) -> Line<'a> {
    Line::from(vec![
        Span::styled(format!("   {:>14}     ", key), Style::default().fg(TEXT_DIM)),
        Span::styled(value, Style::default().fg(color).add_modifier(Modifier::BOLD)),
    ])
}

fn stat_line<'a>(key: &'a str, value: &'a str) -> Line<'a> {
    Line::from(vec![
        Span::styled(format!("    {:<13}", key), Style::default().fg(TEXT_DIM)),
        Span::styled(value, Style::default().fg(TEXT_BRIGHT).add_modifier(Modifier::BOLD)),
    ])
}

/// Inset the content area horizontally for breathing room.
fn content_inset(area: Rect) -> Rect {
    let margin = 4u16.min(area.width / 6);
    Rect {
        x: area.x + margin,
        y: area.y,
        width: area.width.saturating_sub(margin * 2),
        height: area.height,
    }
}

fn format_duration(ticks: u64) -> String {
    let secs = ticks / 10; // 100ms per tick
    let mins = secs / 60;
    let secs = secs % 60;
    format!("{:02}:{:02}", mins, secs)
}

fn format_number(n: usize) -> String {
    if n < 1000 {
        return n.to_string();
    }
    let s = n.to_string();
    let mut result = String::new();
    for (i, c) in s.chars().rev().enumerate() {
        if i > 0 && i % 3 == 0 {
            result.push(',');
        }
        result.push(c);
    }
    result.chars().rev().collect()
}
