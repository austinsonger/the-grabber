use ratatui::layout::{Alignment, Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::{
    Block, BorderType, Clear, Gauge, List, ListItem, ListState, Padding,
    Paragraph,
};
use ratatui::Frame;

use super::{App, CollectorState, Screen};

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
const STEPS_LEGACY: &[&str]   = &["Profile", "Region", "Dates", "Collectors", "Options", "Confirm", "Run"];

fn screen_to_step(screen: &Screen, has_accounts: bool) -> Option<usize> {
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

    let show_steps = !matches!(app.screen, Screen::Welcome | Screen::Results);
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
    let step_info = screen_to_step(&app.screen, app.has_accounts());
    let steps = if app.has_accounts() { STEPS_ACCOUNTS } else { STEPS_LEGACY };
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
        Screen::SelectAccount    => draw_select_account(f, content, app),
        Screen::SelectProfile    => draw_profile(f, content, app),
        Screen::SelectRegion     => draw_region(f, content, app),
        Screen::SetDates         => draw_dates(f, content, app),
        Screen::SelectCollectors => draw_collectors(f, content, app),
        Screen::SetOptions       => draw_options(f, content, app),
        Screen::Confirm          => draw_confirm(f, content, app),
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
        Screen::Welcome => vec![("⏎", "Begin"), ("Esc", "Quit")],
        Screen::SelectAccount => vec![("↑↓", "Navigate"), ("⏎", "Select"), ("Esc", "Quit")],
        Screen::SelectProfile => vec![("↑↓", "Navigate"), ("⏎", "Select"), ("Esc", "Back")],
        Screen::SelectRegion => vec![("↑↓", "Navigate"), ("↓", "Custom"), ("⏎", "Confirm"), ("Esc", "Back")],
        Screen::SetDates => vec![("⇥", "Switch"), ("⏎", "Confirm"), ("Esc", "Back")],
        Screen::SelectCollectors => vec![("↑↓", "Navigate"), ("␣", "Toggle"), ("⏎", "Confirm"), ("Esc", "Back")],
        Screen::SetOptions => vec![("⇥", "Switch"), ("␣", "Toggle"), ("⏎", "Confirm"), ("Esc", "Back")],
        Screen::Confirm => vec![("⏎", "Start"), ("Esc", "Back")],
        Screen::Running => vec![],
        Screen::Results => vec![("q", "Quit"), ("Esc", "Exit")],
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
// Select Account (NEW)
// ═══════════════════════════════════════════════════════════════════════════

fn draw_select_account(f: &mut Frame, area: Rect, app: &App) {
    let chunks = Layout::vertical([
        Constraint::Length(2),
        Constraint::Fill(1),
    ])
    .split(content_inset(area));

    f.render_widget(
        Paragraph::new(Span::styled(
            "Select the AWS account to collect evidence from:",
            Style::default().fg(TEXT_DIM),
        )),
        chunks[0],
    );

    // Build list items: accounts + separator + "Other"
    let total_entries = app.accounts.len() + 2; // accounts + separator + "Other"
    let mut items: Vec<ListItem> = Vec::with_capacity(total_entries);

    for (i, acct) in app.accounts.iter().enumerate() {
        let selected = i == app.account_cursor;
        let icon = if selected { "▸ " } else { "  " };

        let name_style = if selected {
            Style::default().fg(AMBER).add_modifier(Modifier::BOLD).bg(BG_SELECTED)
        } else {
            Style::default().fg(TEXT_BRIGHT).add_modifier(Modifier::BOLD)
        };

        let detail = format!(
            "    {} · {} · {}",
            acct.account_id.as_deref().unwrap_or(""),
            acct.profile,
            acct.region.as_deref().unwrap_or("us-east-1"),
        );

        items.push(ListItem::new(Text::from(vec![
            Line::from(vec![
                Span::styled(icon, Style::default().fg(AMBER)),
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
        Constraint::Length(1),
        Constraint::Length(3),
        Constraint::Length(1),
        Constraint::Length(3),
        Constraint::Fill(1),
    ])
    .split(content_inset(area));

    f.render_widget(
        Paragraph::new(Span::styled(
            "Set the date range for time-windowed evidence:",
            Style::default().fg(TEXT_DIM),
        )),
        chunks[0],
    );

    f.render_widget(
        Paragraph::new(Span::styled(
            "Format: YYYY-MM-DD",
            Style::default().fg(TEXT_DIM).add_modifier(Modifier::ITALIC),
        )),
        Rect { x: chunks[1].x + 6, ..chunks[1] },
    );

    draw_text_field(f, chunks[2], "Start Date", &app.start_date.value, app.date_field == 0);
    draw_text_field(f, chunks[4], "End Date", &app.end_date.value, app.date_field == 1);
}

// ═══════════════════════════════════════════════════════════════════════════
// Select Collectors
// ═══════════════════════════════════════════════════════════════════════════

/// Category boundaries for section headers.
const COLLECTOR_CATEGORIES: &[(usize, &str)] = &[
    (0,  "Time-Windowed Evidence (JSON)"),
    (4,  "Infrastructure & Services (CSV)"),
    (22, "IAM"),
    (26, "Security Services"),
    (29, "Network & Compute"),
    (33, "Encryption & Secrets"),
    (35, "Storage"),
    (36, "Monitoring"),
    (38, "Application Layer"),
    (40, "Containers"),
    (42, "Extended Configuration"),
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
    // Output directory is always sourced from TOML config — not editable here.
    // Two fields: 0 = filter, 1 = include_raw toggle.
    let chunks = Layout::vertical([
        Constraint::Length(2),
        Constraint::Length(3),
        Constraint::Length(1),
        Constraint::Length(3),
        Constraint::Fill(1),
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

    // Include Raw JSON toggle
    let toggle_focused = app.options_field == 1;
    let border_style = if toggle_focused {
        Style::default().fg(CYAN)
    } else {
        Style::default().fg(BORDER_SUBTLE)
    };
    let title_style = if toggle_focused {
        Style::default().fg(CYAN)
    } else {
        Style::default().fg(TEXT_DIM)
    };

    let (off_style, on_style) = if app.include_raw {
        (Style::default().fg(TEXT_DIM), Style::default().fg(AMBER).add_modifier(Modifier::BOLD))
    } else {
        (Style::default().fg(AMBER).add_modifier(Modifier::BOLD), Style::default().fg(TEXT_DIM))
    };
    let off_icon = if !app.include_raw { "●" } else { "○" };
    let on_icon = if app.include_raw { "●" } else { "○" };

    let toggle_block = Block::bordered()
        .border_type(BorderType::Rounded)
        .border_style(border_style)
        .title(Span::styled(" Include Raw JSON ", title_style));

    f.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled(format!("   {} ", off_icon), off_style),
            Span::styled("Disabled", off_style),
            Span::styled("    ", Style::default()),
            Span::styled(format!("{} ", on_icon), on_style),
            Span::styled("Enabled", on_style),
        ]))
        .block(toggle_block),
        chunks[3],
    );
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

    // Summary card
    let collectors = format!("{} selected", app.collector_selected.len());
    let filter_display = if app.filter_input.value.is_empty() {
        "none".to_string()
    } else {
        app.filter_input.value.clone()
    };
    let region = app.selected_region();

    let rows: Vec<Line> = vec![
        Line::raw(""),
        kv_line("Profile", app.selected_profile()),
        kv_line("Region", &region),
        kv_line("Start Date", &app.start_date.value),
        kv_line("End Date", &app.end_date.value),
        kv_line_colored("Collectors", &collectors, AMBER),
        kv_line("Output Dir", &app.output_dir.value),
        kv_line("Filter", &filter_display),
        kv_line("Include Raw", if app.include_raw { "yes" } else { "no" }),
        Line::raw(""),
    ];

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

    f.render_widget(
        Paragraph::new(Span::styled(
            "▸▸  Start Collection  ◂◂",
            Style::default().fg(AMBER).add_modifier(Modifier::BOLD),
        ))
        .alignment(Alignment::Center)
        .block(button_block),
        chunks[2],
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// Running
// ═══════════════════════════════════════════════════════════════════════════

fn draw_running(f: &mut Frame, area: Rect, app: &App) {
    let inset = content_inset(area);

    if inset.width >= 90 {
        // Two-column layout
        let columns = Layout::horizontal([
            Constraint::Percentage(60),
            Constraint::Percentage(40),
        ])
        .split(inset);
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
        .split(inset);
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

    let chunks = Layout::vertical([
        Constraint::Length(3), // success banner
        Constraint::Length(1), // blank
        Constraint::Length(5), // stat cards
        Constraint::Length(1), // blank
        Constraint::Fill(1),  // file list
    ])
    .split(inset);

    // Success banner
    let banner_block = Block::bordered()
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(GREEN));
    f.render_widget(
        Paragraph::new(Span::styled(
            "✓  Collection Complete",
            Style::default().fg(GREEN).add_modifier(Modifier::BOLD),
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
    let elapsed = format_duration(app.tick);

    let cards = Layout::horizontal([
        Constraint::Ratio(1, 3),
        Constraint::Ratio(1, 3),
        Constraint::Ratio(1, 3),
    ])
    .split(chunks[2]);

    draw_stat_card(f, cards[0], "Files", &app.result_files.len().to_string(), CYAN);
    draw_stat_card(f, cards[1], "Records", &format_number(total_records), AMBER);
    draw_stat_card(f, cards[2], "Duration", &elapsed, PURPLE);

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
