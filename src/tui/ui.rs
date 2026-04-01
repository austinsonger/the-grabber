use ratatui::layout::{Alignment, Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::{Block, Borders, Clear, List, ListItem, ListState, Padding, Paragraph, Wrap};
use ratatui::Frame;

use super::{App, CollectorState, Screen};

// Palette
const COLOR_BRAND:   Color = Color::Cyan;
const COLOR_ACCENT:  Color = Color::Yellow;
const COLOR_SUCCESS: Color = Color::Green;
const COLOR_ERROR:   Color = Color::Red;
const COLOR_DIM:     Color = Color::DarkGray;
const COLOR_BG:      Color = Color::Reset;

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

pub fn draw(f: &mut Frame, app: &App) {
    let area = f.area();

    // Full-screen background
    f.render_widget(
        Block::default().style(Style::default().bg(COLOR_BG)),
        area,
    );

    match app.screen {
        Screen::Welcome          => draw_welcome(f, area),
        Screen::SelectProfile    => draw_profile(f, area, app),
        Screen::SelectRegion     => draw_region(f, area, app),
        Screen::SetDates         => draw_dates(f, area, app),
        Screen::SelectCollectors => draw_collectors(f, area, app),
        Screen::SetOptions       => draw_options(f, area, app),
        Screen::Confirm          => draw_confirm(f, area, app),
        Screen::Running          => draw_running(f, area, app),
        Screen::Results          => draw_results(f, area, app),
    }

    // Error banner at bottom
    if let Some(ref msg) = app.error_msg {
        draw_error_banner(f, area, msg);
    }
}

// ---------------------------------------------------------------------------
// Welcome
// ---------------------------------------------------------------------------

fn draw_welcome(f: &mut Frame, area: Rect) {
    let block = centered_rect(60, 50, area);

    f.render_widget(Clear, block);
    f.render_widget(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(COLOR_BRAND))
            .title(title_span(" evidence "))
            .title_alignment(Alignment::Center),
        block,
    );

    let inner = inner_rect(block);
    let chunks = Layout::vertical([
        Constraint::Fill(1),
        Constraint::Length(3),
        Constraint::Length(2),
        Constraint::Length(1),
        Constraint::Length(2),
        Constraint::Fill(1),
    ])
    .split(inner);

    f.render_widget(
        Paragraph::new(Text::from(vec![
            Line::from(Span::styled(
                "  AWS Compliance Evidence Collector  ",
                Style::default().fg(COLOR_BRAND).add_modifier(Modifier::BOLD),
            )),
            Line::from(""),
            Line::from(Span::styled(
                "Collect backup evidence from CloudTrail,",
                Style::default().fg(Color::White),
            )),
        ]))
        .alignment(Alignment::Center),
        chunks[1],
    );

    f.render_widget(
        Paragraph::new(Text::from(vec![
            Line::from(Span::styled(
                "AWS Backup, RDS Snapshots, and S3 logs.",
                Style::default().fg(Color::White),
            )),
        ]))
        .alignment(Alignment::Center),
        chunks[2],
    );

    f.render_widget(
        Paragraph::new(
            Span::styled(
                "[ Press  Enter  to begin ]",
                Style::default().fg(COLOR_ACCENT).add_modifier(Modifier::BOLD),
            ),
        )
        .alignment(Alignment::Center),
        chunks[4],
    );
}

// ---------------------------------------------------------------------------
// Profile selection
// ---------------------------------------------------------------------------

fn draw_profile(f: &mut Frame, area: Rect, app: &App) {
    let block = centered_rect(60, 70, area);
    f.render_widget(Clear, block);

    let outer = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(COLOR_BRAND))
        .title(title_span(" AWS Profile "))
        .title_alignment(Alignment::Center);
    f.render_widget(outer, block);

    let inner = inner_rect(block);
    let chunks = Layout::vertical([
        Constraint::Length(2),
        Constraint::Fill(1),
        Constraint::Length(1),
    ])
    .split(inner);

    f.render_widget(
        Paragraph::new(Span::styled(
            "Select the AWS profile to use:",
            Style::default().fg(COLOR_DIM),
        )),
        chunks[0],
    );

    let items: Vec<ListItem> = app
        .profiles
        .iter()
        .enumerate()
        .map(|(i, p)| {
            let icon = if i == app.profile_cursor { "▶ " } else { "  " };
            ListItem::new(Line::from(vec![
                Span::styled(icon, Style::default().fg(COLOR_BRAND)),
                Span::raw(p),
            ]))
        })
        .collect();

    let mut state = ListState::default();
    state.select(Some(app.profile_cursor));

    f.render_stateful_widget(
        List::new(items)
            .highlight_style(Style::default().fg(COLOR_ACCENT).add_modifier(Modifier::BOLD))
            .highlight_symbol(""),
        chunks[1],
        &mut state,
    );

    f.render_widget(hint("↑↓ navigate   Enter confirm   Esc back"), chunks[2]);
}

// ---------------------------------------------------------------------------
// Region selection
// ---------------------------------------------------------------------------

fn draw_region(f: &mut Frame, area: Rect, app: &App) {
    let block = centered_rect(60, 80, area);
    f.render_widget(Clear, block);

    let outer = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(COLOR_BRAND))
        .title(title_span(" AWS Region "))
        .title_alignment(Alignment::Center);
    f.render_widget(outer, block);

    let inner = inner_rect(block);
    let chunks = Layout::vertical([
        Constraint::Length(2),
        Constraint::Fill(1),
        Constraint::Length(3),
        Constraint::Length(1),
    ])
    .split(inner);

    f.render_widget(
        Paragraph::new(Span::styled(
            "Select or type a region:",
            Style::default().fg(COLOR_DIM),
        )),
        chunks[0],
    );

    let items: Vec<ListItem> = app
        .regions
        .iter()
        .enumerate()
        .map(|(i, r)| {
            let selected = !app.region_use_custom && i == app.region_cursor;
            let icon = if selected { "▶ " } else { "  " };
            ListItem::new(Line::from(vec![
                Span::styled(icon, Style::default().fg(COLOR_BRAND)),
                Span::styled(
                    *r,
                    if selected {
                        Style::default().fg(COLOR_ACCENT).add_modifier(Modifier::BOLD)
                    } else {
                        Style::default()
                    },
                ),
            ]))
        })
        .collect();

    let mut state = ListState::default();
    if !app.region_use_custom {
        state.select(Some(app.region_cursor));
    }
    f.render_stateful_widget(List::new(items), chunks[1], &mut state);

    // Custom input box at bottom
    let custom_style = if app.region_use_custom {
        Style::default().fg(COLOR_ACCENT)
    } else {
        Style::default().fg(COLOR_DIM)
    };
    let custom_block = Block::default()
        .borders(Borders::ALL)
        .border_style(custom_style)
        .title(Span::styled(" Custom ", custom_style));

    f.render_widget(
        Paragraph::new(app.region_custom.value.as_str())
            .block(custom_block),
        chunks[2],
    );

    f.render_widget(hint("↑↓ navigate   ↓ past list = custom   Enter confirm   Esc back"), chunks[3]);
}

// ---------------------------------------------------------------------------
// Date inputs
// ---------------------------------------------------------------------------

fn draw_dates(f: &mut Frame, area: Rect, app: &App) {
    let block = centered_rect(60, 50, area);
    f.render_widget(Clear, block);

    let outer = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(COLOR_BRAND))
        .title(title_span(" Date Range "))
        .title_alignment(Alignment::Center);
    f.render_widget(outer, block);

    let inner = inner_rect(block);
    let chunks = Layout::vertical([
        Constraint::Length(2),
        Constraint::Length(3),
        Constraint::Length(1),
        Constraint::Length(3),
        Constraint::Fill(1),
        Constraint::Length(1),
    ])
    .split(inner);

    f.render_widget(
        Paragraph::new(Span::styled("Format: YYYY-MM-DD", Style::default().fg(COLOR_DIM))),
        chunks[0],
    );

    draw_text_field(f, chunks[1], "Start Date", &app.start_date.value, app.date_field == 0);
    draw_text_field(f, chunks[3], "End Date",   &app.end_date.value,   app.date_field == 1);
    f.render_widget(hint("Tab switch field   Enter confirm   Esc back"), chunks[5]);
}

// ---------------------------------------------------------------------------
// Collector selection
// ---------------------------------------------------------------------------

fn draw_collectors(f: &mut Frame, area: Rect, app: &App) {
    let block = centered_rect(65, 60, area);
    f.render_widget(Clear, block);

    let outer = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(COLOR_BRAND))
        .title(title_span(" Evidence Collectors "))
        .title_alignment(Alignment::Center);
    f.render_widget(outer, block);

    let inner = inner_rect(block);
    let chunks = Layout::vertical([
        Constraint::Length(2),
        Constraint::Fill(1),
        Constraint::Length(1),
    ])
    .split(inner);

    f.render_widget(
        Paragraph::new(Span::styled(
            "Space to toggle, Enter to confirm:",
            Style::default().fg(COLOR_DIM),
        )),
        chunks[0],
    );

    let items: Vec<ListItem> = app
        .collector_items
        .iter()
        .enumerate()
        .map(|(i, (_, label))| {
            let checked = app.collector_selected.contains(&i);
            let focused = i == app.collector_cursor;

            let checkbox = if checked { "✓" } else { " " };
            let cursor   = if focused { "▶" } else { " " };

            ListItem::new(Line::from(vec![
                Span::styled(format!("{cursor} "), Style::default().fg(COLOR_BRAND)),
                Span::styled(
                    format!("[{checkbox}] "),
                    if checked {
                        Style::default().fg(COLOR_SUCCESS).add_modifier(Modifier::BOLD)
                    } else {
                        Style::default().fg(COLOR_DIM)
                    },
                ),
                Span::styled(
                    *label,
                    if focused {
                        Style::default().fg(COLOR_ACCENT)
                    } else {
                        Style::default()
                    },
                ),
            ]))
        })
        .collect();

    let mut state = ListState::default();
    state.select(Some(app.collector_cursor));
    f.render_stateful_widget(List::new(items), chunks[1], &mut state);

    f.render_widget(hint("↑↓ navigate   Space toggle   Enter confirm   Esc back"), chunks[2]);
}

// ---------------------------------------------------------------------------
// Options
// ---------------------------------------------------------------------------

fn draw_options(f: &mut Frame, area: Rect, app: &App) {
    let block = centered_rect(65, 55, area);
    f.render_widget(Clear, block);

    let outer = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(COLOR_BRAND))
        .title(title_span(" Options "))
        .title_alignment(Alignment::Center);
    f.render_widget(outer, block);

    let inner = inner_rect(block);
    let chunks = Layout::vertical([
        Constraint::Length(3),
        Constraint::Length(1),
        Constraint::Length(3),
        Constraint::Length(1),
        Constraint::Length(3),
        Constraint::Fill(1),
        Constraint::Length(1),
    ])
    .split(inner);

    draw_text_field(f, chunks[0], "Output Directory", &app.output_dir.value, app.options_field == 0);
    draw_text_field(f, chunks[2], "Filter (optional)", &app.filter_input.value, app.options_field == 1);

    // Include raw toggle
    let raw_style = if app.options_field == 2 {
        Style::default().fg(COLOR_ACCENT)
    } else {
        Style::default().fg(COLOR_DIM)
    };
    let raw_block = Block::default()
        .borders(Borders::ALL)
        .border_style(raw_style)
        .title(Span::styled(" Include Raw JSON ", raw_style));
    let raw_text = if app.include_raw {
        Span::styled("  [✓] Enabled ", Style::default().fg(COLOR_SUCCESS).add_modifier(Modifier::BOLD))
    } else {
        Span::styled("  [ ] Disabled", Style::default().fg(COLOR_DIM))
    };
    f.render_widget(Paragraph::new(raw_text).block(raw_block), chunks[4]);

    f.render_widget(hint("Tab switch field   Space toggle raw   Enter confirm   Esc back"), chunks[6]);
}

// ---------------------------------------------------------------------------
// Confirm
// ---------------------------------------------------------------------------

fn draw_confirm(f: &mut Frame, area: Rect, app: &App) {
    let block = centered_rect(65, 70, area);
    f.render_widget(Clear, block);

    let outer = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(COLOR_BRAND))
        .title(title_span(" Confirm "))
        .title_alignment(Alignment::Center);
    f.render_widget(outer, block);

    let inner = inner_rect(block);
    let chunks = Layout::vertical([
        Constraint::Length(1),
        Constraint::Fill(1),
        Constraint::Length(3),
        Constraint::Length(1),
    ])
    .split(inner);

    let collectors = app.selected_collectors().join(", ");
    let filter_display = if app.filter_input.value.is_empty() {
        "none".to_string()
    } else {
        app.filter_input.value.clone()
    };
    let region = app.selected_region();

    let rows: Vec<Line> = vec![
        kv_line("Profile",    app.selected_profile()),
        kv_line("Region",     &region),
        kv_line("Start Date", &app.start_date.value),
        kv_line("End Date",   &app.end_date.value),
        kv_line("Collectors", &collectors),
        kv_line("Output Dir",  &app.output_dir.value),
        kv_line("Filter",     &filter_display),
        kv_line("Include Raw", if app.include_raw { "yes" } else { "no" }),
    ];

    f.render_widget(
        Paragraph::new(Text::from(rows))
            .block(Block::default().padding(Padding::horizontal(1))),
        chunks[1],
    );

    f.render_widget(
        Paragraph::new(Span::styled(
            "  Press  Enter  to start collection",
            Style::default().fg(COLOR_ACCENT).add_modifier(Modifier::BOLD),
        ))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(COLOR_ACCENT)),
        )
        .alignment(Alignment::Center),
        chunks[2],
    );

    f.render_widget(hint("Enter start   Esc back"), chunks[3]);
}

// ---------------------------------------------------------------------------
// Running
// ---------------------------------------------------------------------------

const SPINNER_FRAMES: &[&str] = &["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];

fn draw_running(f: &mut Frame, area: Rect, app: &App) {
    let block = centered_rect(65, 70, area);
    f.render_widget(Clear, block);

    let outer = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(COLOR_BRAND))
        .title(title_span(" Collecting Evidence "))
        .title_alignment(Alignment::Center);
    f.render_widget(outer, block);

    let inner = inner_rect(block);
    let n = app.collector_statuses.len().max(1);
    let item_height = 3u16;
    let list_height = (n as u16) * item_height;

    let chunks = Layout::vertical([
        Constraint::Length(1),
        Constraint::Length(list_height),
        Constraint::Fill(1),
    ])
    .split(inner);

    f.render_widget(
        Paragraph::new(Span::styled(
            "Running collectors...",
            Style::default().fg(COLOR_DIM),
        )),
        chunks[0],
    );

    let spinner = SPINNER_FRAMES[(app.tick as usize / 2) % SPINNER_FRAMES.len()];

    let items: Vec<Line> = app
        .collector_statuses
        .iter()
        .flat_map(|s| {
            let (icon, _label, style) = match &s.state {
                CollectorState::Waiting  => ("  ", "waiting...", Style::default().fg(COLOR_DIM)),
                CollectorState::Running  => (spinner, "running",   Style::default().fg(COLOR_ACCENT)),
                CollectorState::Done(n)  => ("✓ ", &format!("{n} records") as &str, Style::default().fg(COLOR_SUCCESS)),
                CollectorState::Failed(_)=> ("✗ ", "error",      Style::default().fg(COLOR_ERROR)),
            };
            // Need owned strings for the Done case
            let label_owned = match &s.state {
                CollectorState::Done(n)   => format!("{n} records"),
                CollectorState::Failed(m) => format!("error: {m}"),
                CollectorState::Running   => "running…".to_string(),
                CollectorState::Waiting   => "waiting…".to_string(),
            };
            vec![
                Line::from(vec![
                    Span::styled(format!("  {icon} "), style),
                    Span::styled(s.name.clone(), Style::default().add_modifier(Modifier::BOLD)),
                ]),
                Line::from(vec![
                    Span::styled("      ", style),
                    Span::styled(label_owned, style),
                ]),
                Line::raw(""),
            ]
        })
        .collect();

    f.render_widget(Paragraph::new(Text::from(items)), chunks[1]);
}

// ---------------------------------------------------------------------------
// Results
// ---------------------------------------------------------------------------

fn draw_results(f: &mut Frame, area: Rect, app: &App) {
    let block = centered_rect(70, 80, area);
    f.render_widget(Clear, block);

    let outer = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(COLOR_SUCCESS))
        .title(title_span(" Collection Complete "))
        .title_alignment(Alignment::Center);
    f.render_widget(outer, block);

    let inner = inner_rect(block);
    let chunks = Layout::vertical([
        Constraint::Length(2),
        Constraint::Fill(1),
        Constraint::Length(3),
        Constraint::Length(1),
    ])
    .split(inner);

    let file_count = app.result_files.len();
    f.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled("Files written: ", Style::default().fg(COLOR_DIM)),
            Span::styled(
                file_count.to_string(),
                Style::default().fg(COLOR_SUCCESS).add_modifier(Modifier::BOLD),
            ),
        ])),
        chunks[0],
    );

    let rows: Vec<Line> = app
        .result_files
        .iter()
        .flat_map(|path| {
            vec![
                Line::from(vec![
                    Span::styled("  ✓ ", Style::default().fg(COLOR_SUCCESS)),
                    Span::styled(path.clone(), Style::default().fg(Color::White)),
                ]),
                Line::raw(""),
            ]
        })
        .collect();

    f.render_widget(
        Paragraph::new(Text::from(rows))
            .wrap(Wrap { trim: false })
            .block(Block::default().padding(Padding::horizontal(1))),
        chunks[1],
    );

    f.render_widget(
        Paragraph::new(Span::styled(
            "  Each collector's evidence is in its own timestamped file.",
            Style::default().fg(COLOR_DIM),
        ))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(COLOR_DIM)),
        ),
        chunks[2],
    );

    f.render_widget(hint("q / Esc to exit"), chunks[3]);
}

// ---------------------------------------------------------------------------
// Reusable helpers
// ---------------------------------------------------------------------------

fn draw_text_field(f: &mut Frame, area: Rect, label: &str, value: &str, focused: bool) {
    let style = if focused {
        Style::default().fg(COLOR_ACCENT)
    } else {
        Style::default().fg(COLOR_DIM)
    };
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(style)
        .title(Span::styled(format!(" {label} "), style));

    f.render_widget(
        Paragraph::new(format!(" {value}")).block(block),
        area,
    );

    if focused {
        // Show cursor at end of value
        f.set_cursor_position((
            area.x + 1 + value.len() as u16 + 1,
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
    f.render_widget(
        Paragraph::new(Span::styled(
            format!(" ✗  {msg}"),
            Style::default().fg(Color::White).bg(COLOR_ERROR),
        )),
        banner,
    );
}

fn hint(text: &'static str) -> Paragraph<'static> {
    Paragraph::new(Span::styled(
        text,
        Style::default().fg(COLOR_DIM).add_modifier(Modifier::ITALIC),
    ))
    .alignment(Alignment::Center)
}

fn title_span(text: &str) -> Line {
    Line::from(Span::styled(
        text.to_string(),
        Style::default()
            .fg(COLOR_BRAND)
            .add_modifier(Modifier::BOLD),
    ))
}

fn kv_line<'a>(key: &'a str, value: &'a str) -> Line<'a> {
    Line::from(vec![
        Span::styled(format!("  {key:<12}"), Style::default().fg(COLOR_DIM)),
        Span::styled(value, Style::default().fg(Color::White).add_modifier(Modifier::BOLD)),
    ])
}

/// Returns a centered rect using `percent_x` / `percent_y` of the given area.
fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let popup_layout = Layout::vertical([
        Constraint::Percentage((100 - percent_y) / 2),
        Constraint::Percentage(percent_y),
        Constraint::Percentage((100 - percent_y) / 2),
    ])
    .split(r);

    Layout::horizontal([
        Constraint::Percentage((100 - percent_x) / 2),
        Constraint::Percentage(percent_x),
        Constraint::Percentage((100 - percent_x) / 2),
    ])
    .split(popup_layout[1])[1]
}

/// Returns the inner area of a Block (1 cell inset on all sides).
fn inner_rect(outer: Rect) -> Rect {
    Rect {
        x: outer.x + 1,
        y: outer.y + 1,
        width: outer.width.saturating_sub(2),
        height: outer.height.saturating_sub(2),
    }
}
