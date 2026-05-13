use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::{Block, BorderType, Gauge, List, ListItem, ListState, Paragraph};
use ratatui::Frame;

use super::widgets::{content_inset, format_duration, format_number, stat_line};
use super::{
    App, CollectorState, AMBER, BG_ELEVATED, BORDER_SUBTLE, CYAN, CYAN_DIM, GREEN, RED,
    SPINNER_FRAMES, TEXT_BRIGHT, TEXT_DIM, TEXT_NORMAL,
};

pub(super) fn draw_running(f: &mut Frame, area: Rect, app: &App) {
    let inset = content_inset(area);

    // Always show a status line when we have account or region info.
    let multi_account = app.total_account_count > 1;
    let has_status = multi_account || app.current_region_label.is_some();
    let (status_area, rest) = if has_status {
        let parts = Layout::vertical([
            Constraint::Length(1), // status line
            Constraint::Length(1), // blank
            Constraint::Fill(1),   // rest
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
                format!(
                    "Account {} of {}: {}",
                    app.current_account_index, app.total_account_count, label
                ),
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
        let columns = Layout::horizontal([Constraint::Percentage(60), Constraint::Percentage(40)])
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
            Constraint::Fill(1),   // list
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
        Constraint::Fill(1),   // list
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
            .label(Span::styled(
                label,
                Style::default()
                    .fg(TEXT_BRIGHT)
                    .add_modifier(Modifier::BOLD),
            )),
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
    let chunks = Layout::vertical([Constraint::Length(8), Constraint::Fill(1)]).split(area);

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
        .filter_map(|s| {
            if let CollectorState::Done(n) = s.state {
                Some(n)
            } else {
                None
            }
        })
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
        Style::default()
            .fg(TEXT_BRIGHT)
            .add_modifier(Modifier::BOLD)
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
                    Span::styled(format!("{}: {}", s.name, m), Style::default().fg(RED)),
                ]));
            }
            CollectorState::Running => {
                log_lines.push(Line::from(vec![
                    Span::styled("  ▸ ", Style::default().fg(AMBER)),
                    Span::styled(format!("{} started", s.name), Style::default().fg(AMBER)),
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
        .filter_map(|s| {
            if let CollectorState::Done(n) = s.state {
                Some(n)
            } else {
                None
            }
        })
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
            Span::styled(
                &elapsed,
                Style::default()
                    .fg(TEXT_BRIGHT)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled("   Done ", Style::default().fg(TEXT_DIM)),
            Span::styled(
                format!("{}/{}", completed, total),
                Style::default()
                    .fg(TEXT_BRIGHT)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled("   Records ", Style::default().fg(TEXT_DIM)),
            Span::styled(
                format_number(total_records),
                Style::default()
                    .fg(TEXT_BRIGHT)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled("   Errors ", Style::default().fg(TEXT_DIM)),
            Span::styled(
                errors.to_string(),
                if errors > 0 {
                    Style::default().fg(RED).add_modifier(Modifier::BOLD)
                } else {
                    Style::default()
                        .fg(TEXT_BRIGHT)
                        .add_modifier(Modifier::BOLD)
                },
            ),
        ])),
        area,
    );
}
