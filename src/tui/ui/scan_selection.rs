use ratatui::layout::{Alignment, Constraint, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, List, ListItem, ListState, Paragraph};
use ratatui::Frame;

use super::widgets::content_inset;
use super::{
    App, AMBER, BG_ELEVATED, BG_MAIN, BG_SELECTED, BORDER_SUBTLE, CYAN, GREEN, TEXT_BRIGHT,
    TEXT_DIM, TEXT_NORMAL,
};

use crate::tui::state::ScanTimeFilter;
use tenable_rs::types::scan::ScanStatus;

// ═══════════════════════════════════════════════════════════════════════════
// Scan Selection
// ═══════════════════════════════════════════════════════════════════════════

pub(super) fn draw_scan_selection(f: &mut Frame, area: Rect, app: &App) {
    let inset = content_inset(area);

    let chunks = Layout::vertical([
        Constraint::Length(1), // title
        Constraint::Length(1), // subtitle
        Constraint::Length(1), // spacer
        Constraint::Length(1), // tab bar
        Constraint::Length(1), // spacer
        Constraint::Fill(1),   // scrollable list
    ])
    .split(inset);

    // Title
    f.render_widget(
        Paragraph::new(Span::styled(
            "Select Scans",
            Style::default()
                .fg(TEXT_BRIGHT)
                .add_modifier(Modifier::BOLD),
        ))
        .alignment(Alignment::Center),
        chunks[0],
    );

    // Subtitle
    f.render_widget(
        Paragraph::new(Span::styled(
            "Use Tab to switch filter, Space to toggle, Enter to confirm",
            Style::default().fg(TEXT_DIM),
        ))
        .alignment(Alignment::Center),
        chunks[1],
    );

    // Tab bar
    let recent_style = if app.scan_filter == ScanTimeFilter::Recent {
        Style::default().fg(AMBER).add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(TEXT_DIM)
    };
    let past12_style = if app.scan_filter == ScanTimeFilter::Past12Months {
        Style::default().fg(AMBER).add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(TEXT_DIM)
    };

    f.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled("[ Recent (30d) ]", recent_style),
            Span::styled("   ", Style::default()),
            Span::styled("[ Past 12 Months ]", past12_style),
        ]))
        .alignment(Alignment::Center),
        chunks[3],
    );

    // Scrollable scan list
    let list_area = chunks[5];
    let visible = app.visible_scans();

    if visible.is_empty() {
        let block = Block::bordered()
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(BORDER_SUBTLE))
            .style(Style::default().bg(BG_MAIN));
        let inner = block.inner(list_area);
        f.render_widget(block, list_area);

        let v_chunks = Layout::vertical([
            Constraint::Fill(1),
            Constraint::Length(1),
            Constraint::Fill(1),
        ])
        .split(inner);
        f.render_widget(
            Paragraph::new(Span::styled(
                "No scans found. Verify your Tenable credentials.",
                Style::default().fg(TEXT_DIM),
            ))
            .alignment(Alignment::Center),
            v_chunks[1],
        );
        return;
    }

    let mut items: Vec<ListItem> = Vec::with_capacity(visible.len());
    for (cursor_pos, &real_idx) in visible.iter().enumerate() {
        let scan = &app.scan_list[real_idx];
        let at_cursor = cursor_pos == app.scan_cursor;
        let checked = app.scan_selected.contains(&real_idx);

        let checkbox = if checked { "[✓] " } else { "[ ] " };
        let checkbox_style = if checked {
            Style::default().fg(GREEN)
        } else {
            Style::default().fg(TEXT_DIM)
        };

        let name_style = if at_cursor {
            Style::default()
                .fg(AMBER)
                .add_modifier(Modifier::BOLD)
                .bg(BG_SELECTED)
        } else {
            Style::default()
                .fg(TEXT_BRIGHT)
                .add_modifier(Modifier::BOLD)
        };

        let status_str = match scan.status {
            ScanStatus::Running => "RUNNING",
            ScanStatus::Completed => "COMPLETED",
            ScanStatus::Canceled => "CANCELED",
            ScanStatus::Paused => "PAUSED",
            ScanStatus::Pending => "PENDING",
            ScanStatus::Stopping => "STOPPING",
            ScanStatus::Unknown => "UNKNOWN",
        };
        let status_style = match scan.status {
            ScanStatus::Running => Style::default().fg(CYAN),
            ScanStatus::Completed => Style::default().fg(GREEN),
            ScanStatus::Canceled | ScanStatus::Unknown => Style::default().fg(TEXT_DIM),
            _ => Style::default().fg(TEXT_NORMAL),
        };

        let date_str = scan
            .last_modification_date
            .and_then(|ts| chrono::DateTime::from_timestamp(ts, 0))
            .map(|dt| dt.format("%Y-%m-%d").to_string())
            .unwrap_or_default();

        items.push(ListItem::new(Line::from(vec![
            Span::styled(checkbox, checkbox_style),
            Span::styled(&scan.name, name_style),
            Span::styled("   ", Style::default()),
            Span::styled(status_str, status_style),
            Span::styled("   ", Style::default()),
            Span::styled(date_str, Style::default().fg(TEXT_DIM)),
        ])));
    }

    let mut state = ListState::default();
    state.select(Some(app.scan_cursor));

    let block = Block::bordered()
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(BORDER_SUBTLE))
        .style(Style::default().bg(BG_MAIN));

    f.render_stateful_widget(
        List::new(items)
            .highlight_style(Style::default())
            .highlight_symbol("")
            .block(block),
        list_area,
        &mut state,
    );
}
