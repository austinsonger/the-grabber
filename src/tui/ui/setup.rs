use ratatui::layout::{Alignment, Constraint, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::{Block, BorderType, List, ListItem, ListState, Padding, Paragraph};
use ratatui::Frame;

use super::widgets::{content_inset, draw_list_with_detail};
use super::Feature;
use super::{
    App, AMBER, BG_SELECTED, BORDER_SUBTLE, CYAN, CYAN_DIM, GREEN, LOGO, LOGO_COLORS, TEXT_BRIGHT,
    TEXT_DIM, TEXT_NORMAL,
};

// ═══════════════════════════════════════════════════════════════════════════
// Welcome
// ═══════════════════════════════════════════════════════════════════════════

pub(super) fn draw_welcome(f: &mut Frame, area: Rect) {
    let chunks = Layout::vertical([
        Constraint::Fill(1),
        Constraint::Length(6), // logo
        Constraint::Length(1), // blank
        Constraint::Length(1), // decorative divider
        Constraint::Length(1), // blank
        Constraint::Length(1), // title
        Constraint::Length(1), // blank
        Constraint::Length(2), // description
        Constraint::Length(2), // blank
        Constraint::Length(1), // CTA
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
            Style::default()
                .fg(TEXT_BRIGHT)
                .add_modifier(Modifier::BOLD),
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

pub(super) fn draw_feature_selection(f: &mut Frame, area: Rect, app: &App) {
    let chunks = Layout::vertical([
        Constraint::Length(1), // title
        Constraint::Length(1), // subtitle
        Constraint::Length(1), // blank
        Constraint::Fill(1),   // list + detail panels
    ])
    .split(area);

    f.render_widget(
        Paragraph::new(Span::styled(
            "What would you like to do?",
            Style::default()
                .fg(TEXT_BRIGHT)
                .add_modifier(Modifier::BOLD),
        ))
        .alignment(Alignment::Center),
        chunks[0],
    );
    f.render_widget(
        Paragraph::new(Span::styled(
            "Use ↑↓ to select a feature, then press Enter",
            Style::default().fg(TEXT_DIM),
        ))
        .alignment(Alignment::Center),
        chunks[1],
    );

    let options = [
        (
            Feature::Collectors,
            "Collectors",
            "Run 100+ compliance evidence collectors (CloudTrail, S3, IAM, RDS, …)",
        ),
        (
            Feature::Inventory,
            "Inventory",
            "Build a unified asset-inventory CSV across selected AWS resource types",
        ),
        (
            Feature::Poam,
            "POAM",
            "Reconcile Inspector2 ECR findings into FedRAMP-POAM.xlsx (add new, close resolved)",
        ),
    ];

    let items: Vec<(String, String)> = options
        .iter()
        .map(|(_, name, desc)| (name.to_string(), desc.to_string()))
        .collect();
    let selected = options
        .iter()
        .position(|(feature, _, _)| *feature == app.selected_feature)
        .unwrap_or(0);

    draw_list_with_detail(f, chunks[3], "Features", &items, selected);
}

// ═══════════════════════════════════════════════════════════════════════════
// Inventory Asset-Type Selection
// ═══════════════════════════════════════════════════════════════════════════

pub(super) fn draw_inventory_selection(f: &mut Frame, area: Rect, app: &App) {
    let chunks =
        Layout::vertical([Constraint::Length(2), Constraint::Fill(1)]).split(content_inset(area));

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
// Set Dates
// ═══════════════════════════════════════════════════════════════════════════

pub(super) fn draw_dates(f: &mut Frame, area: Rect, app: &App) {
    let chunks =
        Layout::vertical([Constraint::Length(2), Constraint::Fill(1)]).split(content_inset(area));

    f.render_widget(
        Paragraph::new(Span::styled(
            "Select how far back to collect evidence:",
            Style::default().fg(TEXT_DIM),
        )),
        chunks[0],
    );

    const MONTH_LABELS: [&str; 12] = [
        "1 Month",
        "2 Months",
        "3 Months",
        "4 Months",
        "5 Months",
        "6 Months",
        "7 Months",
        "8 Months",
        "9 Months",
        "10 Months",
        "11 Months",
        "12 Months",
    ];

    let items: Vec<ListItem> = MONTH_LABELS
        .iter()
        .enumerate()
        .map(|(i, label)| {
            let selected = i == app.time_frame_cursor;
            let icon = if selected { "▸ " } else { "  " };
            let style = if selected {
                Style::default()
                    .fg(AMBER)
                    .add_modifier(Modifier::BOLD)
                    .bg(BG_SELECTED)
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
// Tenable Endpoint Selection
// ═══════════════════════════════════════════════════════════════════════════

pub(super) fn draw_tenable_endpoint(f: &mut Frame, area: Rect, app: &App) {
    let chunks =
        Layout::vertical([Constraint::Length(2), Constraint::Fill(1)]).split(content_inset(area));

    f.render_widget(
        Paragraph::new(Span::styled(
            "Choose the Tenable endpoint:",
            Style::default().fg(TEXT_DIM),
        )),
        chunks[0],
    );

    const OPTIONS: [crate::tui::state::TenableEndpointChoice; 2] = [
        crate::tui::state::TenableEndpointChoice::Commercial,
        crate::tui::state::TenableEndpointChoice::Fedramp,
    ];

    let items: Vec<ListItem> = OPTIONS
        .iter()
        .enumerate()
        .map(|(i, endpoint)| {
            let selected = i == app.tenable_endpoint_cursor;
            let icon = if selected { "▸ " } else { "  " };
            let style = if selected {
                Style::default()
                    .fg(AMBER)
                    .add_modifier(Modifier::BOLD)
                    .bg(BG_SELECTED)
            } else {
                Style::default().fg(TEXT_NORMAL)
            };

            ListItem::new(Line::from(vec![
                Span::styled(icon, Style::default().fg(AMBER)),
                Span::styled(endpoint.label(), style),
            ]))
        })
        .collect();

    let block = Block::bordered()
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(BORDER_SUBTLE))
        .title(Span::styled(" Endpoint ", Style::default().fg(CYAN_DIM)))
        .padding(Padding::horizontal(1));

    let mut state = ListState::default();
    state.select(Some(app.tenable_endpoint_cursor));

    f.render_stateful_widget(
        List::new(items)
            .highlight_style(Style::default())
            .highlight_symbol("")
            .block(block),
        chunks[1],
        &mut state,
    );
}
