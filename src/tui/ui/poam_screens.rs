use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, List, ListItem, ListState, Padding, Paragraph};
use ratatui::Frame;

use super::widgets::{content_inset, draw_text_field};
use super::{App, AMBER, BG_SELECTED, BORDER_SUBTLE, CYAN_DIM, TEXT_DIM, TEXT_NORMAL};

// ═══════════════════════════════════════════════════════════════════════════
// POAM Account / Region / Year / Month
// ═══════════════════════════════════════════════════════════════════════════

pub(super) fn draw_poam_account(f: &mut Frame, area: Rect, app: &App) {
    let chunks =
        Layout::vertical([Constraint::Length(2), Constraint::Fill(1)]).split(content_inset(area));

    f.render_widget(
        Paragraph::new(Span::styled(
            "Select the account whose evidence directory contains Inspector2 ECR findings:",
            Style::default().fg(TEXT_DIM),
        )),
        chunks[0],
    );

    let items: Vec<ListItem> = app
        .accounts
        .iter()
        .enumerate()
        .map(|(i, acct)| {
            let selected = i == app.poam_account_cursor;
            let icon = if selected { "▸ " } else { "  " };
            let name_style = if selected {
                Style::default()
                    .fg(AMBER)
                    .add_modifier(Modifier::BOLD)
                    .bg(BG_SELECTED)
            } else {
                Style::default().fg(TEXT_NORMAL)
            };
            let base = acct
                .output_dir
                .as_deref()
                .unwrap_or("")
                .trim_start_matches("./");
            ListItem::new(Line::from(vec![
                Span::styled(icon, Style::default().fg(AMBER)),
                Span::styled(format!("{:<32}", acct.name), name_style),
                Span::styled(format!("  {base}"), Style::default().fg(TEXT_DIM)),
            ]))
        })
        .collect();

    let block = Block::bordered()
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(BORDER_SUBTLE))
        .title(Span::styled(
            " Configured Accounts ",
            Style::default().fg(CYAN_DIM),
        ))
        .padding(Padding::horizontal(1));

    let mut state = ListState::default();
    state.select(Some(app.poam_account_cursor));
    f.render_stateful_widget(List::new(items).block(block), chunks[1], &mut state);
}

pub(super) fn draw_poam_region(f: &mut Frame, area: Rect, app: &App) {
    let chunks =
        Layout::vertical([Constraint::Length(2), Constraint::Fill(1)]).split(content_inset(area));

    f.render_widget(
        Paragraph::new(Span::styled(
            "Select the AWS region containing Inspector2 ECR findings:",
            Style::default().fg(TEXT_DIM),
        )),
        chunks[0],
    );

    let items: Vec<ListItem> = app
        .regions
        .iter()
        .enumerate()
        .map(|(i, r)| {
            let selected = i == app.poam_region_cursor;
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
                Span::styled(*r, style),
            ]))
        })
        .collect();

    let block = Block::bordered()
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(BORDER_SUBTLE))
        .title(Span::styled(
            " Supported Regions ",
            Style::default().fg(CYAN_DIM),
        ))
        .padding(Padding::horizontal(1));

    let mut state = ListState::default();
    state.select(Some(app.poam_region_cursor));
    f.render_stateful_widget(List::new(items).block(block), chunks[1], &mut state);
}

pub(super) fn draw_poam_year(f: &mut Frame, area: Rect, app: &App) {
    let chunks = Layout::vertical([
        Constraint::Length(2),
        Constraint::Length(3),
        Constraint::Length(2),
        Constraint::Fill(1),
    ])
    .split(content_inset(area));

    f.render_widget(
        Paragraph::new(Span::styled(
            "Enter findings year (YYYY):",
            Style::default().fg(TEXT_DIM),
        )),
        chunks[0],
    );
    draw_text_field(f, chunks[1], "Findings Year", &app.poam_year.value, true);
    f.render_widget(
        Paragraph::new(Span::styled(
            format!("Default: {}", chrono::Local::now().format("%Y")),
            Style::default().fg(TEXT_DIM),
        )),
        chunks[2],
    );
}

pub(super) fn draw_poam_month(f: &mut Frame, area: Rect, app: &App) {
    const MONTHS: [(&str, &str); 12] = [
        ("January", "01-JAN"),
        ("February", "02-FEB"),
        ("March", "03-MAR"),
        ("April", "04-APR"),
        ("May", "05-MAY"),
        ("June", "06-JUN"),
        ("July", "07-JUL"),
        ("August", "08-AUG"),
        ("September", "09-SEP"),
        ("October", "10-OCT"),
        ("November", "11-NOV"),
        ("December", "12-DEC"),
    ];

    let chunks =
        Layout::vertical([Constraint::Length(2), Constraint::Fill(1)]).split(content_inset(area));

    f.render_widget(
        Paragraph::new(Span::styled(
            "Select findings month:",
            Style::default().fg(TEXT_DIM),
        )),
        chunks[0],
    );

    let items: Vec<ListItem> = MONTHS
        .iter()
        .enumerate()
        .map(|(i, (name, folder))| {
            let selected = i == app.poam_month_cursor;
            let icon = if selected { "▸ " } else { "  " };
            let name_style = if selected {
                Style::default()
                    .fg(AMBER)
                    .add_modifier(Modifier::BOLD)
                    .bg(BG_SELECTED)
            } else {
                Style::default().fg(TEXT_NORMAL)
            };
            ListItem::new(Line::from(vec![
                Span::styled(icon, Style::default().fg(AMBER)),
                Span::styled(format!("{:<12}", name), name_style),
                Span::styled(format!(" ({folder})"), Style::default().fg(TEXT_DIM)),
            ]))
        })
        .collect();

    let block = Block::bordered()
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(BORDER_SUBTLE))
        .padding(Padding::horizontal(1));

    let mut state = ListState::default();
    state.select(Some(app.poam_month_cursor));
    f.render_stateful_widget(List::new(items).block(block), chunks[1], &mut state);
}
