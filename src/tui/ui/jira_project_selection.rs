use ratatui::layout::{Alignment, Constraint, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, List, ListItem, ListState, Paragraph};
use ratatui::Frame;

use super::widgets::content_inset;
use super::{
    App, AMBER, BG_MAIN, BG_SELECTED, BORDER_SUBTLE, GREEN, TEXT_BRIGHT, TEXT_DIM, TEXT_NORMAL,
};

pub(super) fn draw_jira_project_selection(f: &mut Frame, area: Rect, app: &App) {
    let inset = content_inset(area);

    let chunks = Layout::vertical([
        Constraint::Length(1), // title
        Constraint::Length(1), // subtitle
        Constraint::Length(1), // spacer
        Constraint::Fill(1),   // list
    ])
    .split(inset);

    f.render_widget(
        Paragraph::new(Span::styled(
            "Select Jira Projects",
            Style::default()
                .fg(TEXT_BRIGHT)
                .add_modifier(Modifier::BOLD),
        ))
        .alignment(Alignment::Center),
        chunks[0],
    );

    f.render_widget(
        Paragraph::new(Span::styled(
            "Space to toggle, Enter to confirm, Esc to go back",
            Style::default().fg(TEXT_DIM),
        ))
        .alignment(Alignment::Center),
        chunks[1],
    );

    let list_area = chunks[3];

    if app.jira_project_list.is_empty() {
        let block = Block::bordered()
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(BORDER_SUBTLE))
            .style(Style::default().bg(BG_MAIN));
        let inner = block.inner(list_area);
        f.render_widget(block, list_area);

        let v = Layout::vertical([
            Constraint::Fill(1),
            Constraint::Length(1),
            Constraint::Fill(1),
        ])
        .split(inner);
        f.render_widget(
            Paragraph::new(Span::styled(
                "No Jira projects found. Verify your Jira credentials.",
                Style::default().fg(TEXT_DIM),
            ))
            .alignment(Alignment::Center),
            v[1],
        );
        return;
    }

    let mut items: Vec<ListItem> = Vec::with_capacity(app.jira_project_list.len());
    for (i, proj) in app.jira_project_list.iter().enumerate() {
        let at_cursor = i == app.jira_project_cursor;
        let checked = app.jira_project_selected.contains(&i);

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

        items.push(ListItem::new(Line::from(vec![
            Span::styled(checkbox, checkbox_style),
            Span::styled(
                format!("{:<12}", proj.key),
                Style::default().fg(TEXT_NORMAL),
            ),
            Span::styled("  ", Style::default()),
            Span::styled(proj.name.clone(), name_style),
        ])));
    }

    let mut state = ListState::default();
    state.select(Some(app.jira_project_cursor));

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
