use ratatui::layout::{Alignment, Constraint, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, List, ListItem, ListState, Paragraph};
use ratatui::Frame;

use super::widgets::content_inset;
use super::{
    App, AMBER, BG_MAIN, BG_SELECTED, BORDER_SUBTLE, GREEN, RED, TEXT_BRIGHT, TEXT_DIM, TEXT_NORMAL,
};

// ═══════════════════════════════════════════════════════════════════════════
// SBOM export destination (bucket / KMS key / prefix)
// ═══════════════════════════════════════════════════════════════════════════

pub(super) fn draw_sbom_destination(f: &mut Frame, area: Rect, app: &App) {
    let inset = content_inset(area);

    let chunks = Layout::vertical([
        Constraint::Length(1), // title
        Constraint::Length(1), // subtitle
        Constraint::Length(1), // spacer
        Constraint::Length(3), // bucket
        Constraint::Length(3), // kms
        Constraint::Length(3), // prefix
        Constraint::Fill(1),   // note
    ])
    .split(inset);

    f.render_widget(
        Paragraph::new(Span::styled(
            "Inspector SBOM Export Destination",
            Style::default()
                .fg(TEXT_BRIGHT)
                .add_modifier(Modifier::BOLD),
        ))
        .alignment(Alignment::Center),
        chunks[0],
    );

    f.render_widget(
        Paragraph::new(Span::styled(
            "↑↓ to switch field, type to edit, Enter to discover repositories",
            Style::default().fg(TEXT_DIM),
        ))
        .alignment(Alignment::Center),
        chunks[1],
    );

    let fields = [
        ("S3 Bucket (required)", &app.sbom_bucket_input.value, 0usize),
        ("KMS Key ARN (required)", &app.sbom_kms_input.value, 1usize),
        (
            "Key Prefix (optional)",
            &app.sbom_prefix_input.value,
            2usize,
        ),
    ];

    for (label, value, idx) in fields {
        let focused = app.sbom_dest_field == idx;
        let border_style = if focused {
            Style::default().fg(AMBER)
        } else {
            Style::default().fg(BORDER_SUBTLE)
        };
        let shown = if focused {
            format!("{value}▏")
        } else {
            value.to_string()
        };
        f.render_widget(
            Paragraph::new(Span::styled(shown, Style::default().fg(TEXT_NORMAL))).block(
                Block::bordered()
                    .border_type(BorderType::Rounded)
                    .border_style(border_style)
                    .style(Style::default().bg(BG_MAIN))
                    .title(Span::styled(label, Style::default().fg(TEXT_DIM))),
            ),
            chunks[3 + idx],
        );
    }

    f.render_widget(
        Paragraph::new(vec![
            Line::from(Span::styled(
                "Inspector writes the export into this bucket, then grabber downloads",
                Style::default().fg(TEXT_DIM),
            )),
            Line::from(Span::styled(
                "the SBOM for the newest scanned image of each repository you pick.",
                Style::default().fg(TEXT_DIM),
            )),
        ])
        .alignment(Alignment::Center),
        chunks[6],
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// Repository discovery (async work in progress)
// ═══════════════════════════════════════════════════════════════════════════

pub(super) fn draw_sbom_repo_discovery(f: &mut Frame, area: Rect, _app: &App) {
    let inset = content_inset(area);

    let chunks = Layout::vertical([
        Constraint::Fill(1),
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Fill(1),
    ])
    .split(inset);

    f.render_widget(
        Paragraph::new(Span::styled(
            "Discovering ECR repositories…",
            Style::default()
                .fg(TEXT_BRIGHT)
                .add_modifier(Modifier::BOLD),
        ))
        .alignment(Alignment::Center),
        chunks[1],
    );

    f.render_widget(
        Paragraph::new(Span::styled(
            "Calling ecr:DescribeRepositories for the first selected AWS account",
            Style::default().fg(TEXT_DIM),
        ))
        .alignment(Alignment::Center),
        chunks[2],
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// Repository picker
// ═══════════════════════════════════════════════════════════════════════════

pub(super) fn draw_sbom_repo_selection(f: &mut Frame, area: Rect, app: &App) {
    let inset = content_inset(area);

    let chunks = Layout::vertical([
        Constraint::Length(1), // title
        Constraint::Length(1), // subtitle
        Constraint::Length(1), // spacer
        Constraint::Length(3), // search
        Constraint::Fill(1),   // list
    ])
    .split(inset);

    f.render_widget(
        Paragraph::new(Span::styled(
            "Select ECR Repositories for SBOM Export",
            Style::default()
                .fg(TEXT_BRIGHT)
                .add_modifier(Modifier::BOLD),
        ))
        .alignment(Alignment::Center),
        chunks[0],
    );

    let selected_count = app.sbom_repo_selected.len();
    f.render_widget(
        Paragraph::new(Span::styled(
            format!(
                "Space to toggle, a = all, d = none, Enter to confirm — {selected_count} selected"
            ),
            Style::default().fg(TEXT_DIM),
        ))
        .alignment(Alignment::Center),
        chunks[1],
    );

    f.render_widget(
        Paragraph::new(Span::styled(
            format!("{}▏", app.sbom_repo_search.value),
            Style::default().fg(TEXT_NORMAL),
        ))
        .block(
            Block::bordered()
                .border_type(BorderType::Rounded)
                .border_style(Style::default().fg(BORDER_SUBTLE))
                .style(Style::default().bg(BG_MAIN))
                .title(Span::styled("Filter", Style::default().fg(TEXT_DIM))),
        ),
        chunks[3],
    );

    let list_area = chunks[4];
    let visible = app.visible_sbom_repos();

    if visible.is_empty() {
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

        let (msg, style) = match app.sbom_discovery_error.as_deref() {
            Some(err) => (err.to_string(), Style::default().fg(RED)),
            None if app.sbom_repo_list.is_empty() => (
                "No ECR repositories found in this account/region.".to_string(),
                Style::default().fg(TEXT_DIM),
            ),
            None => (
                "No repositories match the filter.".to_string(),
                Style::default().fg(TEXT_DIM),
            ),
        };
        f.render_widget(
            Paragraph::new(Span::styled(msg, style)).alignment(Alignment::Center),
            v[1],
        );
        return;
    }

    let mut items: Vec<ListItem> = Vec::with_capacity(visible.len());
    for (cursor_pos, &real_idx) in visible.iter().enumerate() {
        let repo = &app.sbom_repo_list[real_idx];
        let at_cursor = cursor_pos == app.sbom_repo_cursor;
        let checked = app.sbom_repo_selected.contains(&real_idx);

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
            Span::styled(format!("{:<40}", repo.name), name_style),
            Span::styled("  ", Style::default()),
            Span::styled(repo.uri.clone(), Style::default().fg(TEXT_DIM)),
        ])));
    }

    let mut state = ListState::default();
    state.select(Some(app.sbom_repo_cursor));

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
