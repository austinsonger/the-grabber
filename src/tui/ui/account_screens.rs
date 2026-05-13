use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::{Block, BorderType, List, ListItem, ListState, Padding, Paragraph};
use ratatui::Frame;

use super::widgets::{content_inset, draw_text_field};
use super::{
    App, AMBER, BG_SELECTED, BORDER_SUBTLE, CYAN_DIM, GREEN, TEXT_BRIGHT, TEXT_DIM, TEXT_NORMAL,
};

// ═══════════════════════════════════════════════════════════════════════════
// Select Account (NEW)
// ═══════════════════════════════════════════════════════════════════════════

pub(super) fn draw_select_account(f: &mut Frame, area: Rect, app: &App) {
    let chunks =
        Layout::vertical([Constraint::Length(2), Constraint::Fill(1)]).split(content_inset(area));

    let count_text = format!(
        "Select AWS account(s) to collect evidence from:  ({} of {} selected)",
        app.selected_accounts.len(),
        app.accounts.len(),
    );
    f.render_widget(
        Paragraph::new(Span::styled(count_text, Style::default().fg(TEXT_DIM))),
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
            Style::default()
                .fg(AMBER)
                .add_modifier(Modifier::BOLD)
                .bg(BG_SELECTED)
        } else {
            Style::default()
                .fg(TEXT_BRIGHT)
                .add_modifier(Modifier::BOLD)
        };

        let checkbox_style = if checked {
            Style::default().fg(GREEN)
        } else {
            Style::default().fg(TEXT_DIM)
        };

        let detail = format!(
            "      {} · {} · {}",
            acct.account_id.as_deref().unwrap_or(""),
            acct.profile.as_deref().unwrap_or(""),
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
        Style::default()
            .fg(AMBER)
            .add_modifier(Modifier::BOLD)
            .bg(BG_SELECTED)
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

pub(super) fn draw_profile(f: &mut Frame, area: Rect, app: &App) {
    let chunks =
        Layout::vertical([Constraint::Length(2), Constraint::Fill(1)]).split(content_inset(area));

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
                Style::default()
                    .fg(AMBER)
                    .add_modifier(Modifier::BOLD)
                    .bg(BG_SELECTED)
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

pub(super) fn draw_region(f: &mut Frame, area: Rect, app: &App) {
    let region_names: &[(&str, &str)] = &[
        ("us-east-1", "N. Virginia"),
        ("us-east-2", "Ohio"),
        ("us-west-1", "N. California"),
        ("us-west-2", "Oregon"),
        ("eu-west-1", "Ireland"),
        ("eu-central-1", "Frankfurt"),
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
            let friendly = region_names
                .iter()
                .find(|(code, _)| code == r)
                .map(|(_, name)| *name)
                .unwrap_or("");
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
        .title(Span::styled(
            " Available Regions ",
            Style::default().fg(CYAN_DIM),
        ))
        .padding(Padding::horizontal(1));

    f.render_stateful_widget(List::new(items).block(list_block), chunks[1], &mut state);

    // Custom region input
    let custom_focused = app.region_use_custom;
    draw_text_field(
        f,
        chunks[2],
        "Custom Region",
        &app.region_custom.value,
        custom_focused,
    );
}
