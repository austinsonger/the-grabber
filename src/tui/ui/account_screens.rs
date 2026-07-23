use ratatui::layout::{Alignment, Constraint, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::{Block, BorderType, List, ListItem, ListState, Padding, Paragraph};
use ratatui::Frame;

use super::widgets::{content_inset, draw_text_field};
use super::{
    App, AMBER, BG_ELEVATED, BG_MAIN, BG_SELECTED, BORDER_SUBTLE, CYAN, CYAN_DIM, GREEN,
    TEXT_BRIGHT, TEXT_DIM, TEXT_NORMAL,
};

// ═══════════════════════════════════════════════════════════════════════════
// Select Provider
// ═══════════════════════════════════════════════════════════════════════════

pub(super) fn draw_provider_selection(f: &mut Frame, area: Rect, app: &App) {
    use crate::providers::CloudProvider;

    let providers: Vec<(CloudProvider, &str, &str)> = {
        let mut v = vec![(
            CloudProvider::Aws,
            "◆  Amazon Web Services (AWS)",
            "Run 100+ compliance evidence collectors (CloudTrail, S3, IAM, RDS, …)",
        )];
        #[cfg(feature = "azure")]
        v.push((
            CloudProvider::Azure,
            "◆  Microsoft Azure",
            "Collect compliance evidence from Azure resources",
        ));
        #[cfg(feature = "gcp")]
        v.push((
            CloudProvider::Gcp,
            "◆  Google Cloud Platform (GCP)",
            "Collect compliance evidence from GCP resources",
        ));
        #[cfg(feature = "tenable")]
        v.push((
            CloudProvider::Tenable,
            "◆  Tenable",
            "Export vulnerability findings from Tenable.io or Tenable.sc",
        ));
        #[cfg(feature = "okta")]
        v.push((
            CloudProvider::Okta,
            "◆  Okta",
            "Collect users, groups, apps, policies, MFA factors, and system log events",
        ));
        #[cfg(feature = "jira")]
        v.push((
            CloudProvider::Jira,
            "◆  Jira",
            "Collect projects and issues from Jira Cloud or Jira Server",
        ));
        #[cfg(feature = "elastic")]
        v.push((
            CloudProvider::Elastic,
            "◆  Elastic Security",
            "Collect detection rules, exception items, alerts, and cases from Elastic SIEM",
        ));
        #[cfg(feature = "jamf")]
        v.push((
            CloudProvider::Jamf,
            "◆  Jamf",
            "Collect computer/mobile device inventory, configuration profiles, policies, and patch compliance from Jamf Pro",
        ));
        v
    };

    let card_height: u16 = 5;
    let gap: u16 = 1;
    let total_cards_height =
        providers.len() as u16 * card_height + providers.len().saturating_sub(1) as u16 * gap;

    let chunks = Layout::vertical([
        Constraint::Fill(1),
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Length(2),
        Constraint::Length(total_cards_height),
        Constraint::Fill(1),
    ])
    .split(area);

    f.render_widget(
        Paragraph::new(Span::styled(
            "Select a cloud provider:",
            Style::default()
                .fg(TEXT_BRIGHT)
                .add_modifier(Modifier::BOLD),
        ))
        .alignment(Alignment::Center),
        chunks[1],
    );
    f.render_widget(
        Paragraph::new(Span::styled(
            "Use ↑↓ to select a provider, then press Enter",
            Style::default().fg(TEXT_DIM),
        ))
        .alignment(Alignment::Center),
        chunks[2],
    );

    let cards_area = chunks[4];
    for (idx, (provider, label, desc)) in providers.iter().enumerate() {
        let selected = app.selected_provider == *provider;
        let card_area = Rect {
            x: cards_area.x,
            y: cards_area.y + idx as u16 * (card_height + gap),
            width: cards_area.width,
            height: card_height,
        };

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
            .border_type(if selected {
                BorderType::Thick
            } else {
                BorderType::Plain
            })
            .border_style(border_style)
            .style(Style::default().bg(if selected { BG_ELEVATED } else { BG_MAIN }));
        let inner = card_block.inner(card_area);
        f.render_widget(card_block, card_area);

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
// Select Account (NEW)
// ═══════════════════════════════════════════════════════════════════════════

pub(super) fn draw_select_account(f: &mut Frame, area: Rect, app: &App) {
    let indices = app.provider_account_indices();

    let chunks =
        Layout::vertical([Constraint::Length(2), Constraint::Fill(1)]).split(content_inset(area));

    let selected_count = app
        .selected_accounts
        .iter()
        .filter(|&&i| {
            app.accounts
                .get(i)
                .map(|a| a.provider == app.selected_provider)
                .unwrap_or(false)
        })
        .count();

    let count_text = format!(
        "Select {} account(s) to collect evidence from:  ({} of {} selected)",
        app.selected_provider,
        selected_count,
        indices.len(),
    );
    f.render_widget(
        Paragraph::new(Span::styled(count_text, Style::default().fg(TEXT_DIM))),
        chunks[0],
    );

    let total_entries = indices.len() + 2;
    let mut items: Vec<ListItem> = Vec::with_capacity(total_entries);

    for (cursor_pos, &real_idx) in indices.iter().enumerate() {
        let acct = &app.accounts[real_idx];
        let at_cursor = cursor_pos == app.account_cursor;
        let checked = app.selected_accounts.contains(&real_idx);
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

    let sep_width = chunks[1].width.saturating_sub(6) as usize;
    items.push(ListItem::new(Line::from(Span::styled(
        format!("  {}", "┄".repeat(sep_width)),
        Style::default().fg(BORDER_SUBTLE),
    ))));

    let other_selected = app.account_cursor == indices.len();
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
