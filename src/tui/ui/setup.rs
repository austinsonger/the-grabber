use ratatui::layout::{Alignment, Constraint, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::{Block, BorderType, List, ListItem, ListState, Padding, Paragraph};
use ratatui::Frame;

use super::widgets::{content_inset, draw_text_field};
use super::Feature;
use super::{
    App, AMBER, BG_ELEVATED, BG_MAIN, BG_SELECTED, BORDER_SUBTLE, CYAN, CYAN_DIM, GREEN, LOGO,
    LOGO_COLORS, TEXT_BRIGHT, TEXT_DIM, TEXT_NORMAL,
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
        Constraint::Fill(1),
        Constraint::Length(1), // title
        Constraint::Length(1), // subtitle
        Constraint::Length(2), // blank
        Constraint::Length(5), // Collectors card
        Constraint::Length(1), // gap
        Constraint::Length(5), // Inventory card
        Constraint::Length(1), // gap
        Constraint::Length(5), // POAM card
        Constraint::Fill(1),
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
        chunks[1],
    );
    f.render_widget(
        Paragraph::new(Span::styled(
            "Use ↑↓ to select a feature, then press Enter",
            Style::default().fg(TEXT_DIM),
        ))
        .alignment(Alignment::Center),
        chunks[2],
    );

    let options = [
        (
            Feature::Collectors,
            "◆  Collectors",
            "Run 100+ compliance evidence collectors (CloudTrail, S3, IAM, RDS, …)",
        ),
        (
            Feature::Inventory,
            "◆  Inventory",
            "Build a unified asset-inventory CSV across selected AWS resource types",
        ),
        (
            Feature::Poam,
            "◆  POAM",
            "Reconcile Inspector2 ECR findings into FedRAMP-POAM.xlsx (add new, close resolved)",
        ),
    ];

    let card_areas = [chunks[4], chunks[6], chunks[8]];
    for (idx, (feature, label, desc)) in options.iter().enumerate() {
        let selected = app.selected_feature == *feature;
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
        let inner = card_block.inner(card_areas[idx]);
        f.render_widget(card_block, card_areas[idx]);

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
