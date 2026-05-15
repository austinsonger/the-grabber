use ratatui::layout::{Alignment, Constraint, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::{Block, BorderType, List, ListItem, ListState, Paragraph};
use ratatui::Frame;

use super::widgets::{content_inset, draw_stat_card, format_duration, format_number, kv_line};
use super::{
    App, CollectorState, Feature, AMBER, BG_ELEVATED, BG_MAIN, BORDER_SUBTLE, CYAN, CYAN_DIM,
    GREEN, PURPLE, RED, RED_BG, TEXT_DIM, TEXT_NORMAL,
};

pub(super) fn draw_results(f: &mut Frame, area: Rect, app: &App) {
    if matches!(app.selected_feature, Feature::Poam) {
        draw_poam_results(f, area, app);
        return;
    }

    let inset = content_inset(area);

    let has_errors = !app.error_messages.is_empty();
    let has_zip = app.result_zip.is_some();
    let has_sign = app.result_signing_manifest.is_some();
    let error_height = if has_errors {
        // Show up to 8 error lines, plus border
        (app.error_messages.len().min(8) as u16) + 2
    } else {
        0
    };

    let chunks = Layout::vertical([
        Constraint::Length(3),                              // [0] success banner
        Constraint::Length(1),                              // [1] blank
        Constraint::Length(5),                              // [2] stat cards
        Constraint::Length(1),                              // [3] blank
        Constraint::Fill(1),                                // [4] file list
        Constraint::Length(if has_zip { 1 } else { 0 }),    // [5] blank before zip
        Constraint::Length(if has_zip { 3 } else { 0 }),    // [6] zip path banner
        Constraint::Length(if has_sign { 1 } else { 0 }),   // [7] blank before sign
        Constraint::Length(if has_sign { 4 } else { 0 }),   // [8] sign manifest+key banner
        Constraint::Length(if has_errors { 1 } else { 0 }), // [9] blank before errors
        Constraint::Length(error_height),                   // [10] error list
    ])
    .split(inset);

    // Success banner — change color/text if there were errors
    let (banner_text, banner_color) = if has_errors {
        ("!  Collection Complete (with errors)", AMBER)
    } else {
        ("✓  Collection Complete", GREEN)
    };
    let banner_block = Block::bordered()
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(banner_color));
    f.render_widget(
        Paragraph::new(Span::styled(
            banner_text,
            Style::default()
                .fg(banner_color)
                .add_modifier(Modifier::BOLD),
        ))
        .alignment(Alignment::Center)
        .block(banner_block),
        chunks[0],
    );

    // Stat cards
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
    let elapsed = format_duration(app.finished_tick.unwrap_or(app.tick));
    let error_count = app.error_messages.len();

    let cards = Layout::horizontal([
        Constraint::Ratio(1, 4),
        Constraint::Ratio(1, 4),
        Constraint::Ratio(1, 4),
        Constraint::Ratio(1, 4),
    ])
    .split(chunks[2]);

    draw_stat_card(
        f,
        cards[0],
        "Files",
        &app.result_files.len().to_string(),
        CYAN,
    );
    draw_stat_card(f, cards[1], "Records", &format_number(total_records), AMBER);
    draw_stat_card(
        f,
        cards[2],
        "Errors",
        &error_count.to_string(),
        if error_count > 0 { RED } else { GREEN },
    );
    draw_stat_card(f, cards[3], "Duration", &elapsed, PURPLE);

    // File list
    let file_items: Vec<ListItem> = app
        .result_files
        .iter()
        .enumerate()
        .map(|(i, path)| {
            let bg = if i % 2 == 0 { BG_MAIN } else { BG_ELEVATED };
            ListItem::new(Line::from(vec![
                Span::styled("  ✓ ", Style::default().fg(GREEN)),
                Span::styled(path.as_str(), Style::default().fg(TEXT_NORMAL)),
            ]))
            .style(Style::default().bg(bg))
        })
        .collect();

    let file_block = Block::bordered()
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(BORDER_SUBTLE))
        .title(Span::styled(
            " Output Files ",
            Style::default().fg(CYAN_DIM),
        ));

    let mut state = ListState::default();
    if !app.result_files.is_empty() {
        state.select(Some(app.result_scroll.min(app.result_files.len() - 1)));
    }

    f.render_stateful_widget(
        List::new(file_items).block(file_block).highlight_symbol(""),
        chunks[4],
        &mut state,
    );

    // Zip path banner (only shown when a bundle was created)
    if let Some(zip) = &app.result_zip {
        f.render_widget(
            Paragraph::new(Line::from(vec![
                Span::styled("  ⬇ ", Style::default().fg(GREEN)),
                Span::styled("Zip bundle: ", Style::default().fg(TEXT_DIM)),
                Span::styled(
                    zip.as_str(),
                    Style::default().fg(GREEN).add_modifier(Modifier::BOLD),
                ),
            ]))
            .block(
                Block::bordered()
                    .border_type(BorderType::Rounded)
                    .border_style(Style::default().fg(GREEN))
                    .title(Span::styled(
                        " Zip Package Ready ",
                        Style::default().fg(GREEN),
                    )),
            ),
            chunks[6],
        );
    }

    // Signing banner (only shown when signing was performed)
    if let Some(manifest) = &app.result_signing_manifest {
        let key_line = app
            .result_signing_key_path
            .as_deref()
            .unwrap_or("(see stderr log)");
        f.render_widget(
            Paragraph::new(vec![
                Line::from(vec![
                    Span::styled("  ✎ ", Style::default().fg(PURPLE)),
                    Span::styled("Manifest:  ", Style::default().fg(TEXT_DIM)),
                    Span::styled(
                        manifest.as_str(),
                        Style::default().fg(PURPLE).add_modifier(Modifier::BOLD),
                    ),
                ]),
                Line::from(vec![
                    Span::styled("  ⚠ ", Style::default().fg(AMBER)),
                    Span::styled("Key file:  ", Style::default().fg(TEXT_DIM)),
                    Span::styled(
                        key_line,
                        Style::default().fg(AMBER).add_modifier(Modifier::BOLD),
                    ),
                    Span::styled(
                        "  ← store securely, separate from evidence",
                        Style::default().fg(TEXT_DIM),
                    ),
                ]),
            ])
            .block(
                Block::bordered()
                    .border_type(BorderType::Rounded)
                    .border_style(Style::default().fg(PURPLE))
                    .title(Span::styled(
                        " Signing Manifest Ready ",
                        Style::default().fg(PURPLE),
                    )),
            ),
            chunks[8],
        );
    }

    // Error list (only shown if there are errors)
    if has_errors {
        let error_items: Vec<ListItem> = app
            .error_messages
            .iter()
            .enumerate()
            .map(|(i, (name, msg))| {
                let bg = if i % 2 == 0 { BG_MAIN } else { RED_BG };
                ListItem::new(Line::from(vec![
                    Span::styled("  ✗ ", Style::default().fg(RED)),
                    Span::styled(format!("{}: ", name), Style::default().fg(AMBER)),
                    Span::styled(msg.as_str(), Style::default().fg(TEXT_DIM)),
                ]))
                .style(Style::default().bg(bg))
            })
            .collect();

        let error_block = Block::bordered()
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(RED))
            .title(Span::styled(
                format!(" Errors ({}) ", error_count),
                Style::default().fg(RED),
            ));

        f.render_widget(List::new(error_items).block(error_block), chunks[10]);
    }
}

fn draw_poam_results(f: &mut Frame, area: Rect, app: &App) {
    let inset = content_inset(area);
    let summary = app.poam_summary.as_ref();

    let region = summary
        .map(|s| s.region.clone())
        .unwrap_or_else(|| app.poam_selected_region());
    let year = summary
        .map(|s| s.year.clone())
        .unwrap_or_else(|| app.poam_year_value());
    let month = summary
        .map(|s| s.month.clone())
        .unwrap_or_else(|| app.poam_month_name().to_string());
    let evidence_path = summary
        .map(|s| s.evidence_path.clone())
        .unwrap_or_else(|| app.poam_evidence_path());
    let csv_used = summary
        .and_then(|s| s.csv_used.clone())
        .unwrap_or_else(|| "none found".to_string());
    let workbook_path = app
        .result_files
        .iter()
        .find(|p| p.ends_with(".xlsx"))
        .cloned()
        .unwrap_or_else(|| "evidence-output/poam/FedRAMP-POAM.xlsx".to_string());
    let added_open_count = summary.map(|s| s.added_open_count).unwrap_or(0);
    let moved_closed_count = summary.map(|s| s.moved_closed_count).unwrap_or(0);
    let warnings = summary.map(|s| s.warnings.clone()).unwrap_or_default();
    let warning_count = warnings.len();
    let error_count = app.error_messages.len();
    let has_errors = error_count > 0;

    let chunks = Layout::vertical([
        Constraint::Length(3),  // [0] banner
        Constraint::Length(1),  // [1] blank
        Constraint::Length(10), // [2] summary
        Constraint::Length(1),  // [3] blank
        Constraint::Length(5),  // [4] stat cards
        Constraint::Length(1),  // [5] blank
        Constraint::Fill(1),    // [6] warnings/errors
    ])
    .split(inset);

    let (banner_text, banner_color) = if has_errors {
        ("!  POAM Run Complete (with errors)", AMBER)
    } else {
        ("✓  POAM Run Complete", GREEN)
    };
    let banner_block = Block::bordered()
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(banner_color));
    f.render_widget(
        Paragraph::new(Span::styled(
            banner_text,
            Style::default()
                .fg(banner_color)
                .add_modifier(Modifier::BOLD),
        ))
        .alignment(Alignment::Center)
        .block(banner_block),
        chunks[0],
    );

    let summary_rows = vec![
        Line::raw(""),
        kv_line("Region", &region),
        kv_line("Year", &year),
        kv_line("Month", &month),
        kv_line("Evidence Path", &evidence_path),
        kv_line("CSV Used", &csv_used),
        kv_line("Workbook", &workbook_path),
        Line::raw(""),
    ];
    let summary_block = Block::bordered()
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(CYAN_DIM))
        .title(Span::styled(
            " POAM Run Summary ",
            Style::default().fg(CYAN_DIM),
        ));
    f.render_widget(
        Paragraph::new(Text::from(summary_rows)).block(summary_block),
        chunks[2],
    );

    let cards = Layout::horizontal([
        Constraint::Ratio(1, 4),
        Constraint::Ratio(1, 4),
        Constraint::Ratio(1, 4),
        Constraint::Ratio(1, 4),
    ])
    .split(chunks[4]);
    draw_stat_card(
        f,
        cards[0],
        "Added Open",
        &added_open_count.to_string(),
        CYAN,
    );
    draw_stat_card(
        f,
        cards[1],
        "Moved Closed",
        &moved_closed_count.to_string(),
        AMBER,
    );
    draw_stat_card(
        f,
        cards[2],
        "Warnings",
        &warning_count.to_string(),
        if warning_count > 0 { AMBER } else { GREEN },
    );
    draw_stat_card(
        f,
        cards[3],
        "Errors",
        &error_count.to_string(),
        if error_count > 0 { RED } else { GREEN },
    );

    let mut messages: Vec<ListItem> = Vec::new();
    for warning in warnings {
        messages.push(ListItem::new(Line::from(vec![
            Span::styled("  ⚠ ", Style::default().fg(AMBER)),
            Span::styled(warning, Style::default().fg(TEXT_NORMAL)),
        ])));
    }
    for (name, msg) in &app.error_messages {
        messages.push(ListItem::new(Line::from(vec![
            Span::styled("  ✗ ", Style::default().fg(RED)),
            Span::styled(format!("{name}: "), Style::default().fg(AMBER)),
            Span::styled(msg.as_str(), Style::default().fg(TEXT_DIM)),
        ])));
    }
    if messages.is_empty() {
        messages.push(ListItem::new(Line::from(vec![
            Span::styled("  ✓ ", Style::default().fg(GREEN)),
            Span::styled("No warnings or errors.", Style::default().fg(TEXT_NORMAL)),
        ])));
    }

    let message_border = if error_count > 0 {
        RED
    } else if warning_count > 0 {
        AMBER
    } else {
        GREEN
    };
    let message_title = if error_count > 0 {
        format!(" Warnings / Errors ({}/{}) ", warning_count, error_count)
    } else if warning_count > 0 {
        format!(" Warnings ({warning_count}) ")
    } else {
        " Status ".to_string()
    };
    let msg_block = Block::bordered()
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(message_border))
        .title(Span::styled(
            message_title,
            Style::default().fg(message_border),
        ));
    f.render_widget(List::new(messages).block(msg_block), chunks[6]);
}
