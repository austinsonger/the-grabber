use ratatui::layout::{Alignment, Constraint, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::{Block, BorderType, Gauge, List, ListItem, Padding, Paragraph};
use ratatui::Frame;

use super::widgets::{content_inset, kv_line, kv_line_colored};
use super::{
    App, Feature, AMBER, BG_ELEVATED, BORDER_SUBTLE, CYAN, CYAN_DIM, GREEN, RED, TEXT_DIM,
    TEXT_NORMAL,
};

// ═══════════════════════════════════════════════════════════════════════════
// Confirm
// ═══════════════════════════════════════════════════════════════════════════

pub(super) fn draw_confirm(f: &mut Frame, area: Rect, app: &App) {
    let chunks = Layout::vertical([
        Constraint::Length(1),
        Constraint::Fill(1),
        Constraint::Length(3),
        Constraint::Length(1),
    ])
    .split(content_inset(area));

    if matches!(app.selected_feature, Feature::Poam) {
        let poam_account = if app.has_accounts() {
            app.accounts
                .get(app.poam_account_cursor)
                .map(|a| a.name.as_str())
                .unwrap_or("(none)")
                .to_string()
        } else {
            String::new()
        };
        let poam_region = app.poam_selected_region();
        let poam_year = app.poam_year_value();
        let poam_month = app.poam_month_name().to_string();
        let evidence_path = app.poam_evidence_path();
        let workbook_path = "evidence-output/poam/FedRAMP-POAM.xlsx".to_string();

        let mut rows = vec![
            Line::raw(""),
            kv_line_colored("Feature", "POAM Reconciliation", AMBER),
        ];
        if !poam_account.is_empty() {
            rows.push(kv_line("Account", &poam_account));
        }
        rows.extend([
            kv_line("Region", &poam_region),
            kv_line("Year", &poam_year),
            kv_line("Month", &poam_month),
            kv_line("Evidence Path", &evidence_path),
            kv_line("Workbook", &workbook_path),
            Line::raw(""),
        ]);

        let summary_block = Block::bordered()
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(CYAN_DIM))
            .title(Span::styled(
                " Configuration Summary ",
                Style::default().fg(CYAN_DIM),
            ));
        f.render_widget(
            Paragraph::new(Text::from(rows)).block(summary_block),
            chunks[1],
        );

        let button_block = Block::bordered()
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(AMBER));
        f.render_widget(
            Paragraph::new(Span::styled(
                "▸▸  Start POAM Run  ◂◂",
                Style::default().fg(AMBER).add_modifier(Modifier::BOLD),
            ))
            .alignment(Alignment::Center)
            .block(button_block),
            chunks[2],
        );
        return;
    }

    let region = app.selected_region();

    // Build account/profile lines depending on selection mode.
    let sorted_accounts = app.selected_account_indices();
    let account_display = if sorted_accounts.len() > 1 {
        let names: Vec<&str> = sorted_accounts
            .iter()
            .map(|&i| app.accounts[i].name.as_str())
            .collect();
        format!("{} selected ({})", sorted_accounts.len(), names.join(", "))
    } else {
        String::new()
    };

    let mut rows: Vec<Line> = vec![Line::raw("")];

    if !sorted_accounts.is_empty() {
        if sorted_accounts.len() == 1 {
            let acct = &app.accounts[sorted_accounts[0]];
            rows.push(kv_line("Account", &acct.name));
            rows.push(kv_line("Profile", acct.profile.as_deref().unwrap_or("")));
            rows.push(kv_line("Region", acct.region.as_deref().unwrap_or(&region)));
        } else {
            rows.push(kv_line_colored("Accounts", &account_display, AMBER));
        }
    } else {
        rows.push(kv_line("Profile", app.selected_profile()));
        rows.push(kv_line("Region", &region));
    }

    let time_frame_label = format!(
        "{} Month{}",
        app.time_frame_months(),
        if app.time_frame_months() == 1 {
            ""
        } else {
            "s"
        },
    );
    rows.extend_from_slice(&[
        kv_line("Time Frame", &time_frame_label),
        kv_line("Start Date", &app.start_date.value),
        kv_line("End Date", &app.end_date.value),
    ]);

    // Pre-compute display strings so they outlive the match arms below.
    let collectors_display = format!("{} selected", app.collector_selected.len());
    let filter_display = if app.filter_input.value.is_empty() {
        "none".to_string()
    } else {
        app.filter_input.value.clone()
    };
    let explicit_regions = app.explicit_regions();
    let explicit_regions_display = explicit_regions.join(", ");

    let mut inv_indices: Vec<usize> = app.inventory_selected.iter().copied().collect();
    inv_indices.sort_unstable();
    let inv_labels: Vec<&str> = inv_indices
        .iter()
        .filter_map(|&i| app.inventory_items.get(i).map(|(_, label)| *label))
        .collect();
    let assets_display = format!("{} selected ({})", inv_indices.len(), inv_labels.join(", "));

    match app.selected_feature {
        Feature::Collectors => {
            let regions_line = if app.all_regions {
                kv_line("Regions", "all — round-robin every enabled region")
            } else if explicit_regions.is_empty() {
                kv_line("Regions", "account default (single region)")
            } else {
                kv_line_colored("Regions", &explicit_regions_display, CYAN)
            };
            rows.extend_from_slice(&[
                kv_line_colored("Collectors", &collectors_display, AMBER),
                kv_line("Output Dir", &app.output_dir.value),
                kv_line("Filter", &filter_display),
                kv_line("Include Raw", if app.include_raw { "yes" } else { "no" }),
                kv_line(
                    "Zip Package",
                    if app.zip {
                        "yes — bundle output into a dated .zip"
                    } else {
                        "no"
                    },
                ),
                kv_line(
                    "Sign Output",
                    if app.sign {
                        "yes — HMAC-SHA256 manifest + key file"
                    } else {
                        "no"
                    },
                ),
                kv_line(
                    "Run Manifest",
                    if app.write_run_manifest {
                        "enabled"
                    } else {
                        "disabled"
                    },
                ),
                kv_line(
                    "Chain of Custody",
                    if app.write_chain_of_custody {
                        "enabled"
                    } else {
                        "disabled"
                    },
                ),
                regions_line,
            ]);
        }
        Feature::Inventory => {
            rows.extend_from_slice(&[
                kv_line("Feature", "Inventory"),
                kv_line_colored("Asset Types", &assets_display, AMBER),
                kv_line("Output Dir", &app.output_dir.value),
                kv_line(
                    "Output Format",
                    if app.skip_inventory_csv {
                        "Excel only (CSV skipped)"
                    } else {
                        "CSV + Excel"
                    },
                ),
            ]);
        }
        Feature::Poam => {}
    }
    rows.push(Line::raw(""));

    let summary_block = Block::bordered()
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(CYAN_DIM))
        .title(Span::styled(
            " Configuration Summary ",
            Style::default().fg(CYAN_DIM),
        ));

    f.render_widget(
        Paragraph::new(Text::from(rows)).block(summary_block),
        chunks[1],
    );

    // Start button
    let button_block = Block::bordered()
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(AMBER));

    let button_label = match app.selected_feature {
        Feature::Collectors => "▸▸  Start Collection  ◂◂",
        Feature::Inventory => "▸▸  Start Inventory   ◂◂",
        Feature::Poam => "▸▸  Start POAM Run    ◂◂",
    };
    f.render_widget(
        Paragraph::new(Span::styled(
            button_label,
            Style::default().fg(AMBER).add_modifier(Modifier::BOLD),
        ))
        .alignment(Alignment::Center)
        .block(button_block),
        chunks[2],
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// Preparing
// ═══════════════════════════════════════════════════════════════════════════

pub(super) fn draw_preparing(f: &mut Frame, area: Rect, app: &App) {
    let inset = content_inset(area);

    let chunks = Layout::vertical([
        Constraint::Length(3), // title
        Constraint::Fill(1),   // log lines
    ])
    .split(inset);

    // Title / progress indicator
    let title = if app.prep_total > 0 {
        format!(
            "  Preparing account {}/{}  —  building AWS SDK clients…",
            app.prep_current.max(1),
            app.prep_total,
        )
    } else {
        "  Preparing AWS SDK clients…".to_string()
    };

    let progress_pct = if app.prep_total > 0 {
        ((app.prep_current.saturating_sub(1)) as f64 / app.prep_total as f64 * 100.0) as u16
    } else {
        0
    };

    let gauge = Gauge::default()
        .block(Block::default())
        .gauge_style(Style::default().fg(CYAN).bg(BG_ELEVATED))
        .percent(progress_pct)
        .label(title);
    f.render_widget(gauge, chunks[0]);

    // Scrollable log — show the last N lines that fit in the area
    let log_height = chunks[1].height as usize;
    let lines: Vec<ListItem> = app
        .prep_log
        .iter()
        .rev()
        .take(log_height)
        .rev()
        .map(|line| {
            let style = if line.starts_with("  ✓") {
                Style::default().fg(GREEN)
            } else if line.starts_with("  ✗") || line.starts_with("  ERROR") {
                Style::default().fg(RED)
            } else if line.starts_with("    Region")
                || line.starts_with("    All ")
                || line.starts_with("    Building")
            {
                Style::default().fg(TEXT_DIM)
            } else if line.starts_with("  [") {
                Style::default().fg(CYAN).add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(TEXT_NORMAL)
            };
            ListItem::new(line.as_str()).style(style)
        })
        .collect();

    let log_widget = List::new(lines).block(
        Block::bordered()
            .border_style(Style::default().fg(BORDER_SUBTLE))
            .title(Span::styled(" Setup Log ", Style::default().fg(TEXT_DIM)))
            .padding(Padding::horizontal(1)),
    );
    f.render_widget(log_widget, chunks[1]);
}
