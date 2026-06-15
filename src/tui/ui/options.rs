use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, List, ListItem, ListState, Paragraph};
use ratatui::Frame;

use super::widgets::content_inset;
use super::{App, Feature, AMBER, BORDER_SUBTLE, CYAN, GREEN, PURPLE, TEXT_DIM, TEXT_NORMAL};

// ═══════════════════════════════════════════════════════════════════════════
// Options
// ═══════════════════════════════════════════════════════════════════════════

pub(super) fn draw_options(f: &mut Frame, area: Rect, app: &App) {
    // Collectors: 8 fields (0=filter 1=include_raw 2=all_regions 3=zip 4=sign
    //   5=write_run_manifest 6=write_chain_of_custody 7=region list)
    // Inventory:  7 fields (0=filter 1=include_raw 2=all_regions 3=zip 4=sign
    //   5=skip_inventory_csv 6=region list)
    let is_inventory = matches!(app.selected_feature, Feature::Inventory);
    let chunks = Layout::vertical([
        Constraint::Length(2), // [0] heading
        Constraint::Length(3), // [1] filter
        Constraint::Length(1), // [2] spacer
        Constraint::Length(3), // [3] include raw
        Constraint::Length(1), // [4] spacer
        Constraint::Length(3), // [5] all regions toggle
        Constraint::Length(1), // [6] spacer
        Constraint::Length(3), // [7] zip bundle toggle
        Constraint::Length(1), // [8] spacer
        Constraint::Length(3), // [9] sign output toggle
        Constraint::Length(1), // [10] spacer
        // Collectors-only (collapsed to 0 in Inventory mode):
        Constraint::Length(if is_inventory { 0 } else { 3 }), // [11] write_run_manifest
        Constraint::Length(if is_inventory { 0 } else { 1 }), // [12] spacer
        Constraint::Length(if is_inventory { 0 } else { 3 }), // [13] write_chain_of_custody
        Constraint::Length(if is_inventory { 0 } else { 1 }), // [14] spacer
        // Inventory-only (collapsed to 0 in Collectors mode):
        Constraint::Length(if is_inventory { 3 } else { 0 }), // [15] skip_inventory_csv
        Constraint::Length(if is_inventory { 1 } else { 0 }), // [16] spacer
        Constraint::Fill(1),                                  // [17] region list
    ])
    .split(content_inset(area));

    f.render_widget(
        Paragraph::new(Span::styled(
            "Configure output options:",
            Style::default().fg(TEXT_DIM),
        )),
        chunks[0],
    );

    super::widgets::draw_text_field(
        f,
        chunks[1],
        "Filter (optional)",
        &app.filter_input.value,
        app.options_field == 0,
    );

    // ── Include Raw JSON toggle (field 1) ─────────────────────────────────────
    {
        let focused = app.options_field == 1;
        let border_style = if focused {
            Style::default().fg(CYAN)
        } else {
            Style::default().fg(BORDER_SUBTLE)
        };
        let title_style = if focused {
            Style::default().fg(CYAN)
        } else {
            Style::default().fg(TEXT_DIM)
        };
        let (off_style, on_style) = if app.include_raw {
            (
                Style::default().fg(TEXT_DIM),
                Style::default().fg(AMBER).add_modifier(Modifier::BOLD),
            )
        } else {
            (
                Style::default().fg(AMBER).add_modifier(Modifier::BOLD),
                Style::default().fg(TEXT_DIM),
            )
        };
        let off_icon = if !app.include_raw { "●" } else { "○" };
        let on_icon = if app.include_raw { "●" } else { "○" };
        f.render_widget(
            Paragraph::new(Line::from(vec![
                Span::styled(format!("   {} ", off_icon), off_style),
                Span::styled("Disabled", off_style),
                Span::styled("    ", Style::default()),
                Span::styled(format!("{} ", on_icon), on_style),
                Span::styled("Enabled", on_style),
            ]))
            .block(
                Block::bordered()
                    .border_type(BorderType::Rounded)
                    .border_style(border_style)
                    .title(Span::styled(" Include Raw JSON ", title_style)),
            ),
            chunks[3],
        );
    }

    // ── All Regions (round-robin) toggle (field 2) ────────────────────────────
    {
        let focused = app.options_field == 2;
        let border_style = if focused {
            Style::default().fg(CYAN)
        } else {
            Style::default().fg(BORDER_SUBTLE)
        };
        let title_style = if focused {
            Style::default().fg(CYAN)
        } else {
            Style::default().fg(TEXT_DIM)
        };
        let (off_style, on_style) = if app.all_regions {
            (
                Style::default().fg(TEXT_DIM),
                Style::default().fg(AMBER).add_modifier(Modifier::BOLD),
            )
        } else {
            (
                Style::default().fg(AMBER).add_modifier(Modifier::BOLD),
                Style::default().fg(TEXT_DIM),
            )
        };
        let off_icon = if !app.all_regions { "●" } else { "○" };
        let on_icon = if app.all_regions { "●" } else { "○" };
        f.render_widget(
            Paragraph::new(Line::from(vec![
                Span::styled(format!("   {} ", off_icon), off_style),
                Span::styled("Single Region", off_style),
                Span::styled("    ", Style::default()),
                Span::styled(format!("{} ", on_icon), on_style),
                Span::styled("All Regions (round-robin discovery)", on_style),
            ]))
            .block(
                Block::bordered()
                    .border_type(BorderType::Rounded)
                    .border_style(border_style)
                    .title(Span::styled(" All Regions ", title_style)),
            ),
            chunks[5],
        );
    }

    // ── Zip Bundle toggle (field 3) ───────────────────────────────────────────
    {
        let focused = app.options_field == 3;
        let border_style = if focused {
            Style::default().fg(CYAN)
        } else {
            Style::default().fg(BORDER_SUBTLE)
        };
        let title_style = if focused {
            Style::default().fg(CYAN)
        } else {
            Style::default().fg(TEXT_DIM)
        };
        let (off_style, on_style) = if app.zip {
            (
                Style::default().fg(TEXT_DIM),
                Style::default().fg(GREEN).add_modifier(Modifier::BOLD),
            )
        } else {
            (
                Style::default().fg(GREEN).add_modifier(Modifier::BOLD),
                Style::default().fg(TEXT_DIM),
            )
        };
        let off_icon = if !app.zip { "●" } else { "○" };
        let on_icon = if app.zip { "●" } else { "○" };
        f.render_widget(
            Paragraph::new(Line::from(vec![
                Span::styled(format!("   {} ", off_icon), off_style),
                Span::styled("Disabled", off_style),
                Span::styled("    ", Style::default()),
                Span::styled(format!("{} ", on_icon), on_style),
                Span::styled("Enabled — bundle output into a dated .zip", on_style),
            ]))
            .block(
                Block::bordered()
                    .border_type(BorderType::Rounded)
                    .border_style(border_style)
                    .title(Span::styled(" Zip Package ", title_style)),
            ),
            chunks[7],
        );
    }

    // ── Sign Output toggle (field 4) ──────────────────────────────────────────
    {
        let focused = app.options_field == 4;
        let border_style = if focused {
            Style::default().fg(CYAN)
        } else {
            Style::default().fg(BORDER_SUBTLE)
        };
        let title_style = if focused {
            Style::default().fg(CYAN)
        } else {
            Style::default().fg(TEXT_DIM)
        };
        let (off_style, on_style) = if app.sign {
            (
                Style::default().fg(TEXT_DIM),
                Style::default().fg(PURPLE).add_modifier(Modifier::BOLD),
            )
        } else {
            (
                Style::default().fg(PURPLE).add_modifier(Modifier::BOLD),
                Style::default().fg(TEXT_DIM),
            )
        };
        let off_icon = if !app.sign { "●" } else { "○" };
        let on_icon = if app.sign { "●" } else { "○" };
        f.render_widget(
            Paragraph::new(Line::from(vec![
                Span::styled(format!("   {} ", off_icon), off_style),
                Span::styled("Disabled", off_style),
                Span::styled("    ", Style::default()),
                Span::styled(format!("{} ", on_icon), on_style),
                Span::styled("Enabled — HMAC-SHA256 sign all output files", on_style),
            ]))
            .block(
                Block::bordered()
                    .border_type(BorderType::Rounded)
                    .border_style(border_style)
                    .title(Span::styled(" Sign Output ", title_style)),
            ),
            chunks[9],
        );
    }

    // ── Run Manifest toggle (Collectors only, field 5) ───────────────────────
    if !is_inventory {
        let focused = app.options_field == 5;
        let border_style = if focused {
            Style::default().fg(CYAN)
        } else {
            Style::default().fg(BORDER_SUBTLE)
        };
        let title_style = if focused {
            Style::default().fg(CYAN)
        } else {
            Style::default().fg(TEXT_DIM)
        };
        let (off_style, on_style) = if app.write_run_manifest {
            (
                Style::default().fg(TEXT_DIM),
                Style::default().fg(AMBER).add_modifier(Modifier::BOLD),
            )
        } else {
            (
                Style::default().fg(AMBER).add_modifier(Modifier::BOLD),
                Style::default().fg(TEXT_DIM),
            )
        };
        let off_icon = if !app.write_run_manifest {
            "●"
        } else {
            "○"
        };
        let on_icon = if app.write_run_manifest { "●" } else { "○" };
        f.render_widget(
            Paragraph::new(Line::from(vec![
                Span::styled(format!("   {} ", off_icon), off_style),
                Span::styled("Disabled", off_style),
                Span::styled("    ", Style::default()),
                Span::styled(format!("{} ", on_icon), on_style),
                Span::styled("Enabled — write RUN-MANIFEST file", on_style),
            ]))
            .block(
                Block::bordered()
                    .border_type(BorderType::Rounded)
                    .border_style(border_style)
                    .title(Span::styled(" Run Manifest ", title_style)),
            ),
            chunks[11],
        );
    }

    // ── Chain of Custody toggle (Collectors only, field 6) ───────────────────
    if !is_inventory {
        let focused = app.options_field == 6;
        let border_style = if focused {
            Style::default().fg(CYAN)
        } else {
            Style::default().fg(BORDER_SUBTLE)
        };
        let title_style = if focused {
            Style::default().fg(CYAN)
        } else {
            Style::default().fg(TEXT_DIM)
        };
        let (off_style, on_style) = if app.write_chain_of_custody {
            (
                Style::default().fg(TEXT_DIM),
                Style::default().fg(AMBER).add_modifier(Modifier::BOLD),
            )
        } else {
            (
                Style::default().fg(AMBER).add_modifier(Modifier::BOLD),
                Style::default().fg(TEXT_DIM),
            )
        };
        let off_icon = if !app.write_chain_of_custody {
            "●"
        } else {
            "○"
        };
        let on_icon = if app.write_chain_of_custody {
            "●"
        } else {
            "○"
        };
        f.render_widget(
            Paragraph::new(Line::from(vec![
                Span::styled(format!("   {} ", off_icon), off_style),
                Span::styled("Disabled", off_style),
                Span::styled("    ", Style::default()),
                Span::styled(format!("{} ", on_icon), on_style),
                Span::styled("Enabled — write CHAIN-OF-CUSTODY file", on_style),
            ]))
            .block(
                Block::bordered()
                    .border_type(BorderType::Rounded)
                    .border_style(border_style)
                    .title(Span::styled(" Chain of Custody ", title_style)),
            ),
            chunks[13],
        );
    }

    // ── Skip Inventory CSV toggle (Inventory only, field 5) ──────────────────
    if is_inventory {
        let focused = app.options_field == 5;
        let border_style = if focused {
            Style::default().fg(CYAN)
        } else {
            Style::default().fg(BORDER_SUBTLE)
        };
        let title_style = if focused {
            Style::default().fg(CYAN)
        } else {
            Style::default().fg(TEXT_DIM)
        };
        let (off_style, on_style) = if app.skip_inventory_csv {
            (
                Style::default().fg(TEXT_DIM),
                Style::default().fg(AMBER).add_modifier(Modifier::BOLD),
            )
        } else {
            (
                Style::default().fg(AMBER).add_modifier(Modifier::BOLD),
                Style::default().fg(TEXT_DIM),
            )
        };
        let off_icon = if !app.skip_inventory_csv {
            "●"
        } else {
            "○"
        };
        let on_icon = if app.skip_inventory_csv { "●" } else { "○" };
        f.render_widget(
            Paragraph::new(Line::from(vec![
                Span::styled(format!("   {} ", off_icon), off_style),
                Span::styled("CSV + Excel", off_style),
                Span::styled("    ", Style::default()),
                Span::styled(format!("{} ", on_icon), on_style),
                Span::styled("Excel only — skip intermediate CSV", on_style),
            ]))
            .block(
                Block::bordered()
                    .border_type(BorderType::Rounded)
                    .border_style(border_style)
                    .title(Span::styled(" Inventory Output Format ", title_style)),
            ),
            chunks[15],
        );
    }

    // ── Region multi-select list (field 6 for Inventory, 7 for Collectors) ───
    {
        let region_field = if is_inventory { 6 } else { 7 };
        let focused = app.options_field == region_field;
        let dimmed = app.all_regions; // when all_regions is ON, list is informational only

        let border_style = if dimmed {
            Style::default().fg(BORDER_SUBTLE)
        } else if focused {
            Style::default().fg(CYAN)
        } else {
            Style::default().fg(BORDER_SUBTLE)
        };
        let title_style = if focused && !dimmed {
            Style::default().fg(CYAN)
        } else {
            Style::default().fg(TEXT_DIM)
        };

        let selected_count = app.options_selected_regions.len();
        let title = if dimmed {
            " Specific Regions — disabled while All Regions is ON ".to_string()
        } else if selected_count == 0 {
            " Specific Regions (optional — leave empty to use account default) ".to_string()
        } else {
            format!(" Specific Regions — {} selected ", selected_count)
        };

        let items: Vec<ListItem> = app
            .regions
            .iter()
            .enumerate()
            .map(|(i, region)| {
                let is_selected = app.options_selected_regions.contains(&i);
                let is_cursor = focused && i == app.options_region_cursor;

                let check_style = if dimmed {
                    Style::default().fg(TEXT_DIM)
                } else if is_selected {
                    Style::default().fg(GREEN).add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(TEXT_DIM)
                };
                let name_style = if dimmed {
                    Style::default().fg(TEXT_DIM)
                } else if is_selected {
                    Style::default()
                        .fg(TEXT_NORMAL)
                        .add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(TEXT_NORMAL)
                };

                let check = if is_selected { "[✓]" } else { "[ ]" };
                let prefix = if is_cursor && !dimmed { " ▶ " } else { "   " };

                ListItem::new(Line::from(vec![
                    Span::styled(prefix, Style::default().fg(CYAN)),
                    Span::styled(check, check_style),
                    Span::styled(format!("  {}", region), name_style),
                ]))
            })
            .collect();

        let block = Block::bordered()
            .border_type(BorderType::Rounded)
            .border_style(border_style)
            .title(Span::styled(title, title_style));

        let mut list_state = ListState::default();
        if focused && !dimmed {
            list_state.select(Some(app.options_region_cursor));
        }

        f.render_stateful_widget(List::new(items).block(block), chunks[17], &mut list_state);
    }
}
