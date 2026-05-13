use ratatui::layout::{Alignment, Constraint, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, List, ListItem, ListState, Padding, Paragraph};
use ratatui::Frame;

use super::widgets::{content_inset, draw_text_field};
use super::COLLECTOR_CATEGORIES;
use super::{
    App, CollectorFocus, Feature, AMBER, BG_SELECTED, BORDER_SUBTLE, CYAN, CYAN_DIM, GREEN, PURPLE,
    TEXT_BRIGHT, TEXT_DIM, TEXT_NORMAL,
};

// ═══════════════════════════════════════════════════════════════════════════
// Select Collectors
// ═══════════════════════════════════════════════════════════════════════════

pub(super) fn draw_collectors(f: &mut Frame, area: Rect, app: &App) {
    let selected_count = app.collector_selected.len();
    let total_count = app.collector_items.len();
    let search_term = &app.collector_search.value;

    let title = if search_term.is_empty() {
        format!(
            " Collectors ─────────── {} of {} selected ",
            selected_count, total_count,
        )
    } else {
        let match_count: usize = (0..total_count)
            .filter(|&i| app.search_matches_item(i))
            .count();
        format!(
            " Collectors ─────────── {} of {} selected  •  {} matches ",
            selected_count, total_count, match_count,
        )
    };

    let block = Block::bordered()
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(BORDER_SUBTLE))
        .title(Line::from(vec![Span::styled(
            &title,
            Style::default().fg(CYAN_DIM),
        )]));

    let inner = block.inner(area);
    f.render_widget(block, area);

    // Layout: search bar (3) | main panels (fill) | separator (1) | help (1)
    let v_chunks = Layout::vertical([
        Constraint::Length(3),
        Constraint::Fill(1),
        Constraint::Length(1),
        Constraint::Length(1),
    ])
    .split(inner);

    let search_area = v_chunks[0];
    let main_area = v_chunks[1];
    let help_area = v_chunks[3];

    // ── Search bar ───────────────────────────────────────────────
    let search_focused = app.collector_focus == CollectorFocus::Search;
    let has_search = !search_term.is_empty();
    let search_label = if has_search {
        " Search collectors  [✕ Esc to clear] ".to_string()
    } else {
        " Search collectors… ".to_string()
    };
    let search_block = Block::bordered()
        .border_type(BorderType::Rounded)
        .border_style(if search_focused {
            Style::default().fg(CYAN)
        } else {
            Style::default().fg(BORDER_SUBTLE)
        })
        .title(Span::styled(
            search_label,
            if search_focused {
                Style::default().fg(CYAN)
            } else {
                Style::default().fg(TEXT_DIM)
            },
        ))
        .padding(Padding::horizontal(1));

    f.render_widget(
        Paragraph::new(Span::styled(
            search_term.as_str(),
            Style::default().fg(TEXT_BRIGHT),
        ))
        .block(search_block),
        search_area,
    );

    if search_focused {
        // border(1) + padding(1) + cursor byte offset
        f.set_cursor_position((
            search_area.x + 2 + app.collector_search.cursor as u16,
            search_area.y + 1,
        ));
    }

    // ── Resolve visible set ───────────────────────────────────────
    let visible_cats = app.visible_categories();

    // ── Empty state: no categories have any matching item ─────────
    if visible_cats.is_empty() {
        let empty_msg = format!("No collectors match \"{}\"   •   Esc to clear", search_term);
        f.render_widget(
            Paragraph::new(Span::styled(empty_msg, Style::default().fg(TEXT_DIM)))
                .alignment(Alignment::Center),
            main_area,
        );
        f.render_widget(
            Paragraph::new("Type to filter  •  Down/Tab switch panel  •  Esc clear")
                .style(Style::default().fg(TEXT_DIM))
                .alignment(Alignment::Center),
            help_area,
        );
        return;
    }

    // ── Split into left (categories) and right (items) ───────────
    let h_split = Layout::horizontal([Constraint::Percentage(30), Constraint::Percentage(70)])
        .split(main_area);
    let left_area = h_split[0];
    let right_area = h_split[1];

    // ── Left panel: visible categories ───────────────────────────
    let cat_focused = app.collector_focus == CollectorFocus::Categories;

    let visible_cat_pos = visible_cats
        .iter()
        .position(|&c| c == app.collector_category_cursor)
        .unwrap_or(0);

    let mut cat_items: Vec<ListItem> = Vec::new();
    for &cat_idx in &visible_cats {
        let (_, cat_name) = COLLECTOR_CATEGORIES[cat_idx];
        let sel = app.selected_in_category(cat_idx);
        let (start, end) = app.category_bounds(cat_idx);
        let total = end.saturating_sub(start);
        let is_selected_cat = cat_idx == app.collector_category_cursor;

        let num = cat_idx + 1;
        let count_str = format!("{}/{}", sel, total);
        let label = format!("{}.{:<22} {:>5}", num, cat_name, count_str);

        let mut style = Style::default().fg(TEXT_NORMAL);
        if is_selected_cat {
            style = if cat_focused {
                Style::default().fg(AMBER).add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(AMBER)
            };
            style = style.patch(Style::default().bg(BG_SELECTED));
        }

        cat_items.push(ListItem::new(Line::from(Span::styled(label, style))));
    }

    let cat_block = Block::bordered()
        .border_type(BorderType::Rounded)
        .border_style(if cat_focused {
            Style::default().fg(CYAN)
        } else {
            Style::default().fg(BORDER_SUBTLE)
        })
        .title(Line::from(vec![Span::styled(
            " Categories ",
            Style::default().fg(if cat_focused { CYAN } else { CYAN_DIM }),
        )]));

    let mut cat_state = ListState::default();
    cat_state.select(Some(visible_cat_pos));

    f.render_stateful_widget(
        List::new(cat_items)
            .block(cat_block)
            .highlight_symbol("▸ ")
            .highlight_style(Style::default()),
        left_area,
        &mut cat_state,
    );

    // ── Right panel: visible items in selected category ───────────
    let item_focused = app.collector_focus == CollectorFocus::Items;
    let visible_items = app.visible_items_in_category(app.collector_category_cursor);
    let cat_name = COLLECTOR_CATEGORIES[app.collector_category_cursor].1;

    let item_block = Block::bordered()
        .border_type(BorderType::Rounded)
        .border_style(if item_focused {
            Style::default().fg(CYAN)
        } else {
            Style::default().fg(BORDER_SUBTLE)
        })
        .title(Line::from(vec![Span::styled(
            format!(" {} ", cat_name),
            Style::default().fg(if item_focused { CYAN } else { CYAN_DIM }),
        )]));

    let mut item_list: Vec<ListItem> = Vec::new();
    for &i in &visible_items {
        let (_, label) = &app.collector_items[i];
        let checked = app.collector_selected.contains(&i);
        let focused = i == app.collector_cursor;

        let checkbox = if checked { "[✓]" } else { "[ ]" };
        let checkbox_style = if checked {
            Style::default().fg(GREEN).add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(TEXT_DIM)
        };
        let name_style = if focused && item_focused {
            Style::default().fg(AMBER).add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(TEXT_NORMAL)
        };

        let parts: Vec<&str> = label.splitn(2, '(').collect();
        let name = parts[0].trim();
        let desc = if parts.len() > 1 {
            format!("({}", parts[1])
        } else {
            String::new()
        };

        let mut line_spans = vec![
            Span::styled(format!("{} ", checkbox), checkbox_style),
            Span::styled(format!("{:<28}", name), name_style),
        ];
        if !desc.is_empty() {
            line_spans.push(Span::styled(desc, Style::default().fg(TEXT_DIM)));
        }

        let mut item = ListItem::new(Line::from(line_spans));
        if focused && item_focused {
            item = item.style(Style::default().bg(BG_SELECTED));
        }
        item_list.push(item);
    }

    let local_cursor = visible_items
        .iter()
        .position(|&i| i == app.collector_cursor)
        .unwrap_or(0);

    let mut item_state = ListState::default();
    item_state.select(Some(local_cursor));

    f.render_stateful_widget(
        List::new(item_list)
            .block(item_block)
            .highlight_symbol("")
            .highlight_style(Style::default()),
        right_area,
        &mut item_state,
    );

    // ── Help text ─────────────────────────────────────────────────
    let help_text = match app.collector_focus {
        CollectorFocus::Search => "Type to filter  •  Down/Tab switch panel  •  Esc clear",
        CollectorFocus::Categories => {
            if has_search {
                "↑↓ navigate • 1-9 jump • Tab/→ switch panel • Space toggle category • a/d all/none  •  Tab → search"
            } else {
                "↑↓ navigate • 1-9 jump • Tab/→ switch panel • Space toggle category • a/d all/none"
            }
        }
        CollectorFocus::Items => {
            if has_search {
                "↑↓ navigate • Space toggle • a/d all/none • Tab/← switch panel • Enter confirm  •  Tab → search"
            } else {
                "↑↓ navigate • Space toggle • a/d all/none • Tab/← switch panel • Enter confirm"
            }
        }
    };

    f.render_widget(
        Paragraph::new(help_text)
            .style(Style::default().fg(TEXT_DIM))
            .alignment(Alignment::Center),
        help_area,
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// Options
// ═══════════════════════════════════════════════════════════════════════════

pub(super) fn draw_options(f: &mut Frame, area: Rect, app: &App) {
    // Collectors: 8 fields (0=filter 1=include_raw 2=all_regions 3=zip 4=sign
    //   5=skip_run_manifest 6=skip_chain_of_custody 7=region list)
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
        Constraint::Length(if is_inventory { 0 } else { 3 }), // [11] skip_run_manifest
        Constraint::Length(if is_inventory { 0 } else { 1 }), // [12] spacer
        Constraint::Length(if is_inventory { 0 } else { 3 }), // [13] skip_chain_of_custody
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

    draw_text_field(
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

    // ── Skip Run Manifest toggle (Collectors only, field 5) ──────────────────
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
        let (off_style, on_style) = if app.skip_run_manifest {
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
        let off_icon = if !app.skip_run_manifest { "●" } else { "○" };
        let on_icon = if app.skip_run_manifest { "●" } else { "○" };
        f.render_widget(
            Paragraph::new(Line::from(vec![
                Span::styled(format!("   {} ", off_icon), off_style),
                Span::styled("Enabled", off_style),
                Span::styled("    ", Style::default()),
                Span::styled(format!("{} ", on_icon), on_style),
                Span::styled("Disabled — skip RUN-MANIFEST file", on_style),
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

    // ── Skip Chain of Custody toggle (Collectors only, field 6) ──────────────
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
        let (off_style, on_style) = if app.skip_chain_of_custody {
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
        let off_icon = if !app.skip_chain_of_custody {
            "●"
        } else {
            "○"
        };
        let on_icon = if app.skip_chain_of_custody {
            "●"
        } else {
            "○"
        };
        f.render_widget(
            Paragraph::new(Line::from(vec![
                Span::styled(format!("   {} ", off_icon), off_style),
                Span::styled("Enabled", off_style),
                Span::styled("    ", Style::default()),
                Span::styled(format!("{} ", on_icon), on_style),
                Span::styled("Disabled — skip CHAIN-OF-CUSTODY file", on_style),
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
