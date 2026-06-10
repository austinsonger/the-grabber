use ratatui::layout::{Alignment, Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, List, ListItem, ListState, Padding, Paragraph};
use ratatui::Frame;

use crate::providers::CloudProvider;

use super::COLLECTOR_CATEGORIES;
use super::{
    App, CollectorFocus, AMBER, BG_SELECTED, BORDER_SUBTLE, CYAN, CYAN_DIM, GREEN, TEXT_BRIGHT,
    TEXT_DIM, TEXT_NORMAL,
};

// ═══════════════════════════════════════════════════════════════════════════
// Select Collectors
// ═══════════════════════════════════════════════════════════════════════════

pub(super) fn draw_collectors(f: &mut Frame, area: Rect, app: &App) {
    // Count only items visible to the current provider.
    let provider_visible_total: usize = (0..app.collector_items.len())
        .filter(|&i| {
            let (_, _, provider) = &app.collector_items[i];
            if app.selected_feature == crate::tui::state::Feature::Collectors {
                *provider == app.selected_provider
            } else {
                true
            }
        })
        .count();
    let provider_visible_selected: usize = app
        .collector_selected
        .iter()
        .filter(|&&i| {
            app.collector_items
                .get(i)
                .map(|(_, _, p)| {
                    if app.selected_feature == crate::tui::state::Feature::Collectors {
                        *p == app.selected_provider
                    } else {
                        true
                    }
                })
                .unwrap_or(false)
        })
        .count();
    let search_term = &app.collector_search.value;

    let title = if search_term.is_empty() {
        format!(
            " Collectors ─────────── {} of {} selected ",
            provider_visible_selected, provider_visible_total,
        )
    } else {
        let match_count: usize = (0..app.collector_items.len())
            .filter(|&i| app.search_matches_item(i))
            .count();
        format!(
            " Collectors ─────────── {} of {} selected  •  {} matches ",
            provider_visible_selected, provider_visible_total, match_count,
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

    let is_tenable = app.selected_provider == CloudProvider::Tenable
        && app.selected_feature == crate::tui::state::Feature::Collectors;

    // Layout: search bar (3 or 0) | main panels (fill) | separator (1) | help (1)
    let search_height: u16 = if is_tenable { 0 } else { 3 };
    let v_chunks = Layout::vertical([
        Constraint::Length(search_height),
        Constraint::Fill(1),
        Constraint::Length(1),
        Constraint::Length(1),
    ])
    .split(inner);

    let search_area = v_chunks[0];
    let main_area = v_chunks[1];
    let help_area = v_chunks[3];

    // ── Search bar (hidden for Tenable) ──────────────────────────
    if !is_tenable {
        let search_focused = app.collector_focus == CollectorFocus::Search;
        let has_search_inner = !search_term.is_empty();
        let search_label = if has_search_inner {
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
    }
    let has_search = !search_term.is_empty();

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
    // When collector_category_cursor points at a hidden category (e.g. the
    // Tenable provider filters out all AWS categories leaving only Security
    // Scanning), fall back to the first visible category so the right panel
    // title and item list stay in sync with what is actually highlighted.
    let item_focused = app.collector_focus == CollectorFocus::Items;
    let effective_cat = if visible_cats.contains(&app.collector_category_cursor) {
        app.collector_category_cursor
    } else {
        visible_cats
            .first()
            .copied()
            .unwrap_or(app.collector_category_cursor)
    };
    let visible_items = app.visible_items_in_category(effective_cat);
    let cat_name = COLLECTOR_CATEGORIES[effective_cat].1;

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
        let (_, label, provider) = &app.collector_items[i];
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

        let (badge_text, badge_color) = provider_badge(provider);

        let mut line_spans = vec![
            Span::styled(format!("{} ", checkbox), checkbox_style),
            Span::styled(format!("{:<28}", name), name_style),
            Span::styled(
                format!("{:<5}", badge_text),
                Style::default().fg(badge_color),
            ),
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

fn provider_badge(provider: &CloudProvider) -> (&'static str, Color) {
    match provider {
        CloudProvider::Aws => ("AWS", Color::Rgb(255, 153, 0)),
        CloudProvider::Azure => ("AZ", Color::Rgb(0, 120, 212)),
        CloudProvider::Gcp => ("GCP", Color::Rgb(66, 133, 244)),
        CloudProvider::Tenable => ("TEN", Color::Rgb(0, 175, 80)),
        CloudProvider::Okta => ("OKT", Color::Rgb(0, 125, 193)),
    }
}
