use ratatui::layout::{Alignment, Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{
    Block, BorderType, Clear, List, ListItem, ListState, Padding, Paragraph, Wrap,
};
use ratatui::Frame;

use super::{
    AMBER, BG_SELECTED, BORDER_SUBTLE, CYAN, CYAN_DIM, RED, RED_BG, TEXT_BRIGHT, TEXT_DIM,
    TEXT_NORMAL,
};

pub(super) fn draw_stat_card(f: &mut Frame, area: Rect, title: &str, value: &str, color: Color) {
    let block = Block::bordered()
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(BORDER_SUBTLE))
        .title(Span::styled(
            format!(" {title} "),
            Style::default().fg(TEXT_DIM),
        ));

    f.render_widget(
        Paragraph::new(Span::styled(
            value,
            Style::default().fg(color).add_modifier(Modifier::BOLD),
        ))
        .alignment(Alignment::Center)
        .block(block.padding(Padding::vertical(1))),
        area,
    );
}

pub(super) fn draw_text_field(f: &mut Frame, area: Rect, label: &str, value: &str, focused: bool) {
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

    let block = Block::bordered()
        .border_type(BorderType::Rounded)
        .border_style(border_style)
        .title(Span::styled(format!(" {label} "), title_style))
        .padding(Padding::horizontal(1));

    f.render_widget(
        Paragraph::new(Span::styled(value, Style::default().fg(TEXT_BRIGHT))).block(block),
        area,
    );

    if focused {
        // Cursor position: border(1) + padding(1) + value length
        f.set_cursor_position((area.x + 2 + value.len() as u16, area.y + 1));
    }
}

pub(super) fn draw_error_banner(f: &mut Frame, area: Rect, msg: &str) {
    let banner = Rect {
        x: area.x,
        y: area.y + area.height.saturating_sub(1),
        width: area.width,
        height: 1,
    };
    f.render_widget(Clear, banner);
    f.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled(" ✗  ", Style::default().fg(RED)),
            Span::styled(msg, Style::default().fg(TEXT_BRIGHT)),
        ]))
        .style(Style::default().bg(RED_BG)),
        banner,
    );
}

pub(super) fn kv_line<'a>(key: &'a str, value: &'a str) -> Line<'a> {
    Line::from(vec![
        Span::styled(
            format!("   {:>14}     ", key),
            Style::default().fg(TEXT_DIM),
        ),
        Span::styled(
            value,
            Style::default()
                .fg(TEXT_BRIGHT)
                .add_modifier(Modifier::BOLD),
        ),
    ])
}

pub(super) fn kv_line_colored<'a>(key: &'a str, value: &'a str, color: Color) -> Line<'a> {
    Line::from(vec![
        Span::styled(
            format!("   {:>14}     ", key),
            Style::default().fg(TEXT_DIM),
        ),
        Span::styled(
            value,
            Style::default().fg(color).add_modifier(Modifier::BOLD),
        ),
    ])
}

pub(super) fn stat_line<'a>(key: &'a str, value: &'a str) -> Line<'a> {
    Line::from(vec![
        Span::styled(format!("    {:<13}", key), Style::default().fg(TEXT_DIM)),
        Span::styled(
            value,
            Style::default()
                .fg(TEXT_BRIGHT)
                .add_modifier(Modifier::BOLD),
        ),
    ])
}

pub(super) fn content_inset(area: Rect) -> Rect {
    let margin = 4u16.min(area.width / 6);
    Rect {
        x: area.x + margin,
        y: area.y,
        width: area.width.saturating_sub(margin * 2),
        height: area.height,
    }
}

pub(super) fn format_duration(ticks: u64) -> String {
    let secs = ticks / 10;
    let mins = secs / 60;
    let secs = secs % 60;
    format!("{:02}:{:02}", mins, secs)
}

pub(super) fn format_number(n: usize) -> String {
    if n < 1000 {
        return n.to_string();
    }
    let s = n.to_string();
    let mut result = String::new();
    for (i, c) in s.chars().rev().enumerate() {
        if i > 0 && i % 3 == 0 {
            result.push(',');
        }
        result.push(c);
    }
    result.chars().rev().collect()
}

/// Auto-scrolling list (left, 30% width) + detail panel (right, 70% width)
/// for single-column selection screens with a description per item.
/// `items` is `(name, description)` pairs; `selected` indexes into `items`
/// and drives both the list highlight and the detail panel content.
#[allow(dead_code)]
pub(super) fn draw_list_with_detail(
    f: &mut Frame,
    area: Rect,
    list_title: &str,
    items: &[(String, String)],
    selected: usize,
) {
    let chunks =
        Layout::horizontal([Constraint::Percentage(30), Constraint::Percentage(70)]).split(area);

    let list_items: Vec<ListItem> = items
        .iter()
        .enumerate()
        .map(|(idx, (name, _))| {
            let style = if idx == selected {
                Style::default()
                    .fg(AMBER)
                    .add_modifier(Modifier::BOLD)
                    .bg(BG_SELECTED)
            } else {
                Style::default().fg(TEXT_NORMAL)
            };
            ListItem::new(Line::from(Span::styled(format!(" {name}"), style)))
        })
        .collect();

    let list_block = Block::bordered()
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(CYAN))
        .title(Line::from(vec![Span::styled(
            format!(" {list_title} "),
            Style::default().fg(CYAN),
        )]));

    let mut list_state = ListState::default();
    list_state.select(Some(selected));

    f.render_stateful_widget(
        List::new(list_items)
            .block(list_block)
            .highlight_symbol("▸ ")
            .highlight_style(Style::default()),
        chunks[0],
        &mut list_state,
    );

    let (detail_name, detail_desc) = items
        .get(selected)
        .map(|(n, d)| (n.as_str(), d.as_str()))
        .unwrap_or(("", ""));

    let detail_block = Block::bordered()
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(BORDER_SUBTLE))
        .title(Line::from(vec![Span::styled(
            " Details ",
            Style::default().fg(CYAN_DIM),
        )]))
        .padding(Padding::horizontal(1));

    let detail_lines = vec![
        Line::from(Span::styled(
            detail_name,
            Style::default()
                .fg(TEXT_BRIGHT)
                .add_modifier(Modifier::BOLD),
        )),
        Line::raw(""),
        Line::from(Span::styled(detail_desc, Style::default().fg(TEXT_DIM))),
    ];

    f.render_widget(
        Paragraph::new(detail_lines)
            .wrap(Wrap { trim: true })
            .block(detail_block),
        chunks[1],
    );
}
