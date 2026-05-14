use ratatui::layout::{Alignment, Constraint, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;
use ratatui::Frame;

use super::theme::{
    AMBER, BORDER_SUBTLE, CYAN, GREEN, PURPLE, TEAL, TEXT_BRIGHT, TEXT_DIM, TEXT_NORMAL,
};
use crate::tui::state::{Feature, Screen};

use super::theme::{BG_ELEVATED, CYAN_DIM};

// ═══════════════════════════════════════════════════════════════════════════
// Step label sequences (one per wizard flow)
// ═══════════════════════════════════════════════════════════════════════════

pub(super) const STEPS_ACCOUNTS: &[&str] = &[
    "Account",
    "Dates",
    "Collectors",
    "Options",
    "Confirm",
    "Run",
];
pub(super) const STEPS_LEGACY: &[&str] = &[
    "Profile",
    "Region",
    "Dates",
    "Collectors",
    "Options",
    "Confirm",
    "Run",
];
pub(super) const STEPS_INV_ACCOUNTS: &[&str] =
    &["Account", "Dates", "Inventory", "Options", "Confirm", "Run"];
pub(super) const STEPS_INV_LEGACY: &[&str] = &[
    "Profile",
    "Region",
    "Dates",
    "Inventory",
    "Options",
    "Confirm",
    "Run",
];
pub(super) const STEPS_POAM: &[&str] = &["Account", "Region", "Year", "Month", "Confirm", "Run"];
pub(super) const STEPS_POAM_NO_ACCOUNTS: &[&str] = &["Region", "Year", "Month", "Confirm", "Run"];

// ═══════════════════════════════════════════════════════════════════════════
// Step index mapping
// ═══════════════════════════════════════════════════════════════════════════

pub(super) fn screen_to_step(
    screen: &Screen,
    has_accounts: bool,
    feature: &Feature,
) -> Option<usize> {
    match feature {
        Feature::Collectors => {
            if has_accounts {
                match screen {
                    Screen::SelectAccount => Some(0),
                    Screen::SetDates => Some(1),
                    Screen::SelectCollectors => Some(2),
                    Screen::SetOptions => Some(3),
                    Screen::Confirm => Some(4),
                    Screen::Running => Some(5),
                    _ => None,
                }
            } else {
                match screen {
                    Screen::SelectProfile => Some(0),
                    Screen::SelectRegion => Some(1),
                    Screen::SetDates => Some(2),
                    Screen::SelectCollectors => Some(3),
                    Screen::SetOptions => Some(4),
                    Screen::Confirm => Some(5),
                    Screen::Running => Some(6),
                    _ => None,
                }
            }
        }
        Feature::Inventory => {
            if has_accounts {
                match screen {
                    Screen::SelectAccount => Some(0),
                    Screen::SetDates => Some(1),
                    Screen::Inventory => Some(2),
                    Screen::SetOptions => Some(3),
                    Screen::Confirm => Some(4),
                    Screen::Running => Some(5),
                    _ => None,
                }
            } else {
                match screen {
                    Screen::SelectProfile => Some(0),
                    Screen::SelectRegion => Some(1),
                    Screen::SetDates => Some(2),
                    Screen::Inventory => Some(3),
                    Screen::SetOptions => Some(4),
                    Screen::Confirm => Some(5),
                    Screen::Running => Some(6),
                    _ => None,
                }
            }
        }
        Feature::Poam => {
            if has_accounts {
                match screen {
                    Screen::PoamAccount => Some(0),
                    Screen::PoamRegion => Some(1),
                    Screen::PoamYear => Some(2),
                    Screen::PoamMonth => Some(3),
                    Screen::Confirm => Some(4),
                    Screen::Running => Some(5),
                    _ => None,
                }
            } else {
                match screen {
                    Screen::PoamRegion => Some(0),
                    Screen::PoamYear => Some(1),
                    Screen::PoamMonth => Some(2),
                    Screen::Confirm => Some(3),
                    Screen::Running => Some(4),
                    _ => None,
                }
            }
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Frame chrome
// ═══════════════════════════════════════════════════════════════════════════

pub(super) fn draw_header(
    f: &mut Frame,
    area: Rect,
    step: Option<(usize, usize)>,
    screen: &Screen,
) {
    let left = vec![
        Span::styled(" ◆ ", Style::default().fg(CYAN)),
        Span::styled(
            "THE GRABBER",
            Style::default().fg(CYAN).add_modifier(Modifier::BOLD),
        ),
        Span::styled("   ", Style::default()),
        Span::styled(
            "AWS Compliance Evidence Collector",
            Style::default().fg(TEXT_NORMAL),
        ),
    ];

    let right = match screen {
        Screen::Running => vec![
            Span::styled(
                "Collecting...",
                Style::default().fg(AMBER).add_modifier(Modifier::BOLD),
            ),
            Span::raw("  "),
        ],
        Screen::Results => vec![
            Span::styled("✓ ", Style::default().fg(GREEN)),
            Span::styled(
                "Complete",
                Style::default().fg(GREEN).add_modifier(Modifier::BOLD),
            ),
            Span::raw("  "),
        ],
        _ => {
            if let Some((current, total)) = step {
                vec![
                    Span::styled("Step ", Style::default().fg(TEXT_DIM)),
                    Span::styled(
                        current.to_string(),
                        Style::default().fg(AMBER).add_modifier(Modifier::BOLD),
                    ),
                    Span::styled(format!(" of {total}"), Style::default().fg(TEXT_DIM)),
                    Span::raw("  "),
                ]
            } else {
                vec![Span::raw("  ")]
            }
        }
    };

    let cols = Layout::horizontal([Constraint::Fill(1), Constraint::Min(20)]).split(area);
    f.render_widget(Paragraph::new(Line::from(left)), cols[0]);
    f.render_widget(
        Paragraph::new(Line::from(right)).alignment(Alignment::Right),
        cols[1],
    );
}

pub(super) fn draw_step_indicator(f: &mut Frame, area: Rect, current: usize, steps: &[&str]) {
    let mut spans = vec![Span::raw("   ")];
    for (i, label) in steps.iter().enumerate() {
        let (icon, style) = if i < current {
            ("● ", Style::default().fg(GREEN))
        } else if i == current {
            (
                "◉ ",
                Style::default().fg(AMBER).add_modifier(Modifier::BOLD),
            )
        } else {
            ("○ ", Style::default().fg(TEXT_DIM))
        };
        spans.push(Span::styled(icon, style));
        spans.push(Span::styled(*label, style));
        if i < steps.len() - 1 {
            spans.push(Span::styled("   ", Style::default()));
        }
    }
    f.render_widget(Paragraph::new(Line::from(spans)), area);

    if area.height > 1 {
        let bar_area = Rect {
            y: area.y + 1,
            height: 1,
            ..area
        };
        let bar_width = area.width.saturating_sub(6) as usize;
        if steps.len() > 1 && bar_width > 0 {
            let segment = bar_width / steps.len();
            let filled = segment * current + segment / 2;
            let mut bar_spans = vec![Span::raw("   ")];
            let bar_str: String = (0..bar_width)
                .map(|i| if i == filled { '●' } else { '━' })
                .collect();
            for (i, ch) in bar_str.chars().enumerate() {
                let color = if ch == '●' {
                    AMBER
                } else if i < filled {
                    GREEN
                } else {
                    BORDER_SUBTLE
                };
                bar_spans.push(Span::styled(ch.to_string(), Style::default().fg(color)));
            }
            f.render_widget(Paragraph::new(Line::from(bar_spans)), bar_area);
        }
    }
}

pub(super) fn draw_separator(f: &mut Frame, area: Rect) {
    let width = area.width.saturating_sub(4) as usize;
    let line = "┄".repeat(width);
    f.render_widget(
        Paragraph::new(Span::styled(
            format!("  {line}"),
            Style::default().fg(BORDER_SUBTLE),
        )),
        area,
    );
}

pub(super) fn draw_footer(f: &mut Frame, area: Rect, hints: &[(&str, &str)]) {
    let mut spans = vec![Span::raw("  ")];
    for (key, desc) in hints {
        spans.push(Span::styled(
            format!(" {key} "),
            Style::default()
                .fg(TEXT_BRIGHT)
                .bg(BG_ELEVATED)
                .add_modifier(Modifier::BOLD),
        ));
        spans.push(Span::styled(
            format!(" {desc}  "),
            Style::default().fg(TEXT_DIM),
        ));
    }

    let cols = Layout::horizontal([Constraint::Fill(1), Constraint::Min(12)]).split(area);
    f.render_widget(Paragraph::new(Line::from(spans)), cols[0]);
    f.render_widget(
        Paragraph::new(Span::styled("v0.1.0  ", Style::default().fg(TEXT_DIM)))
            .alignment(Alignment::Right),
        cols[1],
    );
}

pub(super) fn get_hints(screen: &Screen) -> Vec<(&'static str, &'static str)> {
    match screen {
        Screen::Welcome => vec![("⏎", "Begin"), ("Esc", "Quit")],
        Screen::FeatureSelection => vec![("↑↓", "Navigate"), ("⏎", "Select"), ("Esc", "Back")],
        Screen::SelectAccount => vec![
            ("↑↓", "Navigate"),
            ("␣", "Toggle"),
            ("a", "All"),
            ("d", "None"),
            ("⏎", "Confirm"),
            ("Esc", "Back"),
        ],
        Screen::SelectProfile => vec![("↑↓", "Navigate"), ("⏎", "Select"), ("Esc", "Back")],
        Screen::SelectRegion => vec![
            ("↑↓", "Navigate"),
            ("↓", "Custom"),
            ("⏎", "Confirm"),
            ("Esc", "Back"),
        ],
        Screen::PoamAccount => vec![("↑↓", "Navigate"), ("⏎", "Confirm"), ("Esc", "Back")],
        Screen::PoamRegion => vec![("↑↓", "Navigate"), ("⏎", "Confirm"), ("Esc", "Back")],
        Screen::PoamYear => vec![
            ("0-9", "Type Year"),
            ("⌫", "Delete"),
            ("⏎", "Confirm"),
            ("Esc", "Back"),
        ],
        Screen::PoamMonth => vec![("↑↓", "Navigate"), ("⏎", "Confirm"), ("Esc", "Back")],
        Screen::SetDates => vec![("↑↓", "Navigate"), ("⏎", "Confirm"), ("Esc", "Back")],
        Screen::Inventory => vec![
            ("↑↓", "Navigate"),
            ("␣", "Toggle"),
            ("a", "Select All"),
            ("d", "Deselect All"),
            ("⏎", "Confirm"),
            ("Esc", "Back"),
        ],
        Screen::SelectCollectors => vec![
            ("↑↓", "Navigate"),
            ("␣", "Toggle"),
            ("a", "Select All"),
            ("d", "Deselect All"),
            ("⏎", "Confirm"),
            ("Esc", "Back"),
        ],
        Screen::SetOptions => vec![
            ("⇥", "Switch Field"),
            ("↑↓", "Navigate Regions"),
            ("␣", "Toggle"),
            ("⏎", "Confirm"),
            ("Esc", "Back"),
        ],
        Screen::Confirm => vec![("⏎", "Start"), ("Esc", "Back")],
        Screen::Preparing => vec![],
        Screen::Running => vec![],
        Screen::Results => vec![("n", "New Collection"), ("q", "Quit"), ("Esc", "Exit")],
        Screen::ProviderSelection => vec![("↑↓", "Navigate"), ("⏎", "Select"), ("Esc", "Back")],
    }
}
