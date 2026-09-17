use ratatui::layout::{Alignment, Constraint, Layout, Rect};
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, Paragraph};
use ratatui::Frame;

use super::widgets::content_inset;
use super::{App, GREEN, RED, TEXT_NORMAL};

pub(super) fn draw_ecr_check_running(f: &mut Frame, area: Rect, app: &App) {
    let v = Layout::vertical([
        Constraint::Fill(1),
        Constraint::Length(1),
        Constraint::Fill(1),
    ])
    .split(area);
    let n = app.selected_account_indices().len();
    f.render_widget(
        Paragraph::new(Span::styled(
            format!("Collecting ECR findings from the inventory and verifying… ({n} accounts)"),
            Style::default().fg(TEXT_NORMAL),
        ))
        .alignment(Alignment::Center),
        v[1],
    );
}

pub(super) fn draw_ecr_check_results(f: &mut Frame, area: Rect, app: &App) {
    let color = if app.ecr_check_failed { RED } else { GREEN };
    let title = if app.ecr_check_failed {
        " ECR Findings Check: FAILURES "
    } else {
        " ECR Findings Check: OK "
    };
    let lines: Vec<Line> = app
        .ecr_check_lines
        .iter()
        .map(|l| Line::from(Span::styled(l.clone(), Style::default().fg(TEXT_NORMAL))))
        .collect();
    let block = Block::bordered()
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(color))
        .title(Span::styled(title, Style::default().fg(color)));
    f.render_widget(Paragraph::new(lines).block(block), content_inset(area));
}
