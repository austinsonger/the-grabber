use ratatui::layout::{Alignment, Constraint, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, Paragraph};
use ratatui::Frame;

use super::widgets::{content_inset, draw_list_with_detail};
use super::{App, GREEN, RED, TEXT_BRIGHT, TEXT_DIM, TEXT_NORMAL};

pub(super) fn draw_ecr_check_account(f: &mut Frame, area: Rect, app: &App) {
    let chunks = Layout::vertical([
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Fill(1),
    ])
    .split(content_inset(area));
    f.render_widget(
        Paragraph::new(Span::styled(
            "Select the AWS account whose Inspector2 findings to check against the inventory",
            Style::default()
                .fg(TEXT_BRIGHT)
                .add_modifier(Modifier::BOLD),
        ))
        .alignment(Alignment::Center),
        chunks[0],
    );
    f.render_widget(
        Paragraph::new(Span::styled(
            "Uses the newest inventory/**/AWS_Inventory-*.csv and the newest *_Inspector2_ECR_Image_Findings-*.csv",
            Style::default().fg(TEXT_DIM),
        ))
        .alignment(Alignment::Center),
        chunks[1],
    );
    let items: Vec<(String, String)> = app
        .ecr_check_account_list
        .iter()
        .filter_map(|&i| app.accounts.get(i))
        .map(|a| (a.name.clone(), a.profile.clone().unwrap_or_default()))
        .collect();
    draw_list_with_detail(
        f,
        chunks[3],
        "AWS Accounts",
        &items,
        app.ecr_check_account_cursor,
    );
}

pub(super) fn draw_ecr_check_running(f: &mut Frame, area: Rect, _app: &App) {
    let v = Layout::vertical([
        Constraint::Fill(1),
        Constraint::Length(1),
        Constraint::Fill(1),
    ])
    .split(area);
    f.render_widget(
        Paragraph::new(Span::styled(
            "Checking ECR findings against the inventory (live Inspector2 queries)…",
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
