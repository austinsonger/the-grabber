use ratatui::layout::{Alignment, Constraint, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;
use ratatui::Frame;

use super::widgets::{content_inset, draw_list_with_detail, draw_text_field};
use super::{App, AMBER, GREEN, RED, TEXT_BRIGHT, TEXT_DIM};
use crate::stig_status::{RemediationOutcome, StigStatus};

// ═══════════════════════════════════════════════════════════════════════════
// Account selection
// ═══════════════════════════════════════════════════════════════════════════

pub(super) fn draw_stig_remediation_account(f: &mut Frame, area: Rect, app: &App) {
    let chunks = Layout::vertical([
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Fill(1),
    ])
    .split(content_inset(area));

    f.render_widget(
        Paragraph::new(Span::styled(
            "Select the Okta tenant to scan and remediate",
            Style::default()
                .fg(TEXT_BRIGHT)
                .add_modifier(Modifier::BOLD),
        ))
        .alignment(Alignment::Center),
        chunks[0],
    );

    let items: Vec<(String, String)> = app
        .stig_account_list
        .iter()
        .filter_map(|&i| app.accounts.get(i))
        .map(|a| (a.name.clone(), a.okta_domain_resolved().unwrap_or_default()))
        .collect();

    draw_list_with_detail(
        f,
        chunks[3],
        "Okta Accounts",
        &items,
        app.stig_account_cursor,
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// Live scanning (async-driven — see runner/tui_session.rs)
// ═══════════════════════════════════════════════════════════════════════════

pub(super) fn draw_stig_remediation_scanning(f: &mut Frame, area: Rect, _app: &App) {
    let v = Layout::vertical([
        Constraint::Fill(1),
        Constraint::Length(1),
        Constraint::Fill(1),
    ])
    .split(area);
    f.render_widget(
        Paragraph::new(Span::styled(
            "Evaluating all 24 DISA STIG checks against the live tenant…",
            Style::default().fg(AMBER).add_modifier(Modifier::BOLD),
        ))
        .alignment(Alignment::Center),
        v[1],
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// Findings list + inline detail/confirm
// ═══════════════════════════════════════════════════════════════════════════

fn status_icon(status: StigStatus) -> (&'static str, ratatui::style::Color) {
    match status {
        StigStatus::Open => ("✗", RED),
        StigStatus::NotReviewed => ("?", AMBER),
        StigStatus::NotAFinding | StigStatus::NotApplicable => ("✓", GREEN),
    }
}

pub(super) fn draw_stig_remediation_list(f: &mut Frame, area: Rect, app: &App) {
    if let Some(err) = &app.stig_scan_error {
        let v = Layout::vertical([
            Constraint::Fill(1),
            Constraint::Length(1),
            Constraint::Fill(1),
        ])
        .split(content_inset(area));
        f.render_widget(
            Paragraph::new(Span::styled(
                format!("Scan failed: {err}"),
                Style::default().fg(RED),
            ))
            .alignment(Alignment::Center),
            v[1],
        );
        return;
    }

    let actionable: Vec<&crate::stig_status::StigCheckResult> = app
        .stig_findings
        .iter()
        .filter(|r| r.status.is_actionable())
        .collect();

    if actionable.is_empty() {
        let v = Layout::vertical([
            Constraint::Fill(1),
            Constraint::Length(1),
            Constraint::Fill(1),
        ])
        .split(content_inset(area));
        f.render_widget(
            Paragraph::new(Span::styled(
                "All 24 checks pass or are not applicable on this tenant. Nothing to remediate.",
                Style::default().fg(GREEN),
            ))
            .alignment(Alignment::Center),
            v[1],
        );
        return;
    }

    let items: Vec<(String, String)> = actionable
        .iter()
        .map(|r| {
            let (icon, _) = status_icon(r.status);
            let name = format!("{icon} {}", r.v_id);
            let remediation_desc = match r.remediation.len() {
                0 => String::new(),
                1 => r.remediation[0].describe(),
                n => format!(
                    "{n} resources will be updated:\n{}",
                    r.remediation
                        .iter()
                        .map(|t| format!("  - {}", t.describe()))
                        .collect::<Vec<_>>()
                        .join("\n")
                ),
            };
            let mut desc = format!(
                "{}\n\nStatus: {}\nExpected: {}\nActual: {}\n\n{}",
                r.details,
                r.status.as_stig_str(),
                r.expected_value,
                r.actual_value,
                remediation_desc,
            );
            if app.stig_confirm_pending
                && actionable
                    .get(app.stig_finding_cursor)
                    .map(|c| c.v_id == r.v_id)
                    .unwrap_or(false)
            {
                let needs_text = r
                    .remediation
                    .first()
                    .map(|t| t.needs_text_input())
                    .unwrap_or(false);
                desc.push_str(if needs_text {
                    "\n\n[Type the text below, Enter to apply, Esc to cancel]"
                } else {
                    "\n\n[Press y to apply, n/Esc to cancel]"
                });
            }
            (name, desc)
        })
        .collect();

    let list_area = if app.stig_confirm_pending
        && actionable
            .get(app.stig_finding_cursor)
            .and_then(|r| r.remediation.first())
            .map(|t| t.needs_text_input())
            .unwrap_or(false)
    {
        let chunks = Layout::vertical([Constraint::Fill(1), Constraint::Length(3)]).split(area);
        draw_text_field(
            f,
            chunks[1],
            "Banner text",
            &app.stig_text_input.value,
            true,
        );
        chunks[0]
    } else {
        area
    };

    draw_list_with_detail(
        f,
        list_area,
        &format!("Findings ({} actionable)", actionable.len()),
        &items,
        app.stig_finding_cursor,
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// Applying (async-driven)
// ═══════════════════════════════════════════════════════════════════════════

pub(super) fn draw_stig_remediation_applying(f: &mut Frame, area: Rect, _app: &App) {
    let v = Layout::vertical([
        Constraint::Fill(1),
        Constraint::Length(1),
        Constraint::Fill(1),
    ])
    .split(area);
    f.render_widget(
        Paragraph::new(Span::styled(
            "Applying…",
            Style::default().fg(AMBER).add_modifier(Modifier::BOLD),
        ))
        .alignment(Alignment::Center),
        v[1],
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// Session results
// ═══════════════════════════════════════════════════════════════════════════

pub(super) fn draw_stig_remediation_results(f: &mut Frame, area: Rect, app: &App) {
    let applied = app
        .stig_outcomes
        .iter()
        .filter(|(_, o)| matches!(o, RemediationOutcome::Applied { .. }))
        .count();
    let manual = app
        .stig_outcomes
        .iter()
        .filter(|(_, o)| matches!(o, RemediationOutcome::ManuallyAcknowledged))
        .count();
    let failed = app
        .stig_outcomes
        .iter()
        .filter(|(_, o)| matches!(o, RemediationOutcome::Failed { .. }))
        .count();

    let chunks = Layout::vertical([
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Fill(1),
    ])
    .split(content_inset(area));

    f.render_widget(
        Paragraph::new(Span::styled(
            "STIG Remediation Session Summary",
            Style::default()
                .fg(TEXT_BRIGHT)
                .add_modifier(Modifier::BOLD),
        ))
        .alignment(Alignment::Center),
        chunks[0],
    );
    f.render_widget(
        Paragraph::new(Span::styled(
            format!(
                "{applied} applied · {manual} manually acknowledged · {failed} failed · {} total attempted",
                app.stig_outcomes.len()
            ),
            Style::default().fg(TEXT_DIM),
        ))
        .alignment(Alignment::Center),
        chunks[1],
    );

    let mut lines: Vec<Line> = app
        .stig_outcomes
        .iter()
        .map(|(v_id, outcome)| {
            let (label, color) = match outcome {
                RemediationOutcome::Applied { .. } => ("applied", GREEN),
                RemediationOutcome::ManuallyAcknowledged => ("manual", AMBER),
                RemediationOutcome::Failed { .. } => ("failed", RED),
            };
            Line::from(vec![
                Span::styled(format!("  {v_id:<12}"), Style::default().fg(TEXT_BRIGHT)),
                Span::styled(label, Style::default().fg(color)),
                Span::styled(
                    format!("  {}", outcome.detail()),
                    Style::default().fg(TEXT_DIM),
                ),
            ])
        })
        .collect();
    if let Some(path) = &app.stig_log_path {
        lines.push(Line::raw(""));
        lines.push(Line::from(Span::styled(
            format!("Audit log: {path}"),
            Style::default().fg(TEXT_DIM),
        )));
    }

    f.render_widget(Paragraph::new(lines), chunks[3]);
}
