use ratatui::layout::{Alignment, Constraint, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, List, ListItem, ListState, Paragraph};
use ratatui::Frame;

use super::widgets::content_inset;
use super::{
    App, AMBER, BG_MAIN, BG_SELECTED, BORDER_SUBTLE, GREEN, RED, TEXT_BRIGHT, TEXT_DIM, TEXT_NORMAL,
};

// ═══════════════════════════════════════════════════════════════════════════
// SBOM export destination (bucket / KMS key / prefix)
// ═══════════════════════════════════════════════════════════════════════════

pub(super) fn draw_sbom_destination(f: &mut Frame, area: Rect, app: &App) {
    let inset = content_inset(area);

    let chunks = Layout::vertical([
        Constraint::Length(1), // title
        Constraint::Length(1), // subtitle
        Constraint::Length(1), // spacer
        Constraint::Length(3), // bucket
        Constraint::Length(3), // kms
        Constraint::Length(3), // prefix
        Constraint::Fill(1),   // note
    ])
    .split(inset);

    f.render_widget(
        Paragraph::new(Span::styled(
            "Inspector SBOM Export Destination",
            Style::default()
                .fg(TEXT_BRIGHT)
                .add_modifier(Modifier::BOLD),
        ))
        .alignment(Alignment::Center),
        chunks[0],
    );

    f.render_widget(
        Paragraph::new(Span::styled(
            "↑↓ to switch field, type to edit, Enter to discover repositories",
            Style::default().fg(TEXT_DIM),
        ))
        .alignment(Alignment::Center),
        chunks[1],
    );

    let fields = [
        ("S3 Bucket (required)", &app.sbom_bucket_input.value, 0usize),
        ("KMS Key ARN (required)", &app.sbom_kms_input.value, 1usize),
        (
            "Key Prefix (optional)",
            &app.sbom_prefix_input.value,
            2usize,
        ),
    ];

    for (label, value, idx) in fields {
        let focused = app.sbom_dest_field == idx;
        let border_style = if focused {
            Style::default().fg(AMBER)
        } else {
            Style::default().fg(BORDER_SUBTLE)
        };
        let shown = if focused {
            format!("{value}▏")
        } else {
            value.to_string()
        };
        f.render_widget(
            Paragraph::new(Span::styled(shown, Style::default().fg(TEXT_NORMAL))).block(
                Block::bordered()
                    .border_type(BorderType::Rounded)
                    .border_style(border_style)
                    .style(Style::default().bg(BG_MAIN))
                    .title(Span::styled(label, Style::default().fg(TEXT_DIM))),
            ),
            chunks[3 + idx],
        );
    }

    f.render_widget(
        Paragraph::new(vec![
            Line::from(Span::styled(
                "Inspector writes the export into this bucket, then grabber downloads",
                Style::default().fg(TEXT_DIM),
            )),
            Line::from(Span::styled(
                "the SBOM for the newest scanned image of each repository you pick.",
                Style::default().fg(TEXT_DIM),
            )),
        ])
        .alignment(Alignment::Center),
        chunks[6],
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// Repository discovery (async work in progress)
// ═══════════════════════════════════════════════════════════════════════════

pub(super) fn draw_sbom_repo_discovery(f: &mut Frame, area: Rect, _app: &App) {
    let inset = content_inset(area);

    let chunks = Layout::vertical([
        Constraint::Fill(1),
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Fill(1),
    ])
    .split(inset);

    f.render_widget(
        Paragraph::new(Span::styled(
            "Discovering ECR repositories…",
            Style::default()
                .fg(TEXT_BRIGHT)
                .add_modifier(Modifier::BOLD),
        ))
        .alignment(Alignment::Center),
        chunks[1],
    );

    f.render_widget(
        Paragraph::new(Span::styled(
            "Calling ecr:DescribeRepositories for the first selected AWS account",
            Style::default().fg(TEXT_DIM),
        ))
        .alignment(Alignment::Center),
        chunks[2],
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// Repository picker
// ═══════════════════════════════════════════════════════════════════════════

pub(super) fn draw_sbom_repo_selection(f: &mut Frame, area: Rect, app: &App) {
    let inset = content_inset(area);

    let chunks = Layout::vertical([
        Constraint::Length(1), // title
        Constraint::Length(1), // subtitle
        Constraint::Length(1), // spacer
        Constraint::Length(3), // search
        Constraint::Fill(1),   // list
    ])
    .split(inset);

    f.render_widget(
        Paragraph::new(Span::styled(
            "Select ECR Repositories for SBOM Export",
            Style::default()
                .fg(TEXT_BRIGHT)
                .add_modifier(Modifier::BOLD),
        ))
        .alignment(Alignment::Center),
        chunks[0],
    );

    let selected_count = app.sbom_repo_selected.len();
    f.render_widget(
        Paragraph::new(Span::styled(
            format!(
                "Space to toggle, a = all, d = none, Enter to confirm — {selected_count} selected"
            ),
            Style::default().fg(TEXT_DIM),
        ))
        .alignment(Alignment::Center),
        chunks[1],
    );

    f.render_widget(
        Paragraph::new(Span::styled(
            format!("{}▏", app.sbom_repo_search.value),
            Style::default().fg(TEXT_NORMAL),
        ))
        .block(
            Block::bordered()
                .border_type(BorderType::Rounded)
                .border_style(Style::default().fg(BORDER_SUBTLE))
                .style(Style::default().bg(BG_MAIN))
                .title(Span::styled("Filter", Style::default().fg(TEXT_DIM))),
        ),
        chunks[3],
    );

    let list_area = chunks[4];
    let visible = app.visible_sbom_repos();

    if visible.is_empty() {
        let block = Block::bordered()
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(BORDER_SUBTLE))
            .style(Style::default().bg(BG_MAIN));
        let inner = block.inner(list_area);
        f.render_widget(block, list_area);

        let v = Layout::vertical([
            Constraint::Fill(1),
            Constraint::Length(1),
            Constraint::Fill(1),
        ])
        .split(inner);

        let (msg, style) = match app.sbom_discovery_error.as_deref() {
            Some(err) => (err.to_string(), Style::default().fg(RED)),
            None if app.sbom_repo_list.is_empty() => (
                "No ECR repositories found in this account/region.".to_string(),
                Style::default().fg(TEXT_DIM),
            ),
            None => (
                "No repositories match the filter.".to_string(),
                Style::default().fg(TEXT_DIM),
            ),
        };
        f.render_widget(
            Paragraph::new(Span::styled(msg, style)).alignment(Alignment::Center),
            v[1],
        );
        return;
    }

    let mut items: Vec<ListItem> = Vec::with_capacity(visible.len());
    for (cursor_pos, &real_idx) in visible.iter().enumerate() {
        let repo = &app.sbom_repo_list[real_idx];
        let at_cursor = cursor_pos == app.sbom_repo_cursor;
        let checked = app.sbom_repo_selected.contains(&real_idx);

        let checkbox = if checked { "[✓] " } else { "[ ] " };
        let checkbox_style = if checked {
            Style::default().fg(GREEN)
        } else {
            Style::default().fg(TEXT_DIM)
        };

        let name_style = if at_cursor {
            Style::default()
                .fg(AMBER)
                .add_modifier(Modifier::BOLD)
                .bg(BG_SELECTED)
        } else {
            Style::default()
                .fg(TEXT_BRIGHT)
                .add_modifier(Modifier::BOLD)
        };

        items.push(ListItem::new(Line::from(vec![
            Span::styled(checkbox, checkbox_style),
            Span::styled(format!("{:<40}", repo.name), name_style),
            Span::styled("  ", Style::default()),
            Span::styled(repo.uri.clone(), Style::default().fg(TEXT_DIM)),
        ])));
    }

    let mut state = ListState::default();
    state.select(Some(app.sbom_repo_cursor));

    let block = Block::bordered()
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(BORDER_SUBTLE))
        .style(Style::default().bg(BG_MAIN));

    f.render_stateful_widget(
        List::new(items)
            .highlight_style(Style::default())
            .highlight_symbol("")
            .block(block),
        list_area,
        &mut state,
    );
}

#[cfg(test)]
mod tests {
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;

    use crate::providers::aws::ecr_repos::EcrRepoSummary;
    use crate::tui::state::Screen;
    use crate::tui::App;

    /// Terminal sizes the wizard is expected to survive. The narrow one matters
    /// most: these screens index fixed layout slots (`chunks[3 + idx]`,
    /// `chunks[6]`, `chunks[4]`), which is exactly what a short/narrow terminal
    /// stresses.
    const WIDE: (u16, u16) = (120, 40);
    const NORMAL: (u16, u16) = (80, 24);
    const NARROW: (u16, u16) = (40, 12);

    /// Render the whole frame — `ui::draw`, not the individual draw functions —
    /// so the `Screen` dispatch, step indicator and footer hints are exercised
    /// too, then flatten the buffer to one line of text per terminal row.
    fn render(app: &App, (width, height): (u16, u16)) -> String {
        let mut terminal = Terminal::new(TestBackend::new(width, height)).expect("test terminal");
        terminal
            .draw(|f| crate::tui::ui::draw(f, app))
            .expect("draw must not fail");

        let buffer = terminal.backend().buffer().clone();
        let mut out = String::new();
        for y in 0..buffer.area.height {
            for x in 0..buffer.area.width {
                out.push_str(buffer[(x, y)].symbol());
            }
            out.push('\n');
        }
        out
    }

    fn sbom_app() -> App {
        let mut app = App::new(vec![]);
        let idx = app
            .collector_items
            .iter()
            .position(|(k, _, _)| *k == "inspector-sbom")
            .expect("inspector-sbom is in the AWS menu");
        app.collector_selected.insert(idx);
        assert!(app.sbom_selected());
        app.sbom_repo_list = ["alpha", "beta"]
            .iter()
            .map(|n| EcrRepoSummary {
                name: (*n).to_string(),
                uri: format!("1.dkr.ecr.us-east-1.amazonaws.com/{n}"),
            })
            .collect();
        app
    }

    #[test]
    fn all_three_screens_render_their_titles() {
        let mut app = sbom_app();
        let cases = [
            (Screen::SbomDestination, "Inspector SBOM Export Destination"),
            (Screen::SbomRepoDiscovery, "Discovering ECR repositories…"),
            (
                Screen::SbomRepoSelection,
                "Select ECR Repositories for SBOM Export",
            ),
        ];

        for (screen, title) in cases {
            for size in [WIDE, NORMAL] {
                app.screen = screen.clone();
                let text = render(&app, size);
                assert!(
                    text.contains(title),
                    "{screen:?} at {size:?} should render {title:?}, got:\n{text}"
                );
            }
        }
    }

    #[test]
    fn destination_screen_renders_all_three_input_fields() {
        let mut app = sbom_app();
        app.screen = Screen::SbomDestination;
        let text = render(&app, WIDE);

        for label in [
            "S3 Bucket (required)",
            "KMS Key ARN (required)",
            "Key Prefix (optional)",
        ] {
            assert!(text.contains(label), "missing {label:?} in:\n{text}");
        }
        // Footer hints come from get_hints, i.e. the frame wiring.
        assert!(text.contains("Discover Repos"), "missing hint in:\n{text}");
    }

    #[test]
    fn narrow_terminal_degrades_without_panicking() {
        let mut app = sbom_app();
        for screen in [
            Screen::SbomDestination,
            Screen::SbomRepoDiscovery,
            Screen::SbomRepoSelection,
        ] {
            app.screen = screen.clone();
            let text = render(&app, NARROW);
            // The body may be squeezed out entirely at 12 rows, but the frame
            // must still render rather than panic on a zero-height slot.
            assert!(
                text.contains("THE GRABBER"),
                "{screen:?} lost its frame at {NARROW:?}:\n{text}"
            );
            assert_eq!(
                text.lines().count(),
                NARROW.1 as usize,
                "{screen:?} should fill every row"
            );
        }

        // The discovery screen is short enough to keep its message even here.
        app.screen = Screen::SbomRepoDiscovery;
        assert!(render(&app, NARROW).contains("Discovering ECR repositories…"));
    }

    #[test]
    fn picker_renders_repositories_with_their_checkbox_state() {
        let mut app = sbom_app();
        app.screen = Screen::SbomRepoSelection;
        app.sbom_repo_selected.insert(1); // beta

        let text = render(&app, WIDE);
        assert!(text.contains("[ ] alpha"), "alpha unchecked in:\n{text}");
        assert!(text.contains("[✓] beta"), "beta checked in:\n{text}");
        assert!(text.contains("1 selected"), "count in:\n{text}");
        assert!(
            text.contains("1.dkr.ecr.us-east-1.amazonaws.com/beta"),
            "repository URI in:\n{text}"
        );
    }

    #[test]
    fn picker_renders_the_discovery_error_in_place_of_the_list() {
        let mut app = sbom_app();
        app.screen = Screen::SbomRepoSelection;
        app.sbom_repo_list.clear();
        app.sbom_discovery_error = Some("ecr:DescribeRepositories denied".to_string());

        let text = render(&app, WIDE);
        assert!(
            text.contains("ecr:DescribeRepositories denied"),
            "discovery error in:\n{text}"
        );
        assert!(
            !text.contains("No ECR repositories found"),
            "error must win over the empty state in:\n{text}"
        );
    }

    #[test]
    fn picker_distinguishes_no_repositories_from_no_filter_matches() {
        let mut app = sbom_app();
        app.screen = Screen::SbomRepoSelection;

        app.sbom_repo_list.clear();
        assert!(render(&app, WIDE).contains("No ECR repositories found in this account/region."));

        app = sbom_app();
        app.screen = Screen::SbomRepoSelection;
        app.sbom_repo_search = crate::tui::state::TextInput::new("zzz");
        assert!(render(&app, WIDE).contains("No repositories match the filter."));
    }

    #[test]
    fn step_indicator_uses_the_sbom_arrays_only_when_sbom_is_selected() {
        let mut with_sbom = sbom_app();
        with_sbom.screen = Screen::SbomDestination;
        let text = render(&with_sbom, WIDE);
        assert!(text.contains("SBOM Dest"), "SBOM step label in:\n{text}");
        assert!(text.contains("Repos"), "Repos step label in:\n{text}");

        let mut without_sbom = App::new(vec![]);
        without_sbom.screen = Screen::SbomDestination;
        assert!(!without_sbom.sbom_selected());
        let text = render(&without_sbom, WIDE);
        assert!(
            !text.contains("SBOM Dest"),
            "non-SBOM runs must keep the short step array:\n{text}"
        );
    }

    #[test]
    fn set_options_step_number_shifts_by_two_when_sbom_is_selected() {
        // Whether the account or legacy array is in play depends on the
        // config.toml present on the machine, so derive the expectation.
        let mut with_sbom = sbom_app();
        with_sbom.screen = Screen::SetOptions;
        let expected = if with_sbom.has_accounts() {
            "Step 7 of 9"
        } else {
            "Step 8 of 10"
        };
        let text = render(&with_sbom, WIDE);
        assert!(text.contains(expected), "expected {expected:?} in:\n{text}");

        let mut without_sbom = App::new(vec![]);
        without_sbom.screen = Screen::SetOptions;
        let expected = if without_sbom.has_accounts() {
            "Step 5 of 7"
        } else {
            "Step 6 of 8"
        };
        let text = render(&without_sbom, WIDE);
        assert!(text.contains(expected), "expected {expected:?} in:\n{text}");
    }
}
