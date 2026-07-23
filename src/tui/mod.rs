pub mod app;
pub mod collector_data;
pub mod events;
pub mod menus;
pub mod scan;
pub mod state;
pub mod ui;

pub use app::App;
pub use state::{
    CollectorFocus, CollectorState, CollectorStatus, Feature, PoamSummary, Progress, Screen,
};

use std::io;

use anyhow::Result;
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::backend::CrosstermBackend;
use ratatui::Terminal;

// ---------------------------------------------------------------------------
// Read ~/.aws/config for available profiles
// ---------------------------------------------------------------------------

pub fn read_aws_profiles() -> Vec<String> {
    let path = dirs_next::home_dir()
        .map(|h| h.join(".aws").join("config"))
        .unwrap_or_default();

    let content = match std::fs::read_to_string(&path) {
        Ok(c) => c,
        Err(_) => return vec![],
    };

    content
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            if line.starts_with("[profile ") && line.ends_with(']') {
                Some(line[9..line.len() - 1].to_string())
            } else if line == "[default]" {
                Some("default".to_string())
            } else {
                None
            }
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Terminal setup / teardown
// ---------------------------------------------------------------------------

pub fn setup_terminal() -> Result<Terminal<CrosstermBackend<io::Stdout>>> {
    let original_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let _ = disable_raw_mode();
        let _ = crossterm::execute!(io::stdout(), LeaveAlternateScreen);
        original_hook(info);
    }));

    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    Ok(Terminal::new(backend)?)
}

pub fn restore_terminal(terminal: &mut Terminal<CrosstermBackend<io::Stdout>>) -> Result<()> {
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Event loop
// ---------------------------------------------------------------------------

/// Returns the configured App when the user reaches the Confirm screen and
/// presses Enter, or None if they quit early.
pub fn run(mut app: App) -> Result<Option<App>> {
    let mut terminal = setup_terminal()?;

    let result = events::event_loop(&mut terminal, &mut app);

    restore_terminal(&mut terminal)?;
    result?;

    if app.screen == Screen::Running
        || app.screen == Screen::Results
        || app.screen == Screen::StigRemediationScanning
        || app.screen == Screen::StigRemediationApplying
    {
        Ok(Some(app))
    } else {
        Ok(None)
    }
}
