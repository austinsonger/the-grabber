# Contextual Help Overlay Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add a `?`-triggered modal overlay that shows each screen's purpose, keyboard shortcuts, and data-collected info, dismissible via `Esc`.

**Architecture:** Add `show_help: bool` to `App`; intercept `?` / `Esc` in `handle_key()` before the screen dispatch; render a ratatui `Clear`+`Block`+`Paragraph` overlay at the end of `draw()`, drawing shortcut data from the existing `get_hints()` function.

**Tech Stack:** Rust, ratatui (already in use), crossterm (already in use), `#[test]` / `TestBackend` for tests.

---

## Context

The TUI wizard has 17 screens (Welcome → Results) each with context-sensitive footer hints. There is no way to see a full shortcut reference or understand what a screen does without guessing. This overlay surfaces that information on demand without disrupting the existing layout.

Mouse events are **not enabled** in this app (`setup_terminal()` does not call `EnableMouseCapture`). "Click outside to dismiss" is therefore deferred — `Esc` is the dismiss mechanism.

---

## Critical Files

| File | What changes |
|------|-------------|
| `src/tui/mod.rs` | Add `show_help` field to `App`; update `new()`, `reset()`; intercept `?`/`Esc` in `handle_key()` |
| `src/tui/ui.rs` | Add `ScreenHelp` struct, `screen_help()`, `wrap_text()`, `centered_rect()`, `draw_help_overlay()`; call from `draw()`; append `?` hint to footer |

---

## Existing Functions to Reuse

- `get_hints(screen: &Screen) -> Vec<(&'static str, &'static str)>` — `src/tui/ui.rs:435` — already has all per-screen shortcut pairs; the overlay must call this to stay DRY.
- `draw_error_banner(f, area, msg)` — `src/tui/ui.rs:2988` — pattern to copy for last-drawn overlay that uses `Clear`.
- `App::reset()` — `src/tui/mod.rs:1302` — must also reset `show_help`.
- `Screen` enum — `src/tui/mod.rs:93` — 17 variants: Welcome, FeatureSelection, SelectAccount, SelectProfile, SelectRegion, SetDates, Inventory, PoamAccount, PoamRegion, PoamYear, PoamMonth, SelectCollectors, SetOptions, Confirm, Preparing, Running, Results.

---

## Task 1: Add `show_help` to `App`

**Files:**
- Modify: `src/tui/mod.rs:283` (App struct), `src/tui/mod.rs:894` (App::new), `src/tui/mod.rs:1317` (App::reset)
- Test: `src/tui/mod.rs` (new `#[cfg(test)] mod tests` block at bottom)

**Step 1: Write the failing tests**

Add at the bottom of `src/tui/mod.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn make_app() -> App {
        App::new(vec!["default".to_string()])
    }

    #[test]
    fn show_help_defaults_false() {
        let app = make_app();
        assert!(!app.show_help);
    }

    #[test]
    fn show_help_resets_to_false() {
        let mut app = make_app();
        app.show_help = true;
        app.reset();
        assert!(!app.show_help);
    }
}
```

**Step 2: Run to confirm failure**

```
cargo test --lib tui::tests 2>&1 | tail -20
```
Expected: `error[E0609]: no field 'show_help'`

**Step 3: Add the field**

In `src/tui/mod.rs` after line 283 (`pub error_msg: Option<String>,`):
```rust
    pub show_help: bool,
```

In `App::new()` around line 894 (after `error_msg: None,`):
```rust
            show_help: false,
```

In `App::reset()` around line 1317 (after `self.error_msg = None;`):
```rust
        self.show_help = false;
```

**Step 4: Run to confirm pass**

```
cargo test --lib tui::tests
```
Expected: `test result: ok. 2 passed`

**Step 5: Commit**

```bash
git add src/tui/mod.rs
git commit -m "feat(tui): add show_help field to App with reset support"
```

---

## Task 2: Add `ScreenHelp` struct and `screen_help()` function

**Files:**
- Modify: `src/tui/ui.rs` (add before `draw_error_banner` at line 2988)
- Test: `src/tui/ui.rs` (new `#[cfg(test)] mod tests` block at bottom)

**Step 1: Write the failing tests**

Add at the bottom of `src/tui/ui.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use super::super::Screen;

    #[test]
    fn screen_help_all_variants_have_content() {
        let screens = [
            Screen::Welcome, Screen::FeatureSelection, Screen::SelectAccount,
            Screen::SelectProfile, Screen::SelectRegion, Screen::SetDates,
            Screen::Inventory, Screen::PoamAccount, Screen::PoamRegion,
            Screen::PoamYear, Screen::PoamMonth, Screen::SelectCollectors,
            Screen::SetOptions, Screen::Confirm, Screen::Preparing,
            Screen::Running, Screen::Results,
        ];
        for s in &screens {
            let h = screen_help(s);
            assert!(!h.title.is_empty(), "missing title for {s:?}");
            assert!(!h.description.is_empty(), "missing description for {s:?}");
        }
    }

    #[test]
    fn wrap_text_splits_at_width() {
        let result = wrap_text("hello world foo bar", 11);
        assert_eq!(result[0], "hello world");
        assert_eq!(result[1], "foo bar");
    }

    #[test]
    fn wrap_text_zero_width_returns_whole_string() {
        let result = wrap_text("hello world", 0);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0], "hello world");
    }
}
```

**Step 2: Run to confirm failure**

```
cargo test --lib tui::ui::tests 2>&1 | tail -20
```
Expected: `error[E0425]: cannot find function 'screen_help'`

**Step 3: Add `ScreenHelp`, `screen_help()`, and `wrap_text()` to `src/tui/ui.rs`**

Insert just before the `draw_error_banner` function (line 2988):

```rust
// ═══════════════════════════════════════════════════════════════════════════
// Help overlay content
// ═══════════════════════════════════════════════════════════════════════════

pub struct ScreenHelp {
    pub title: &'static str,
    pub description: &'static str,
    pub data_collected: &'static str,
}

pub fn screen_help(screen: &Screen) -> ScreenHelp {
    match screen {
        Screen::Welcome => ScreenHelp {
            title: "Welcome",
            description: "The Grabber starting screen. Press Enter to begin the configuration wizard.",
            data_collected: "No data collected on this screen.",
        },
        Screen::FeatureSelection => ScreenHelp {
            title: "Feature Selection",
            description: "Choose a workflow: Collectors pulls evidence from AWS services into CSV/JSON. Inventory builds a unified asset CSV. POAM reconciles Inspector2 ECR findings into a FedRAMP POAM workbook.",
            data_collected: "No data collected on this screen.",
        },
        Screen::SelectAccount => ScreenHelp {
            title: "Select Account",
            description: "Pick one or more TOML-configured AWS accounts to collect evidence from. Use Space to toggle, 'a' to select all, 'd' to deselect all.",
            data_collected: "Account names, IDs, and profiles are read from config.toml. No AWS API calls are made here.",
        },
        Screen::SelectProfile => ScreenHelp {
            title: "Select AWS Profile",
            description: "Pick a single AWS named profile from ~/.aws/config to authenticate evidence collection.",
            data_collected: "Profile list is read from ~/.aws/config. No AWS API calls are made on this screen.",
        },
        Screen::SelectRegion => ScreenHelp {
            title: "Select Region",
            description: "Choose the AWS region to collect evidence from. Scroll to pick a region or type a custom region code.",
            data_collected: "No AWS API calls on this screen. Region is passed to all collectors during the Run step.",
        },
        Screen::SetDates => ScreenHelp {
            title: "Set Date Range",
            description: "Select a time window (1-12 months) for evidence collection. Time-based collectors (CloudTrail, Config history) query only within this window.",
            data_collected: "No AWS API calls on this screen. Start/end dates are computed and passed to collectors.",
        },
        Screen::Inventory => ScreenHelp {
            title: "Inventory Asset Types",
            description: "Multi-select which AWS asset types to include in the unified inventory CSV.",
            data_collected: "No AWS API calls on this screen. Selected asset types determine which inventory collectors run.",
        },
        Screen::PoamAccount => ScreenHelp {
            title: "POAM: Select Account",
            description: "Select the AWS account whose Inspector2 ECR findings will be reconciled into the FedRAMP POAM workbook.",
            data_collected: "Account metadata from config.toml. No AWS API calls on this screen.",
        },
        Screen::PoamRegion => ScreenHelp {
            title: "POAM: Select Region",
            description: "Select the AWS region where Inspector2 is enabled for ECR vulnerability data.",
            data_collected: "No AWS API calls on this screen.",
        },
        Screen::PoamYear => ScreenHelp {
            title: "POAM: Fiscal Year",
            description: "Type the four-digit year for the POAM cycle (e.g. 2025). This determines the evidence directory path.",
            data_collected: "No AWS API calls on this screen.",
        },
        Screen::PoamMonth => ScreenHelp {
            title: "POAM: Month",
            description: "Select the calendar month for the POAM cycle. Combined with the year this resolves the evidence folder path.",
            data_collected: "No AWS API calls on this screen.",
        },
        Screen::SelectCollectors => ScreenHelp {
            title: "Select Collectors",
            description: "Two-panel view: left navigates 12 collector categories, right shows individual collectors. Tab switches panels. Space toggles. Number keys 1-9 jump to categories.",
            data_collected: "No AWS API calls. Selection drives which collectors run (CloudTrail, S3, IAM, RDS, etc).",
        },
        Screen::SetOptions => ScreenHelp {
            title: "Set Options",
            description: "Configure output options: Filter (substring match on collector keys), Include Raw JSON, All Regions, Zip Bundle, Sign Manifest, and per-region overrides.",
            data_collected: "No AWS API calls on this screen.",
        },
        Screen::Confirm => ScreenHelp {
            title: "Confirm & Start",
            description: "Review your configuration. Press Enter to start evidence collection or Esc to go back.",
            data_collected: "No AWS API calls on this screen.",
        },
        Screen::Preparing => ScreenHelp {
            title: "Preparing",
            description: "Building AWS SDK clients for each selected account. STS AssumeRole calls are made here for role-based credentials.",
            data_collected: "STS GetCallerIdentity or AssumeRole per account.",
        },
        Screen::Running => ScreenHelp {
            title: "Running",
            description: "Evidence collection is in progress. Collectors run concurrently. You cannot cancel once collection has started.",
            data_collected: "Active AWS API calls across all selected collectors and regions. Output files are written to the configured output directory.",
        },
        Screen::Results => ScreenHelp {
            title: "Results",
            description: "Collection is complete. Lists all output files written. Press 'n' to start a new collection or 'q'/Esc to exit.",
            data_collected: "All collector output is written to disk. If Zip was enabled, a dated .zip bundle is created. If Sign was enabled, an HMAC-SHA256 manifest and key file are written.",
        },
    }
}

fn wrap_text(s: &str, width: usize) -> Vec<String> {
    if width == 0 {
        return vec![s.to_string()];
    }
    let mut lines = Vec::new();
    let mut current = String::new();
    for word in s.split_whitespace() {
        if current.is_empty() {
            current.push_str(word);
        } else if current.len() + 1 + word.len() <= width {
            current.push(' ');
            current.push_str(word);
        } else {
            lines.push(current.clone());
            current = word.to_string();
        }
    }
    if !current.is_empty() {
        lines.push(current);
    }
    lines
}
```

**Step 4: Run to confirm pass**

```
cargo test --lib tui::ui::tests
```
Expected: `test result: ok. 3 passed`

**Step 5: Commit**

```bash
git add src/tui/ui.rs
git commit -m "feat(tui): add ScreenHelp struct and screen_help() content function"
```

---

## Task 3: Intercept `?` and `Esc` in `handle_key()`

**Files:**
- Modify: `src/tui/mod.rs:1537` (`handle_key` — insert after the global quit guard, before `match app.screen`)
- Test: `src/tui/mod.rs` tests block

**Step 1: Write the failing tests**

Add to the `#[cfg(test)] mod tests` block in `src/tui/mod.rs`:

```rust
    #[test]
    fn question_mark_opens_help_overlay() {
        let mut app = make_app();
        handle_key(&mut app, KeyCode::Char('?'), KeyModifiers::NONE);
        assert!(app.show_help);
    }

    #[test]
    fn esc_closes_overlay_without_navigating() {
        let mut app = make_app();
        app.screen = Screen::SelectCollectors;
        app.show_help = true;
        handle_key(&mut app, KeyCode::Esc, KeyModifiers::NONE);
        assert!(!app.show_help);
        assert_eq!(app.screen, Screen::SelectCollectors);
    }

    #[test]
    fn other_keys_swallowed_while_overlay_open() {
        let mut app = make_app();
        app.screen = Screen::Welcome;
        app.show_help = true;
        handle_key(&mut app, KeyCode::Enter, KeyModifiers::NONE);
        assert_eq!(app.screen, Screen::Welcome);
        assert!(app.show_help);
    }
```

Add `use crossterm::event::KeyModifiers;` to the imports inside the test module.

**Step 2: Run to confirm failure**

```
cargo test --lib tui::tests 2>&1 | tail -20
```
Expected: 3 new failures

**Step 3: Add the intercept to `handle_key()`**

In `src/tui/mod.rs`, at line 1540 (after the `Action::Quit` guard, before `match app.screen`):

```rust
    // Help overlay intercept — universal across all screens
    if key == KeyCode::Char('?') {
        app.show_help = true;
        return Action::Continue;
    }
    if app.show_help {
        if key == KeyCode::Esc {
            app.show_help = false;
        }
        return Action::Continue; // swallow all keys while overlay is open
    }
```

**Step 4: Run to confirm pass**

```
cargo test --lib tui::tests
```
Expected: `test result: ok. 5 passed`

**Step 5: Commit**

```bash
git add src/tui/mod.rs
git commit -m "feat(tui): intercept ? to open help overlay and Esc to close it"
```

---

## Task 4: Add `centered_rect()` and `draw_help_overlay()` to `ui.rs`

**Files:**
- Modify: `src/tui/ui.rs` (add `centered_rect` near other layout helpers; add `draw_help_overlay` just before `draw_error_banner`)
- Test: `src/tui/ui.rs` tests block

**Step 1: Write the failing tests**

Add to the `#[cfg(test)] mod tests` block in `src/tui/ui.rs`:

```rust
    use ratatui::layout::Rect;

    #[test]
    fn centered_rect_is_centered_and_bounded() {
        let outer = Rect { x: 0, y: 0, width: 100, height: 40 };
        let inner = centered_rect(80, 80, 90, 28, outer);
        assert!(inner.width <= 90);
        assert!(inner.height <= 28);
        assert_eq!(inner.x, (outer.width - inner.width) / 2);
    }

    #[test]
    fn centered_rect_does_not_exceed_outer() {
        let outer = Rect { x: 5, y: 5, width: 40, height: 15 };
        let inner = centered_rect(80, 80, 90, 28, outer);
        assert!(inner.x >= outer.x);
        assert!(inner.y >= outer.y);
        assert!(inner.x + inner.width <= outer.x + outer.width);
        assert!(inner.y + inner.height <= outer.y + outer.height);
    }
```

**Step 2: Run to confirm failure**

```
cargo test --lib tui::ui::tests 2>&1 | tail -20
```
Expected: `error: cannot find function 'centered_rect'`

**Step 3: Add `centered_rect()` helper**

Add in `src/tui/ui.rs` in the "Frame components" section (around line 285):

```rust
fn centered_rect(percent_x: u16, percent_y: u16, max_w: u16, max_h: u16, r: Rect) -> Rect {
    let w = (r.width * percent_x / 100).min(max_w);
    let h = (r.height * percent_y / 100).min(max_h);
    let x = r.x + (r.width.saturating_sub(w)) / 2;
    let y = r.y + (r.height.saturating_sub(h)) / 2;
    Rect { x, y, width: w, height: h }
}
```

**Step 4: Run geometry tests, then add the overlay renderer**

```
cargo test --lib tui::ui::tests::centered_rect
```
Expected: `ok. 2 passed`

Add `draw_help_overlay()` just before `draw_error_banner()` in `src/tui/ui.rs`:

```rust
pub fn draw_help_overlay(f: &mut Frame, app: &App) {
    let area = f.area();
    let modal = centered_rect(82, 80, 92, 30, area);

    f.render_widget(Clear, modal);

    let block = Block::bordered()
        .border_type(BorderType::Thick)
        .border_style(Style::default().fg(CYAN))
        .style(Style::default().bg(BG_ELEVATED))
        .title(Span::styled(
            " ? Help ",
            Style::default().fg(CYAN).add_modifier(Modifier::BOLD),
        ))
        .title_bottom(Span::styled(
            " Esc  Close ",
            Style::default().fg(TEXT_DIM),
        ));

    let inner = block.inner(modal);
    f.render_widget(block, modal);

    let help = screen_help(&app.screen);
    let hints = get_hints(&app.screen);
    let wrap_width = (inner.width as usize).saturating_sub(2).max(20);

    let mut lines: Vec<Line> = Vec::new();

    // Title
    lines.push(Line::from(Span::styled(
        help.title,
        Style::default().fg(CYAN).add_modifier(Modifier::BOLD),
    )));
    lines.push(Line::raw(""));

    // Description
    for desc_line in wrap_text(help.description, wrap_width) {
        lines.push(Line::from(Span::styled(desc_line, Style::default().fg(TEXT_NORMAL))));
    }
    lines.push(Line::raw(""));

    // Shortcut section
    let sep: String = "─".repeat(inner.width.saturating_sub(2) as usize);
    lines.push(Line::from(Span::styled(sep.clone(), Style::default().fg(BORDER_SUBTLE))));
    lines.push(Line::from(Span::styled(
        "Keyboard Shortcuts",
        Style::default().fg(TEXT_DIM).add_modifier(Modifier::BOLD),
    )));
    lines.push(Line::raw(""));

    if hints.is_empty() {
        lines.push(Line::from(Span::styled(
            "  No shortcuts on this screen.",
            Style::default().fg(TEXT_DIM),
        )));
    } else {
        for (key, desc) in &hints {
            lines.push(Line::from(vec![
                Span::styled(
                    format!("  {:>6} ", key),
                    Style::default().fg(TEXT_BRIGHT).add_modifier(Modifier::BOLD),
                ),
                Span::raw("  "),
                Span::styled(*desc, Style::default().fg(TEXT_NORMAL)),
            ]));
        }
    }

    // Data collected section
    lines.push(Line::raw(""));
    lines.push(Line::from(Span::styled(sep, Style::default().fg(BORDER_SUBTLE))));
    lines.push(Line::from(Span::styled(
        "Data Collected / API Calls",
        Style::default().fg(TEXT_DIM).add_modifier(Modifier::BOLD),
    )));
    lines.push(Line::raw(""));
    for dc_line in wrap_text(help.data_collected, wrap_width) {
        lines.push(Line::from(Span::styled(dc_line, Style::default().fg(TEXT_DIM))));
    }

    f.render_widget(
        Paragraph::new(Text::from(lines)).style(Style::default().bg(BG_ELEVATED)),
        inner,
    );
}
```

**Note:** Before implementing, verify which color constants exist:
```bash
grep -n "^const \|^pub const " src/tui/ui.rs | grep -i "bg\|text\|border\|cyan"
```
Use only constants already defined in the file.

**Step 5: Run to confirm build passes**

```
cargo build 2>&1 | head -30
```

**Step 6: Commit**

```bash
git add src/tui/ui.rs
git commit -m "feat(tui/ui): add centered_rect and draw_help_overlay renderer"
```

---

## Task 5: Integrate `draw_help_overlay()` into `draw()`

**Files:**
- Modify: `src/tui/ui.rs:279–283` (add call after error_msg overlay, before closing brace of `draw()`)
- Test: `src/tui/ui.rs` tests block (TestBackend render test)

**Step 1: Write the failing render test**

Add to the `#[cfg(test)] mod tests` block in `src/tui/ui.rs`:

```rust
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;
    use super::super::App;

    fn make_app() -> App {
        App::new(vec!["default".to_string()])
    }

    #[test]
    fn draw_renders_help_overlay_when_show_help_true() {
        let mut app = make_app();
        app.show_help = true;
        let backend = TestBackend::new(120, 40);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|f| draw(f, &app)).unwrap();
        let rendered: String = terminal
            .backend()
            .buffer()
            .clone()
            .content()
            .iter()
            .map(|c| c.symbol())
            .collect();
        assert!(rendered.contains("Help") || rendered.contains("Esc"),
            "help overlay not found in render");
    }

    #[test]
    fn draw_does_not_render_overlay_when_show_help_false() {
        let mut app = make_app();
        app.show_help = false;
        let backend = TestBackend::new(120, 40);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|f| draw(f, &app)).unwrap();
        let rendered: String = terminal
            .backend()
            .buffer()
            .clone()
            .content()
            .iter()
            .map(|c| c.symbol())
            .collect();
        assert!(!rendered.contains("Keyboard Shortcuts"));
    }
```

**Step 2: Run to confirm failure**

```
cargo test --lib "draw_renders_help" 2>&1 | tail -20
```

**Step 3: Add the call in `draw()`**

In `src/tui/ui.rs`, change lines 279–283:

```rust
    // Error banner overlays footer
    if let Some(ref msg) = app.error_msg {
        draw_error_banner(f, area, msg);
    }

    // Help overlay — drawn last, appears above all other content
    if app.show_help {
        draw_help_overlay(f, app);
    }
}
```

**Step 4: Run full test suite**

```
cargo test --lib
```
Expected: `test result: ok` with no failures

**Step 5: Commit**

```bash
git add src/tui/ui.rs
git commit -m "feat(tui/ui): integrate help overlay into draw() lifecycle"
```

---

## Task 6: Append `?  Help` hint to every screen's footer

**Files:**
- Modify: `src/tui/ui.rs:410` (`draw_footer` function)

**Step 1: Read `draw_footer` to understand its structure before modifying**

```bash
grep -n "draw_footer\|all_hints\|hints" src/tui/ui.rs | head -20
```

**Step 2: Prepend `all_hints` collection**

In `draw_footer`, change the signature body to collect hints + the universal shortcut:

```rust
fn draw_footer(f: &mut Frame, area: Rect, hints: &[(&str, &str)]) {
    let mut all_hints: Vec<(&str, &str)> = hints.to_vec();
    if !all_hints.is_empty() {
        all_hints.push(("?", "Help"));
    }
    // replace all remaining uses of `hints` in this function with `&all_hints`
```

This ensures Preparing/Running screens (which pass an empty slice) don't show the `?` hint in an otherwise empty footer.

**Step 3: Build and visually verify**

```bash
cargo build && cargo run
```

Navigate to any screen — verify `?  Help` appears in the footer. Verify Preparing/Running screens show no footer hint.

**Step 4: Commit**

```bash
git add src/tui/ui.rs
git commit -m "feat(tui/ui): append ? Help hint to every screen footer"
```

---

## Verification

**Unit tests (no credentials needed):**
```bash
cargo test --lib
```

**Manual smoke test:**
```bash
cargo run
# On any screen: press ? → overlay appears with screen title, description, shortcuts, data-collected
# Press Esc → overlay closes, screen is unchanged
# Navigate screens and verify overlay content changes per screen
# Verify footer shows "?  Help" on all screens except Preparing/Running
```

**Edge cases to verify manually:**
- `?` on Welcome (Esc normally quits — overlay must intercept first)
- `?` on Running (no shortcuts active — overlay still appears, shows "No shortcuts")
- `?` on Results (Esc normally exits — overlay must close instead of quitting)
