# Provider Selection List+Detail Redesign Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the Provider Selection screen's fixed-height, manually-positioned card stack (which silently overflows once enough providers are compiled in) with an auto-scrolling `List` + detail-panel layout, backed by a single feature-gated `CloudProvider::available()` source of truth instead of two hand-duplicated lists. Apply the same shared rendering component to the Feature Selection screen, which uses the identical manual-card pattern today.

**Architecture:** Add `CloudProvider::available()` / `.display_name()` / `.description()` to `src/providers/mod.rs` as the single feature-gated provider list. Add a shared `draw_list_with_detail` widget to `src/tui/ui/widgets.rs` — a 30/70 horizontal split with a `List`+`ListState` on the left (auto-scrolling, `render_stateful_widget`, same idiom as `collectors.rs`'s Categories/Items panels) and a bordered detail pane on the right showing the highlighted item's name and description. Rewire `draw_provider_selection` (`account_screens.rs`) and `handle_provider_selection` (`events.rs`) to consume `CloudProvider::available()`; rewire `draw_feature_selection` (`setup.rs`) to use the same shared widget with its existing fixed 3-item list.

**Tech Stack:** Rust, ratatui, crossterm — all changes within existing modules; no new files, no new `Screen` variants, no new `App` fields.

Full design rationale: [`docs/plans/2026-07-22-provider-selection-list-redesign-spec.md`](2026-07-22-provider-selection-list-redesign-spec.md).

## Global Constraints

- **No tests in this plan.** Per project convention, implement production code only — no unit/integration test steps, no routine `cargo test` runs.
- **Tree must compile on every Write.** A PostToolUse hook runs `cargo check` after every file write. Within a task, make edits in an order that never leaves the tree in a non-compiling state (e.g. add `CloudProvider::available()` before any call site references it).
- **Trunk-based.** Work directly on `main`. Do not create feature branches.
- **Clean clippy + fmt before each commit.** Per `CLAUDE.md`: `cargo clippy -- -D warnings` and `cargo fmt` must be clean before committing. Run both as part of each task's final steps.
- **No behavior change to app state.** Do not touch `src/tui/state.rs` (`Screen` enum) or add/rename fields on `App` — `selected_provider`, `provider_cursor`, `selected_feature` stay as they are. This is a rendering + data-source change only.
- **Reference patterns to mirror (do not reinvent):**
  - Auto-scrolling `List` + `ListState` idiom: `src/tui/ui/collectors.rs:184-194` (Categories panel) and `:271-281` (Items panel).
  - 30/70 two-panel horizontal split: `src/tui/ui/collectors.rs:134`.
  - Existing color/style constants: `src/tui/ui/theme.rs`.

---

## File Structure

**Modified files only — no new files:**
- `src/providers/mod.rs` — add `CloudProvider::available()`, `.display_name()`, `.description()`.
- `src/tui/ui/widgets.rs` — add `draw_list_with_detail`.
- `src/tui/ui/account_screens.rs` — rewrite `draw_provider_selection`.
- `src/tui/events.rs` — rewrite `handle_provider_selection`.
- `src/tui/ui/setup.rs` — rewrite `draw_feature_selection`.

---

## Self-Review Notes (verified after writing, before handoff)

- Spec coverage: spec §1 (single source of truth) → Task 1 + Task 3; spec §2 (shared widget) → Task 2; spec §3 (screen integration) → Tasks 3–4; spec §4 (event handling) → Task 3. Spec's non-goals (no responsive breakpoint, no `menu_for()` panic fix, no new provider, no Feature Selection nav change) are respected — no task touches any of them.
- No placeholders: every code step below is complete, compilable code (verified against the actual current contents of each file, read prior to writing this plan).
- Type/method consistency: `CloudProvider::available() -> Vec<CloudProvider>`, `.display_name() -> &'static str`, `.description() -> &'static str` (Task 1) are consumed with these exact signatures in Task 3 and referenced (for the pattern, not directly called) in Task 4. `draw_list_with_detail(f, area, list_title: &str, items: &[(String, String)], selected: usize)` (Task 2) is called identically in Task 3 and Task 4.
- Stub-first discipline: Task 1 (data source) lands before Task 3 (its first consumer); Task 2 (widget) lands before Task 3 and Task 4 (its consumers). Each task is independently compilable when applied in order.

---

### Task 1: `CloudProvider::available()` / `.display_name()` / `.description()`

**Files:**
- Modify: `src/providers/mod.rs`

**Interfaces:**
- Produces: `CloudProvider::available() -> Vec<CloudProvider>`, `CloudProvider::display_name(&self) -> &'static str`, `CloudProvider::description(&self) -> &'static str` — consumed by Task 3 (Provider Selection).

- [ ] **Step 1: Add the new `impl CloudProvider` block**

Insert immediately after the existing `impl fmt::Display for CloudProvider { ... }` block (ends at line 55 today, right before the `// --- ProviderFactory ---` section comment):

```rust
impl CloudProvider {
    /// Every provider compiled into this build, in canonical UI order.
    /// Single source of truth for the Provider Selection screen — both
    /// the renderer and the key handler call this instead of maintaining
    /// their own copies.
    pub fn available() -> Vec<CloudProvider> {
        let mut v = vec![CloudProvider::Aws];
        #[cfg(feature = "azure")]
        v.push(CloudProvider::Azure);
        #[cfg(feature = "gcp")]
        v.push(CloudProvider::Gcp);
        #[cfg(feature = "tenable")]
        v.push(CloudProvider::Tenable);
        #[cfg(feature = "okta")]
        v.push(CloudProvider::Okta);
        #[cfg(feature = "jira")]
        v.push(CloudProvider::Jira);
        #[cfg(feature = "elastic")]
        v.push(CloudProvider::Elastic);
        v
    }

    /// Long-form display name for the Provider Selection UI, e.g.
    /// "Amazon Web Services (AWS)". Distinct from `Display`, which yields
    /// the short form ("AWS") used in filenames/report metadata.
    pub fn display_name(&self) -> &'static str {
        match self {
            CloudProvider::Aws => "Amazon Web Services (AWS)",
            CloudProvider::Azure => "Microsoft Azure",
            CloudProvider::Gcp => "Google Cloud Platform (GCP)",
            CloudProvider::Tenable => "Tenable",
            CloudProvider::Okta => "Okta",
            CloudProvider::Jira => "Jira",
            CloudProvider::Elastic => "Elastic Security",
        }
    }

    /// One-line description shown in the Provider Selection detail panel.
    pub fn description(&self) -> &'static str {
        match self {
            CloudProvider::Aws => {
                "Run 100+ compliance evidence collectors (CloudTrail, S3, IAM, RDS, …)"
            }
            CloudProvider::Azure => "Collect compliance evidence from Azure resources",
            CloudProvider::Gcp => "Collect compliance evidence from GCP resources",
            CloudProvider::Tenable => {
                "Export vulnerability findings from Tenable.io or Tenable.sc"
            }
            CloudProvider::Okta => {
                "Collect users, groups, apps, policies, MFA factors, and system log events"
            }
            CloudProvider::Jira => {
                "Collect projects and issues from Jira Cloud or Jira Server"
            }
            CloudProvider::Elastic => {
                "Collect detection rules, exception items, alerts, and cases from Elastic SIEM"
            }
        }
    }
}
```

- [ ] **Step 2: Compile check**

Run: `cargo check --workspace 2>&1 | tail -20`
Expected: clean compile (this block is purely additive; nothing calls the new methods yet, so no "unused" errors — inherent methods on a public type don't trigger dead-code warnings).

- [ ] **Step 3: Commit**

```bash
git add src/providers/mod.rs
git commit -m "feat(providers): add CloudProvider::available/display_name/description"
```

---

### Task 2: Shared `draw_list_with_detail` widget

**Files:**
- Modify: `src/tui/ui/widgets.rs`

**Interfaces:**
- Consumes: theme constants from `super` (`src/tui/ui/theme.rs` via `src/tui/ui/mod.rs`).
- Produces: `pub(super) fn draw_list_with_detail(f: &mut Frame, area: Rect, list_title: &str, items: &[(String, String)], selected: usize)` — consumed by Task 3 and Task 4.

- [ ] **Step 1: Update imports at the top of `widgets.rs`**

Replace the current import block:

```rust
use ratatui::layout::{Alignment, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, Clear, Padding, Paragraph};
use ratatui::Frame;

use super::{BORDER_SUBTLE, CYAN, RED, RED_BG, TEXT_BRIGHT, TEXT_DIM};
```

with:

```rust
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
```

- [ ] **Step 2: Add `draw_list_with_detail` at the end of `widgets.rs`**

```rust
/// Auto-scrolling list (left, 30% width) + detail panel (right, 70% width)
/// for single-column selection screens with a description per item.
/// `items` is `(name, description)` pairs; `selected` indexes into `items`
/// and drives both the list highlight and the detail panel content.
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
```

- [ ] **Step 3: Compile check**

Run: `cargo check --workspace 2>&1 | tail -20`
Expected: clean compile, possibly a "function `draw_list_with_detail` is never used" warning — expected until Task 3 adds the first call site; not an error.

- [ ] **Step 4: Commit**

```bash
git add src/tui/ui/widgets.rs
git commit -m "feat(tui/ui): add draw_list_with_detail shared widget"
```

---

### Task 3: Rewrite Provider Selection (render + event handling)

**Files:**
- Modify: `src/tui/ui/account_screens.rs`
- Modify: `src/tui/events.rs`

**Interfaces:**
- Consumes: `CloudProvider::available()` / `.display_name()` / `.description()` (Task 1), `draw_list_with_detail` (Task 2).

- [ ] **Step 1: Update imports in `account_screens.rs`**

Replace:

```rust
use super::widgets::{content_inset, draw_text_field};
```

with:

```rust
use super::widgets::{content_inset, draw_list_with_detail, draw_text_field};
```

- [ ] **Step 2: Replace `draw_provider_selection`**

Replace the entire function body (currently `src/tui/ui/account_screens.rs:17-151`, from `pub(super) fn draw_provider_selection` through its closing `}`) with:

```rust
pub(super) fn draw_provider_selection(f: &mut Frame, area: Rect, app: &App) {
    use crate::providers::CloudProvider;

    let providers = CloudProvider::available();
    let items: Vec<(String, String)> = providers
        .iter()
        .map(|p| (p.display_name().to_string(), p.description().to_string()))
        .collect();
    let selected = providers
        .iter()
        .position(|p| *p == app.selected_provider)
        .unwrap_or(0);

    let chunks = Layout::vertical([
        Constraint::Length(1), // title
        Constraint::Length(1), // subtitle
        Constraint::Length(1), // blank
        Constraint::Fill(1),   // list + detail panels
    ])
    .split(area);

    f.render_widget(
        Paragraph::new(Span::styled(
            "Select a cloud provider:",
            Style::default()
                .fg(TEXT_BRIGHT)
                .add_modifier(Modifier::BOLD),
        ))
        .alignment(Alignment::Center),
        chunks[0],
    );
    f.render_widget(
        Paragraph::new(Span::styled(
            "Use ↑↓ to select a provider, then press Enter",
            Style::default().fg(TEXT_DIM),
        ))
        .alignment(Alignment::Center),
        chunks[1],
    );

    draw_list_with_detail(f, chunks[3], "Providers", &items, selected);
}
```

- [ ] **Step 3: Replace `handle_provider_selection` in `events.rs`**

Replace the entire function (currently `src/tui/events.rs:855-898`, from `fn handle_provider_selection` through its closing `}`, which includes the sync-drift warning comment in its body) with:

```rust
fn handle_provider_selection(app: &mut App, key: KeyCode) {
    use crate::providers::CloudProvider;
    let providers = CloudProvider::available();
    match key {
        KeyCode::Up => {
            if app.provider_cursor > 0 {
                app.provider_cursor -= 1;
                app.selected_provider = providers[app.provider_cursor];
            }
        }
        KeyCode::Down => {
            if app.provider_cursor + 1 < providers.len() {
                app.provider_cursor += 1;
                app.selected_provider = providers[app.provider_cursor];
            }
        }
        KeyCode::Enter | KeyCode::Char(' ') => {
            if app.validate_current() {
                app.load_menu_for_current_provider();
                app.next_screen();
            }
        }
        KeyCode::Esc => app.prev_screen(),
        _ => {}
    }
}
```

- [ ] **Step 4: Compile check and clean up unused imports**

Run: `cargo check --workspace 2>&1 | tail -30`

`account_screens.rs` has other functions in the same file (e.g. `draw_select_account`) — check whether any of the theme constants imported at the top (`AMBER, BG_ELEVATED, BG_MAIN, BG_SELECTED, BORDER_SUBTLE, CYAN, CYAN_DIM, GREEN, TEXT_BRIGHT, TEXT_DIM, TEXT_NORMAL`) are now unused because they were only referenced by the old card-drawing code. Remove any the compiler flags as unused (via `cargo check` warnings — read the actual warning list rather than guessing).

Also check `ratatui::widgets::{Block, BorderType, ListState}` imports at the top of `account_screens.rs` — the old `draw_provider_selection` used `Block`/`BorderType` directly; if `draw_select_account` (the other function in this file) no longer needs them, remove.

- [ ] **Step 5: Run clippy and fmt**

```bash
cargo fmt
cargo clippy -- -D warnings 2>&1 | tail -30
```

Fix anything clippy flags in the two changed functions before proceeding.

- [ ] **Step 6: Commit**

```bash
git add src/tui/ui/account_screens.rs src/tui/events.rs
git commit -m "feat(tui): rewrite Provider Selection as auto-scrolling list + detail panel"
```

---

### Task 4: Rewrite Feature Selection to use the shared widget

**Files:**
- Modify: `src/tui/ui/setup.rs`

**Interfaces:**
- Consumes: `draw_list_with_detail` (Task 2).

- [ ] **Step 1: Update imports in `setup.rs`**

Replace:

```rust
use super::widgets::content_inset;
```

with:

```rust
use super::widgets::{content_inset, draw_list_with_detail};
```

- [ ] **Step 2: Replace `draw_feature_selection`**

Replace the entire function body (currently `src/tui/ui/setup.rs:102-199`, from `pub(super) fn draw_feature_selection` through its closing `}`) with:

```rust
pub(super) fn draw_feature_selection(f: &mut Frame, area: Rect, app: &App) {
    let chunks = Layout::vertical([
        Constraint::Length(1), // title
        Constraint::Length(1), // subtitle
        Constraint::Length(1), // blank
        Constraint::Fill(1),   // list + detail panels
    ])
    .split(area);

    f.render_widget(
        Paragraph::new(Span::styled(
            "What would you like to do?",
            Style::default()
                .fg(TEXT_BRIGHT)
                .add_modifier(Modifier::BOLD),
        ))
        .alignment(Alignment::Center),
        chunks[0],
    );
    f.render_widget(
        Paragraph::new(Span::styled(
            "Use ↑↓ to select a feature, then press Enter",
            Style::default().fg(TEXT_DIM),
        ))
        .alignment(Alignment::Center),
        chunks[1],
    );

    let options = [
        (
            Feature::Collectors,
            "Collectors",
            "Run 100+ compliance evidence collectors (CloudTrail, S3, IAM, RDS, …)",
        ),
        (
            Feature::Inventory,
            "Inventory",
            "Build a unified asset-inventory CSV across selected AWS resource types",
        ),
        (
            Feature::Poam,
            "POAM",
            "Reconcile Inspector2 ECR findings into FedRAMP-POAM.xlsx (add new, close resolved)",
        ),
    ];

    let items: Vec<(String, String)> = options
        .iter()
        .map(|(_, name, desc)| (name.to_string(), desc.to_string()))
        .collect();
    let selected = options
        .iter()
        .position(|(feature, _, _)| *feature == app.selected_feature)
        .unwrap_or(0);

    draw_list_with_detail(f, chunks[3], "Features", &items, selected);
}
```

- [ ] **Step 3: Compile check and clean up unused imports**

Run: `cargo check --workspace 2>&1 | tail -30`

`setup.rs` is a large multi-screen file — check whether `AMBER, BG_ELEVATED, BG_MAIN, BG_SELECTED, BORDER_SUBTLE, CYAN, CYAN_DIM, GREEN, LOGO, LOGO_COLORS, TEXT_BRIGHT, TEXT_DIM, TEXT_NORMAL` and `Block, BorderType` are still used by its other screen-drawing functions (e.g. `draw_welcome`, `draw_dates`, `draw_tenable_endpoint`) before removing any. Only remove what the compiler actually flags as unused.

- [ ] **Step 4: Run clippy and fmt**

```bash
cargo fmt
cargo clippy -- -D warnings 2>&1 | tail -30
```

- [ ] **Step 5: Commit**

```bash
git add src/tui/ui/setup.rs
git commit -m "feat(tui): rewrite Feature Selection to use draw_list_with_detail"
```

---

### Task 5: Manual smoke test

**Files:** none (verification only)

- [ ] **Step 1: Build default features**

```bash
cargo build --release 2>&1 | grep "^error"
```
Expected: no errors.

- [ ] **Step 2: Walk Feature Selection → Provider Selection (default features: tenable, okta, jira, elastic)**

```bash
./target/release/grabber
```

1. On Welcome, press Enter.
2. On Feature Selection: confirm the new list+detail layout renders (left list with "Collectors"/"Inventory"/"POAM", right panel showing the highlighted option's description). Confirm ↑↓ moves the highlight and updates the detail panel; Enter selects.
3. Select **Collectors** → lands on Provider Selection. Confirm the list shows AWS, Tenable, Okta, Jira, Elastic Security (5 entries, no Azure/GCP since those features aren't enabled). Confirm the right panel shows AWS's description by default.
4. Press ↓ repeatedly through all 5 providers — confirm the highlight and detail panel update correctly and the list never overflows the frame.
5. Press Esc from Provider Selection → returns to Feature Selection. Press Esc again → returns to Welcome.

- [ ] **Step 3: Build with `azure,gcp` to verify scrolling behavior with 7 providers**

```bash
cargo build --release --features azure,gcp 2>&1 | grep "^error"
./target/release/grabber
```

1. Navigate to Provider Selection (Feature Selection → Collectors).
2. Confirm all 7 providers are listed (AWS, Azure, GCP, Tenable, Okta, Jira, Elastic Security) with no visual overflow, regardless of terminal height — resize the terminal smaller if needed to confirm the list scrolls (via ratatui's built-in `ListState` viewport tracking) rather than clipping or crashing.
3. Confirm arrow-key navigation stays in sync with the highlighted row at every position, including the last item (previously a risk called out in the spec — `handle_provider_selection`'s cursor list must match what's rendered).

- [ ] **Step 4: Confirm footer hints unchanged**

On both Feature Selection and Provider Selection, confirm the footer still reads `↑↓ Navigate  ⏎ Select  Esc Back` (unchanged — `frame.rs` was not modified by this plan).

- [ ] **Step 5: Fix and commit any issues found**

If the smoke test surfaces a bug, fix it and commit:

```bash
git add -p
git commit -m "fix(tui): smoke-test fixups for provider/feature selection redesign"
```

If no issues, no commit needed for this task.
