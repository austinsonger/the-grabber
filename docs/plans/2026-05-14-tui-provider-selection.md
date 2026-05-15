# TUI Provider Selection Screen Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Insert a `ProviderSelection` screen between `FeatureSelection` and `SelectAccount` in the `Feature::Collectors` wizard flow, filter the collector list to only show collectors for the chosen provider, and skip the Accounts screen entirely when Tenable is selected (auto-selecting all configured Tenable accounts instead).

**Architecture:** Add `Screen::ProviderSelection` to the state enum and `selected_provider: CloudProvider` / `provider_cursor: usize` to `App`. Thread the selected provider through navigation (`next_screen` / `prev_screen`), event handling, collector visibility filtering, account list filtering, step indicators, and UI rendering. The Tenable path diverges at `ProviderSelection` → `SetDates` (skipping `SelectAccount`), with accounts auto-populated from the TOML config. All other providers continue through `SelectAccount` → `SetDates`.

**Tech Stack:** Rust, ratatui, crossterm — all changes within existing modules; no new files.

---

## Key file map (read before editing)

| File | Role |
|------|------|
| `src/tui/state.rs:75-97` | `Screen` enum — add `ProviderSelection` variant |
| `src/tui/app/mod.rs:21-113` | `App` struct — add two new fields |
| `src/tui/app/nav.rs:8-93` | `next_screen()` / `prev_screen()` / `reset()` |
| `src/tui/app/methods.rs` | `search_matches_item`, `validate_current`, new helpers |
| `src/tui/events.rs:52-78` | `handle_key` dispatch + new `handle_provider_selection` |
| `src/tui/events.rs:111-161` | `handle_select_account` — use filtered index list |
| `src/tui/ui/mod.rs:36-134` | `draw()` dispatch + step constant selection |
| `src/tui/ui/setup.rs:99-199` | Template for card-style rendering (reference only) |
| `src/tui/ui/account_screens.rs` | Add `draw_provider_selection`; update `draw_select_account` |
| `src/tui/ui/frame.rs:18-130` | Step constants + `screen_to_step` signature |

---

## Task 1: Add `Screen::ProviderSelection` variant

**Files:**
- Modify: `src/tui/state.rs:75-97`

**Step 1: Write the failing test**

Add inside the `#[cfg(test)]` block in `src/tui/app/mod.rs`:

```rust
#[test]
fn provider_selection_screen_exists() {
    let s = crate::tui::Screen::ProviderSelection;
    assert!(matches!(s, crate::tui::Screen::ProviderSelection));
}
```

**Step 2: Run test to verify it fails**

```
cargo test provider_selection_screen_exists 2>&1 | tail -10
```

Expected: FAIL — `no variant ProviderSelection for enum Screen`

**Step 3: Add the variant to `src/tui/state.rs`**

Insert `ProviderSelection` after `FeatureSelection` on line 80:

```rust
#[derive(Debug, Clone, PartialEq)]
pub enum Screen {
    Welcome,
    FeatureSelection,
    ProviderSelection, // shown after Feature::Collectors is chosen; before account selection
    SelectAccount,
    SelectProfile,
    SelectRegion,
    SetDates,
    Inventory,
    PoamAccount,
    PoamRegion,
    PoamYear,
    PoamMonth,
    SelectCollectors,
    SetOptions,
    Confirm,
    Preparing,
    Running,
    Results,
}
```

**Step 4: Run test to verify it passes**

```
cargo test provider_selection_screen_exists 2>&1 | tail -5
```

Expected: PASS (plus exhaustive-match compile errors in other files — fixed in later tasks)

**Step 5: Commit**

```bash
git add src/tui/state.rs
git commit -m "feat(tui): add Screen::ProviderSelection variant"
```

---

## Task 2: Add `selected_provider` and `provider_cursor` to `App`

**Files:**
- Modify: `src/tui/app/mod.rs` (struct definition and `App::new()`)
- Modify: `src/tui/app/nav.rs` (`reset()`)

**Step 1: Write the failing test**

```rust
#[test]
fn app_has_provider_fields() {
    let app = make_app();
    assert!(matches!(app.selected_provider, crate::providers::CloudProvider::Aws));
    assert_eq!(app.provider_cursor, 0);
}
```

**Step 2: Run test to verify it fails**

```
cargo test app_has_provider_fields 2>&1 | tail -5
```

Expected: FAIL — `no field selected_provider`

**Step 3: Add two fields to `App` struct in `src/tui/app/mod.rs`**

After `pub selected_feature: Feature,` (line 95), insert:

```rust
// Provider selection (Collectors flow only)
pub selected_provider: CloudProvider, // which provider was chosen on ProviderSelection screen
pub provider_cursor: usize,           // cursor position on ProviderSelection screen
```

**Step 4: Initialize in `App::new()`**

After `selected_feature: Feature::Collectors,` in the `Self { … }` block, add:

```rust
selected_provider: CloudProvider::Aws,
provider_cursor: 0,
```

**Step 5: Reset in `App::reset()` in `src/tui/app/nav.rs`**

After `self.selected_feature = Feature::Collectors;` in `reset()`, add:

```rust
self.selected_provider = CloudProvider::Aws;
self.provider_cursor = 0;
```

**Step 6: Run test to verify it passes**

```
cargo test app_has_provider_fields 2>&1 | tail -5
```

**Step 7: Commit**

```bash
git add src/tui/app/mod.rs src/tui/app/nav.rs
git commit -m "feat(tui): add selected_provider and provider_cursor to App"
```

---

## Task 3: Update navigation — `next_screen` and `prev_screen`

**Files:**
- Modify: `src/tui/app/nav.rs:8-93`
- Add method to: `src/tui/app/methods.rs`

**Step 1: Write failing navigation tests**

```rust
#[test]
fn feature_collectors_goes_to_provider_selection() {
    let mut app = make_app();
    app.screen = crate::tui::Screen::FeatureSelection;
    app.selected_feature = Feature::Collectors;
    app.next_screen();
    assert_eq!(app.screen, crate::tui::Screen::ProviderSelection);
}

#[test]
fn provider_selection_prev_goes_to_feature_selection() {
    let mut app = make_app();
    app.screen = crate::tui::Screen::ProviderSelection;
    app.prev_screen();
    assert_eq!(app.screen, crate::tui::Screen::FeatureSelection);
}
```

**Step 2: Run tests to verify they fail**

```
cargo test feature_collectors_goes_to_provider_selection 2>&1 | tail -5
```

**Step 3: Update `next_screen()` in `src/tui/app/nav.rs`**

Replace the `Screen::FeatureSelection` match arm and add the new `Screen::ProviderSelection` arm:

```rust
Screen::FeatureSelection => match self.selected_feature {
    Feature::Poam => {
        if self.has_accounts() {
            Screen::PoamAccount
        } else {
            Screen::PoamRegion
        }
    }
    Feature::Collectors => Screen::ProviderSelection, // CHANGED: always go to provider first
    _ => {
        // Inventory
        if self.has_accounts() {
            Screen::SelectAccount
        } else {
            Screen::SelectProfile
        }
    }
},
// NEW arm — inserted after FeatureSelection
Screen::ProviderSelection => {
    if self.selected_provider == CloudProvider::Tenable {
        // Tenable: skip account picker, auto-select all configured Tenable accounts
        self.auto_select_provider_accounts();
        Screen::SetDates
    } else if self.has_accounts() {
        Screen::SelectAccount
    } else {
        Screen::SelectProfile
    }
},
```

**Step 4: Update `prev_screen()` in `src/tui/app/nav.rs`**

Replace the `Screen::SelectAccount` arm and update `Screen::SelectProfile` / `Screen::SetDates`:

```rust
Screen::ProviderSelection => Screen::FeatureSelection, // NEW
Screen::SelectAccount => Screen::ProviderSelection,    // CHANGED from FeatureSelection
Screen::SelectProfile => {
    if self.has_accounts() {
        Screen::ProviderSelection  // CHANGED: was SelectAccount
    } else {
        Screen::FeatureSelection
    }
},
Screen::SetDates => {
    if self.selected_provider == CloudProvider::Tenable {
        Screen::ProviderSelection  // Tenable skips account screen
    } else if self.has_accounts() {
        Screen::SelectAccount
    } else {
        Screen::SelectRegion
    }
},
```

**Step 5: Add `auto_select_provider_accounts()` to `src/tui/app/methods.rs`**

```rust
/// Auto-select all TOML accounts that match `selected_provider`.
/// Called when navigating past ProviderSelection for providers that
/// skip the SelectAccount screen (Tenable).
pub fn auto_select_provider_accounts(&mut self) {
    self.selected_accounts.clear();
    for (i, acct) in self.accounts.iter().enumerate() {
        if acct.provider == self.selected_provider {
            self.selected_accounts.insert(i);
        }
    }
}
```

**Step 6: Run tests to verify they pass**

```
cargo test feature_collectors_goes_to_provider_selection provider_selection_prev 2>&1 | tail -10
```

**Step 7: Commit**

```bash
git add src/tui/app/nav.rs src/tui/app/methods.rs
git commit -m "feat(tui): update navigation for ProviderSelection; skip accounts for Tenable"
```

---

## Task 4: Provider filtering — collectors and accounts

**Files:**
- Modify: `src/tui/app/methods.rs`

### 4a — Filter `search_matches_item` by provider

**Step 1: Write failing test**

```rust
#[test]
fn tenable_provider_hides_aws_collectors() {
    let mut app = make_app();
    app.selected_feature = Feature::Collectors;
    app.selected_provider = crate::providers::CloudProvider::Tenable;
    // item 0 is "api-gateway" (CloudProvider::Aws) — must not match
    assert!(!app.search_matches_item(0));
    // item 127 is "tenable-vulns" (CloudProvider::Tenable) — must match
    assert!(app.search_matches_item(127));
}

#[test]
fn aws_provider_hides_tenable_collectors() {
    let mut app = make_app();
    app.selected_feature = Feature::Collectors;
    app.selected_provider = crate::providers::CloudProvider::Aws;
    // item 127 is "tenable-vulns" (CloudProvider::Tenable) — must not match
    assert!(!app.search_matches_item(127));
    // item 0 is "api-gateway" (CloudProvider::Aws) — must match
    assert!(app.search_matches_item(0));
}
```

**Step 2: Run tests to verify they fail**

```
cargo test tenable_provider_hides_aws_collectors 2>&1 | tail -5
```

**Step 3: Update `search_matches_item()` in `src/tui/app/methods.rs`**

```rust
pub fn search_matches_item(&self, global_idx: usize) -> bool {
    let (key, label, provider) = &self.collector_items[global_idx];
    // Provider filter: only applies to the Collectors feature.
    if self.selected_feature == Feature::Collectors && *provider != self.selected_provider {
        return false;
    }
    // Search filter
    let term = self.collector_search.value.to_lowercase();
    if term.is_empty() {
        return true;
    }
    key.to_lowercase().contains(&term) || label.to_lowercase().contains(&term)
}
```

**Step 4: Run tests to verify they pass**

```
cargo test tenable_provider_hides_aws_collectors aws_provider_hides_tenable 2>&1 | tail -10
```

### 4b — Add `provider_account_indices()` helper

**Step 5: Write failing test**

```rust
#[test]
fn provider_account_indices_filters_by_provider() {
    use crate::app_config::Account;
    use crate::providers::CloudProvider;
    let mut app = make_app();
    app.accounts = vec![
        Account { provider: CloudProvider::Aws, name: "aws-prod".into(), ..Default::default() },
        Account { provider: CloudProvider::Tenable, name: "tenable-site".into(), ..Default::default() },
    ];
    app.selected_provider = CloudProvider::Aws;
    assert_eq!(app.provider_account_indices(), vec![0]);
    app.selected_provider = CloudProvider::Tenable;
    assert_eq!(app.provider_account_indices(), vec![1]);
}
```

**Step 6: Run test to verify it fails**

```
cargo test provider_account_indices_filters_by_provider 2>&1 | tail -5
```

**Step 7: Add the method to `src/tui/app/methods.rs`**

```rust
/// Returns the raw indices into `self.accounts` that match `self.selected_provider`.
/// Used by the SelectAccount screen to show only provider-relevant accounts.
pub fn provider_account_indices(&self) -> Vec<usize> {
    self.accounts
        .iter()
        .enumerate()
        .filter(|(_, a)| a.provider == self.selected_provider)
        .map(|(i, _)| i)
        .collect()
}
```

**Step 8: Update `validate_current()` for `Screen::SelectCollectors` (provider-aware)**

Replace the `Screen::SelectCollectors` arm:

```rust
Screen::SelectCollectors => {
    // At least one visible (provider-matching) collector must be selected.
    let any_provider_selected = self.collector_selected.iter().any(|&i| {
        self.collector_items
            .get(i)
            .map(|(_, _, p)| {
                self.selected_feature != Feature::Collectors || *p == self.selected_provider
            })
            .unwrap_or(false)
    });
    if !any_provider_selected {
        self.error_msg = Some("Select at least one collector (Space to toggle)".into());
        return false;
    }
    true
}
```

**Step 9: Add `validate_current()` arm for `Screen::ProviderSelection`**

```rust
Screen::ProviderSelection => {
    // If Tenable is selected, at least one Tenable account must be configured.
    #[cfg(feature = "tenable")]
    if self.selected_provider == CloudProvider::Tenable {
        let has_tenable = self
            .accounts
            .iter()
            .any(|a| a.provider == CloudProvider::Tenable);
        if !has_tenable {
            self.error_msg =
                Some("No Tenable accounts configured in grabber.toml".into());
            return false;
        }
    }
    true
}
```

**Step 10: Run all tests**

```
cargo test 2>&1 | tail -20
```

**Step 11: Commit**

```bash
git add src/tui/app/methods.rs src/tui/app/nav.rs
git commit -m "feat(tui): provider-aware collector filtering and account index helper"
```

---

## Task 5: Update `handle_select_account` to use filtered indices

**Files:**
- Modify: `src/tui/events.rs:111-161`

**Step 1: Replace `handle_select_account` entirely**

The cursor now indexes into the filtered list returned by `provider_account_indices()`, not directly into `app.accounts`. The "Other" option remains at the end.

```rust
fn handle_select_account(app: &mut App, key: KeyCode) {
    let indices = app.provider_account_indices();
    let filtered_len = indices.len();

    match key {
        KeyCode::Up => {
            if app.account_cursor > 0 {
                app.account_cursor -= 1;
            }
        }
        KeyCode::Down => {
            if app.account_cursor < filtered_len {
                // filtered_len == index of "Other" option
                app.account_cursor += 1;
            }
        }
        KeyCode::Char(' ') => {
            if app.account_cursor < filtered_len {
                let real = indices[app.account_cursor];
                if app.selected_accounts.contains(&real) {
                    app.selected_accounts.remove(&real);
                } else {
                    app.selected_accounts.insert(real);
                }
            } else {
                // "Other" chosen — fall back to legacy profile picker
                app.selected_accounts.clear();
                app.screen = Screen::SelectProfile;
            }
        }
        KeyCode::Char('a') => {
            for &i in &indices {
                app.selected_accounts.insert(i);
            }
        }
        KeyCode::Char('d') => {
            app.selected_accounts.clear();
        }
        KeyCode::Enter => {
            if app.account_cursor == filtered_len {
                app.selected_accounts.clear();
                app.screen = Screen::SelectProfile;
            } else {
                if app.selected_accounts.is_empty() {
                    app.selected_accounts.insert(indices[app.account_cursor]);
                }
                if app.validate_current() {
                    app.next_screen();
                }
            }
        }
        KeyCode::Esc => app.prev_screen(),
        _ => {}
    }
}
```

**Step 2: Build to verify it compiles**

```
cargo build 2>&1 | grep "^error"
```

**Step 3: Commit**

```bash
git add src/tui/events.rs
git commit -m "feat(tui): filter SelectAccount event handler by selected_provider"
```

---

## Task 6: Add `handle_provider_selection` event handler

**Files:**
- Modify: `src/tui/events.rs`

**Step 1: Add the handler function**

The available providers must mirror what `draw_provider_selection` renders. Define the list with `#[cfg(feature = "…")]` gates.

```rust
fn handle_provider_selection(app: &mut App, key: KeyCode) {
    use crate::providers::CloudProvider;
    let providers: Vec<CloudProvider> = {
        let mut v = vec![CloudProvider::Aws];
        #[cfg(feature = "azure")]
        v.push(CloudProvider::Azure);
        #[cfg(feature = "gcp")]
        v.push(CloudProvider::Gcp);
        #[cfg(feature = "tenable")]
        v.push(CloudProvider::Tenable);
        v
    };
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
                app.next_screen();
            }
        }
        KeyCode::Esc => app.prev_screen(),
        _ => {}
    }
}
```

**Step 2: Wire into `handle_key` dispatch in `src/tui/events.rs:57-78`**

Add after `Screen::FeatureSelection => handle_feature_selection(app, key),`:

```rust
Screen::ProviderSelection => handle_provider_selection(app, key),
```

**Step 3: Build**

```
cargo build 2>&1 | grep "^error"
```

**Step 4: Commit**

```bash
git add src/tui/events.rs
git commit -m "feat(tui): add handle_provider_selection event handler"
```

---

## Task 7: Add `draw_provider_selection` and update `draw_select_account`

**Files:**
- Modify: `src/tui/ui/account_screens.rs`

### 7a — `draw_provider_selection`

Model after `draw_feature_selection` in `src/tui/ui/setup.rs:102-199` (card layout with Thick border on selected item). Add at the top of `account_screens.rs`:

**Step 1: Add `draw_provider_selection` function**

```rust
// ═══════════════════════════════════════════════════════════════════════════
// Select Provider
// ═══════════════════════════════════════════════════════════════════════════

pub(super) fn draw_provider_selection(f: &mut Frame, area: Rect, app: &App) {
    use crate::providers::CloudProvider;

    let providers: Vec<(CloudProvider, &str, &str)> = {
        let mut v = vec![(
            CloudProvider::Aws,
            "◆  Amazon Web Services (AWS)",
            "Run 100+ compliance evidence collectors (CloudTrail, S3, IAM, RDS, …)",
        )];
        #[cfg(feature = "azure")]
        v.push((
            CloudProvider::Azure,
            "◆  Microsoft Azure",
            "Collect compliance evidence from Azure resources",
        ));
        #[cfg(feature = "gcp")]
        v.push((
            CloudProvider::Gcp,
            "◆  Google Cloud Platform (GCP)",
            "Collect compliance evidence from GCP resources",
        ));
        #[cfg(feature = "tenable")]
        v.push((
            CloudProvider::Tenable,
            "◆  Tenable",
            "Export vulnerability findings from Tenable.io or Tenable.sc",
        ));
        v
    };

    let card_height: u16 = 5;
    let total_cards_height = providers.len() as u16 * card_height
        + providers.len().saturating_sub(1) as u16; // 1-row gaps between cards

    let chunks = Layout::vertical([
        Constraint::Fill(1),
        Constraint::Length(1), // title
        Constraint::Length(1), // subtitle
        Constraint::Length(2), // blank
        Constraint::Length(total_cards_height),
        Constraint::Fill(1),
    ])
    .split(area);

    f.render_widget(
        Paragraph::new(Span::styled(
            "Select a cloud provider:",
            Style::default()
                .fg(TEXT_BRIGHT)
                .add_modifier(Modifier::BOLD),
        ))
        .alignment(ratatui::layout::Alignment::Center),
        chunks[1],
    );
    f.render_widget(
        Paragraph::new(Span::styled(
            "Use ↑↓ to select a provider, then press Enter",
            Style::default().fg(TEXT_DIM),
        ))
        .alignment(ratatui::layout::Alignment::Center),
        chunks[2],
    );

    let cards_area = chunks[4];
    for (idx, (provider, label, desc)) in providers.iter().enumerate() {
        let selected = app.selected_provider == *provider;
        let card_area = Rect {
            x: cards_area.x,
            y: cards_area.y + idx as u16 * (card_height + 1),
            width: cards_area.width,
            height: card_height,
        };

        let border_style = if selected {
            Style::default().fg(CYAN)
        } else {
            Style::default().fg(BORDER_SUBTLE)
        };
        let label_style = if selected {
            Style::default().fg(CYAN).add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(TEXT_NORMAL)
        };

        let card_block = Block::bordered()
            .border_type(if selected {
                BorderType::Thick
            } else {
                BorderType::Plain
            })
            .border_style(border_style)
            .style(Style::default().bg(if selected { BG_ELEVATED } else { BG_MAIN }));
        let inner = card_block.inner(card_area);
        f.render_widget(card_block, card_area);

        let inner_layout = Layout::vertical([
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Length(1),
        ])
        .split(inner);

        let indicator = if selected { " ▶ " } else { "   " };
        f.render_widget(
            Paragraph::new(Line::from(vec![
                Span::styled(indicator, Style::default().fg(AMBER)),
                Span::styled(*label, label_style),
            ])),
            inner_layout[0],
        );
        f.render_widget(
            Paragraph::new(Span::styled(*desc, Style::default().fg(TEXT_DIM))),
            inner_layout[2],
        );
    }
}
```

### 7b — Update `draw_select_account` to filter by provider

The account list must only show entries matching `app.selected_provider`. The cursor now positions within the filtered list; the real `app.accounts` index is looked up via `provider_account_indices()`.

**Step 2: Replace `draw_select_account` in `src/tui/ui/account_screens.rs`**

```rust
pub(super) fn draw_select_account(f: &mut Frame, area: Rect, app: &App) {
    let indices = app.provider_account_indices();

    let chunks =
        Layout::vertical([Constraint::Length(2), Constraint::Fill(1)]).split(content_inset(area));

    let count_text = format!(
        "Select {} account(s) to collect evidence from:  ({} of {} selected)",
        app.selected_provider,
        // Count only accounts matching this provider
        app.selected_accounts
            .iter()
            .filter(|&&i| app.accounts.get(i).map(|a| a.provider == app.selected_provider).unwrap_or(false))
            .count(),
        indices.len(),
    );
    f.render_widget(
        Paragraph::new(Span::styled(count_text, Style::default().fg(TEXT_DIM))),
        chunks[0],
    );

    let total_entries = indices.len() + 2; // filtered accounts + separator + "Other"
    let mut items: Vec<ListItem> = Vec::with_capacity(total_entries);

    for (cursor_pos, &real_idx) in indices.iter().enumerate() {
        let acct = &app.accounts[real_idx];
        let at_cursor = cursor_pos == app.account_cursor;
        let checked = app.selected_accounts.contains(&real_idx);
        let cursor_icon = if at_cursor { "▸ " } else { "  " };
        let checkbox = if checked { "[x] " } else { "[ ] " };

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
        let checkbox_style = if checked {
            Style::default().fg(GREEN)
        } else {
            Style::default().fg(TEXT_DIM)
        };

        let detail = format!(
            "      {} · {} · {}",
            acct.account_id.as_deref().unwrap_or(""),
            acct.profile.as_deref().unwrap_or(""),
            acct.region.as_deref().unwrap_or("us-east-1"),
        );

        items.push(ListItem::new(Text::from(vec![
            Line::from(vec![
                Span::styled(cursor_icon, Style::default().fg(AMBER)),
                Span::styled(checkbox, checkbox_style),
                Span::styled(&acct.name, name_style),
            ]),
            Line::from(Span::styled(detail, Style::default().fg(TEXT_DIM))),
            Line::raw(""),
        ])));
    }

    // Separator
    let sep_width = chunks[1].width.saturating_sub(6) as usize;
    items.push(ListItem::new(Line::from(Span::styled(
        format!("  {}", "┄".repeat(sep_width)),
        Style::default().fg(BORDER_SUBTLE),
    ))));

    // "Other" option
    let other_selected = app.account_cursor == indices.len();
    let other_icon = if other_selected { "▸ " } else { "  " };
    let other_style = if other_selected {
        Style::default()
            .fg(AMBER)
            .add_modifier(Modifier::BOLD)
            .bg(BG_SELECTED)
    } else {
        Style::default().fg(TEXT_NORMAL)
    };
    items.push(ListItem::new(Text::from(vec![
        Line::from(vec![
            Span::styled(other_icon, Style::default().fg(AMBER)),
            Span::styled("Other (pick from AWS profiles)", other_style),
        ]),
        Line::from(Span::styled(
            "    Select any profile from ~/.aws/config",
            Style::default().fg(TEXT_DIM),
        )),
    ])));

    let list_block = Block::bordered()
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(BORDER_SUBTLE))
        .padding(Padding::horizontal(1));

    f.render_widget(List::new(items).block(list_block), chunks[1]);
}
```

**Step 3: Build**

```
cargo build 2>&1 | grep "^error"
```

**Step 4: Commit**

```bash
git add src/tui/ui/account_screens.rs
git commit -m "feat(tui/ui): add draw_provider_selection; filter draw_select_account by provider"
```

---

## Task 8: Wire `draw_provider_selection` into `ui/mod.rs` and `events.rs`

**Files:**
- Modify: `src/tui/ui/mod.rs:36-134`

**Step 1: Add dispatch in `draw()` match block**

After `Screen::FeatureSelection => setup::draw_feature_selection(f, content, app),` add:

```rust
Screen::ProviderSelection => account_screens::draw_provider_selection(f, content, app),
```

**Step 2: Exclude `ProviderSelection` from the step-indicator region**

Update the `show_steps` expression (currently line 48-52):

```rust
let show_steps = !matches!(
    app.screen,
    Screen::Welcome
        | Screen::FeatureSelection
        | Screen::ProviderSelection  // NEW
        | Screen::Preparing
        | Screen::Results
);
```

**Step 3: Build**

```
cargo build 2>&1 | grep "^error"
```

**Step 4: Commit**

```bash
git add src/tui/ui/mod.rs
git commit -m "feat(tui/ui): dispatch ProviderSelection in draw(); exclude from step indicator"
```

---

## Task 9: Update step indicators in `frame.rs`

**Files:**
- Modify: `src/tui/ui/frame.rs:18-130`
- Modify: `src/tui/ui/mod.rs:67-90`

**Step 1: Add new step constant arrays in `frame.rs`**

Replace `STEPS_ACCOUNTS` and `STEPS_LEGACY` (which are now Collectors-specific with Provider prepended):

```rust
// Feature::Collectors — has TOML accounts (non-Tenable)
pub(super) const STEPS_PROVIDER_ACCOUNTS: &[&str] =
    &["Provider", "Account", "Dates", "Collectors", "Options", "Confirm", "Run"];

// Feature::Collectors — legacy profile/region (non-Tenable)
pub(super) const STEPS_PROVIDER_LEGACY: &[&str] = &[
    "Provider", "Profile", "Region", "Dates", "Collectors", "Options", "Confirm", "Run",
];

// Feature::Collectors — Tenable (skip account screen)
pub(super) const STEPS_TENABLE: &[&str] =
    &["Provider", "Dates", "Collectors", "Options", "Confirm", "Run"];
```

Keep `STEPS_INV_ACCOUNTS`, `STEPS_INV_LEGACY`, `STEPS_POAM`, `STEPS_POAM_NO_ACCOUNTS` unchanged (Inventory / Poam don't use provider selection).

**Step 2: Update `screen_to_step()` signature to accept `selected_provider`**

```rust
pub(super) fn screen_to_step(
    screen: &Screen,
    has_accounts: bool,
    feature: &Feature,
    selected_provider: crate::providers::CloudProvider, // NEW
) -> Option<usize> {
```

**Step 3: Update the `Feature::Collectors` branch in `screen_to_step()`**

```rust
Feature::Collectors => {
    use crate::providers::CloudProvider;
    if selected_provider == CloudProvider::Tenable {
        match screen {
            Screen::ProviderSelection  => Some(0),
            Screen::SetDates           => Some(1),
            Screen::SelectCollectors   => Some(2),
            Screen::SetOptions         => Some(3),
            Screen::Confirm            => Some(4),
            Screen::Running            => Some(5),
            _                          => None,
        }
    } else if has_accounts {
        match screen {
            Screen::ProviderSelection  => Some(0),
            Screen::SelectAccount      => Some(1),
            Screen::SetDates           => Some(2),
            Screen::SelectCollectors   => Some(3),
            Screen::SetOptions         => Some(4),
            Screen::Confirm            => Some(5),
            Screen::Running            => Some(6),
            _                          => None,
        }
    } else {
        match screen {
            Screen::ProviderSelection  => Some(0),
            Screen::SelectProfile      => Some(1),
            Screen::SelectRegion       => Some(2),
            Screen::SetDates           => Some(3),
            Screen::SelectCollectors   => Some(4),
            Screen::SetOptions         => Some(5),
            Screen::Confirm            => Some(6),
            Screen::Running            => Some(7),
            _                          => None,
        }
    }
}
```

**Step 4: Add `ProviderSelection` hint in `get_hints()`**

```rust
Screen::ProviderSelection => vec![("↑↓", "Navigate"), ("⏎", "Select"), ("Esc", "Back")],
```

**Step 5: Update call sites in `src/tui/ui/mod.rs`**

Update the `screen_to_step` call:

```rust
let step_info = screen_to_step(
    &app.screen,
    app.has_accounts(),
    &app.selected_feature,
    app.selected_provider,  // NEW
);
```

Update the `steps` selection to use new constants:

```rust
let steps = match app.selected_feature {
    Feature::Collectors => {
        use crate::providers::CloudProvider;
        if app.selected_provider == CloudProvider::Tenable {
            STEPS_TENABLE
        } else if app.has_accounts() {
            STEPS_PROVIDER_ACCOUNTS
        } else {
            STEPS_PROVIDER_LEGACY
        }
    }
    Feature::Inventory => {
        if app.has_accounts() {
            STEPS_INV_ACCOUNTS
        } else {
            STEPS_INV_LEGACY
        }
    }
    Feature::Poam => {
        if app.has_accounts() {
            STEPS_POAM
        } else {
            STEPS_POAM_NO_ACCOUNTS
        }
    }
};
```

Update the import line in `ui/mod.rs`:

```rust
use self::frame::{
    draw_footer, draw_header, draw_separator, draw_step_indicator, get_hints, screen_to_step,
    STEPS_INV_ACCOUNTS, STEPS_INV_LEGACY, STEPS_POAM, STEPS_POAM_NO_ACCOUNTS,
    STEPS_PROVIDER_ACCOUNTS, STEPS_PROVIDER_LEGACY, STEPS_TENABLE,
};
```

Remove `STEPS_ACCOUNTS` and `STEPS_LEGACY` from the import (they are replaced).

**Step 6: Delete the old `STEPS_ACCOUNTS` and `STEPS_LEGACY` constants from `frame.rs`**

Confirm they're no longer referenced:

```
grep -rn "STEPS_ACCOUNTS\|STEPS_LEGACY[^_]" src/ 2>&1
```

If the grep shows no results (or only the declaration), delete the declarations.

**Step 7: Build and run all tests**

```
cargo build 2>&1 | grep "^error"
cargo test 2>&1 | tail -20
```

Expected: clean build, all tests green.

**Step 8: Commit**

```bash
git add src/tui/ui/frame.rs src/tui/ui/mod.rs
git commit -m "feat(tui/ui): update step indicators for provider flows; remove old STEPS constants"
```

---

## Task 10: Smoke test the full flow manually

**Step 1: Build a release binary**

```
cargo build --release 2>&1 | grep "^error"
```

**Step 2: Run the TUI**

```
./target/release/grabber
```

**Step 3: Walk the Collectors → AWS path**

1. Press Enter on Welcome
2. Select **Collectors**, press Enter → should land on **ProviderSelection**
3. AWS is pre-selected; press Enter → should land on **SelectAccount** (or SelectProfile if no TOML accounts)
4. Step indicator at top should read: `Provider → Account → Dates → Collectors → …`
5. Press Esc to back up → returns to **ProviderSelection**
6. Press Esc again → returns to **FeatureSelection** ✓

**Step 4: Walk the Collectors → Tenable path (requires `[cfg(feature = "tenable")]` build)**

```
cargo build --release --features tenable 2>&1 | grep "^error"
./target/release/grabber
```

1. Select **Collectors**, Enter → **ProviderSelection**
2. Press ↓ to select Tenable, press Enter
3. Should land on **SetDates** (no Accounts screen) ✓
4. Step indicator should read: `Provider → Dates → Collectors → …`
5. Collector list should show only `tenable-vulns` ✓

**Step 5: Confirm Inventory and Poam flows are unchanged**

Select Inventory → goes straight to SelectAccount / SelectProfile (no ProviderSelection) ✓
Select Poam → goes to PoamAccount / PoamRegion (no ProviderSelection) ✓

**Step 6: Final commit (if any fixups)**

```bash
git add -p
git commit -m "fix(tui): smoke-test fixups for ProviderSelection flow"
```

---

## Summary of all touched files

| File | Change |
|------|--------|
| `src/tui/state.rs` | +`Screen::ProviderSelection` variant |
| `src/tui/app/mod.rs` | +`selected_provider`, +`provider_cursor` fields + init |
| `src/tui/app/nav.rs` | Updated `next_screen`, `prev_screen`, `reset` |
| `src/tui/app/methods.rs` | Updated `search_matches_item`, `validate_current`; +`auto_select_provider_accounts`, +`provider_account_indices` |
| `src/tui/events.rs` | +`handle_provider_selection`; updated `handle_key`, `handle_select_account` |
| `src/tui/ui/account_screens.rs` | +`draw_provider_selection`; updated `draw_select_account` |
| `src/tui/ui/mod.rs` | Updated `draw()`, `show_steps`, `steps` selection, imports |
| `src/tui/ui/frame.rs` | +`STEPS_PROVIDER_ACCOUNTS`, +`STEPS_PROVIDER_LEGACY`, +`STEPS_TENABLE`; removed `STEPS_ACCOUNTS`, `STEPS_LEGACY`; updated `screen_to_step` signature; +hint for `ProviderSelection` |
