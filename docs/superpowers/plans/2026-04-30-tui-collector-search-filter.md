# TUI Collector Search/Filter Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a real-time search/filter bar to the SelectCollectors TUI screen that narrows the two-panel category+item layout to only matching collectors as the user types.

**Architecture:** Extend `CollectorFocus` with a `Search` variant and add a `collector_search: TextInput` field to `App`. Helper methods compute visible categories/items from the search term. Key handler routes characters to the search box when focused. `draw_collectors` prepends a 3-row search bar above the existing panels and renders only visible rows.

**Tech Stack:** Rust, ratatui 0.29, crossterm 0.28. All changes in `src/tui/mod.rs` and `src/tui/ui.rs`. No new files.

---

## File Map

| File | What changes |
|------|-------------|
| `src/tui/mod.rs:83-86` | Add `Search` variant to `CollectorFocus` |
| `src/tui/mod.rs:256` | Add `collector_search: TextInput` field to `App` |
| `src/tui/mod.rs:875` | Initialize `collector_search` in `App::new()` |
| `src/tui/mod.rs:1325` | Clear `collector_search` in `App::reset()` |
| `src/tui/mod.rs:1063+` | Add four helper methods after `jump_to_category` |
| `src/tui/mod.rs:1758-1839` | Replace `Screen::SelectCollectors` key handler |
| `src/tui/ui.rs:1243-1422` | Replace `draw_collectors` function |

---

## Task 1: Extend `CollectorFocus` and add `collector_search` to `App`

**Files:**
- Modify: `src/tui/mod.rs:83-86` (CollectorFocus enum)
- Modify: `src/tui/mod.rs:256` (App struct field)
- Modify: `src/tui/mod.rs:875` (App::new initializer)
- Modify: `src/tui/mod.rs:1325` (App::reset)

- [ ] **Step 1: Add `Search` variant to `CollectorFocus`**

In `src/tui/mod.rs`, replace:

```rust
#[derive(Debug, Clone, PartialEq)]
pub enum CollectorFocus {
    Categories,
    Items,
}
```

with:

```rust
#[derive(Debug, Clone, PartialEq)]
pub enum CollectorFocus {
    Search,
    Categories,
    Items,
}
```

- [ ] **Step 2: Add `collector_search` field to the `App` struct**

In `src/tui/mod.rs`, after the line `pub collector_focus: CollectorFocus,` (line 256), add:

```rust
    pub collector_search: TextInput,
```

The surrounding context for the edit:

```rust
    pub collector_focus: CollectorFocus,
    pub collector_search: TextInput,    // ← add this line

    // Options
    pub output_dir: TextInput,
```

- [ ] **Step 3: Initialize `collector_search` in `App::new()`**

In `src/tui/mod.rs`, after the line `collector_focus: CollectorFocus::Categories,` (line 875), add:

```rust
            collector_search: TextInput::default(),
```

The surrounding context:

```rust
            collector_focus: CollectorFocus::Categories,
            collector_search: TextInput::default(),    // ← add this line
            output_dir: TextInput::new(config.defaults.output_dir.as_deref().unwrap_or(".")),
```

- [ ] **Step 4: Clear `collector_search` in `App::reset()`**

In `src/tui/mod.rs`, after the line `self.collector_focus = CollectorFocus::Categories;` (line 1325), add:

```rust
        self.collector_search.clear();
```

The surrounding context:

```rust
        self.collector_category_cursor = 0;
        self.collector_focus = CollectorFocus::Categories;
        self.collector_search.clear();    // ← add this line
        self.poam_summary = None;
```

- [ ] **Step 5: Verify the project compiles**

```bash
cd /Users/austin-songer/code/grabber && cargo check 2>&1 | head -30
```

Expected: compilation succeeds (zero errors). The `CollectorFocus::Search` variant is unused yet — the compiler may emit an unused-variant warning; that is fine and will be resolved in Task 3.

- [ ] **Step 6: Commit**

```bash
git add src/tui/mod.rs
git commit -m "feat(tui): add Search focus variant and collector_search field"
```

---

## Task 2: Add filter helper methods with unit tests

**Files:**
- Modify: `src/tui/mod.rs` — add four methods to `impl App` after `jump_to_category` (~line 1069)

- [ ] **Step 1: Add the four helper methods**

In `src/tui/mod.rs`, locate the closing brace of `jump_to_category` (it ends around line 1069):

```rust
    /// Jump collector_cursor to the first item of a category.
    pub fn jump_to_category(&mut self, cat_idx: usize) {
        self.collector_category_cursor = cat_idx;
        let (start, _) = self.category_bounds(cat_idx);
        self.collector_cursor = start;
    }
```

Insert the following four methods directly after that closing brace:

```rust
    /// True when `global_idx` passes the current collector search filter.
    /// Always true when the search value is empty.
    pub fn search_matches_item(&self, global_idx: usize) -> bool {
        let term = self.collector_search.value.to_lowercase();
        if term.is_empty() {
            return true;
        }
        let (key, label) = &self.collector_items[global_idx];
        key.to_lowercase().contains(&term) || label.to_lowercase().contains(&term)
    }

    /// Returns indices of categories that contain at least one item matching the
    /// current search filter. Returns all category indices when search is empty.
    pub fn visible_categories(&self) -> Vec<usize> {
        (0..COLLECTOR_CATEGORIES.len())
            .filter(|&cat_idx| {
                let (start, end) = self.category_bounds(cat_idx);
                (start..end).any(|i| self.search_matches_item(i))
            })
            .collect()
    }

    /// Returns global item indices within `cat_idx` that pass the search filter.
    /// Returns all items in the category when search is empty.
    pub fn visible_items_in_category(&self, cat_idx: usize) -> Vec<usize> {
        let (start, end) = self.category_bounds(cat_idx);
        (start..end)
            .filter(|&i| self.search_matches_item(i))
            .collect()
    }

    /// After the search term changes, snaps `collector_category_cursor` to the
    /// first visible category (if the current one no longer matches) and snaps
    /// `collector_cursor` to the first visible item in that category.
    pub fn clamp_collector_cursors(&mut self) {
        let visible_cats = self.visible_categories();
        if visible_cats.is_empty() {
            return;
        }
        if !visible_cats.contains(&self.collector_category_cursor) {
            self.collector_category_cursor = visible_cats[0];
        }
        let visible_items = self.visible_items_in_category(self.collector_category_cursor);
        if visible_items.is_empty() {
            return;
        }
        if !visible_items.contains(&self.collector_cursor) {
            self.collector_cursor = visible_items[0];
        }
    }
```

- [ ] **Step 2: Add unit tests**

At the very bottom of `src/tui/mod.rs` (after the last closing brace), append:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn make_app() -> App {
        App::new(vec![])
    }

    #[test]
    fn search_empty_matches_all_items() {
        let app = make_app();
        for i in 0..app.collector_items.len() {
            assert!(app.search_matches_item(i), "item {i} should match empty search");
        }
    }

    #[test]
    fn search_matches_key_substring() {
        let mut app = make_app();
        app.collector_search.value = "iam".to_string();
        app.collector_search.cursor = 3;
        // "access-analyzer" label is "IAM Access Analyzer …" — matches via label
        assert!(app.search_matches_item(55));
        // "api-gateway" — neither key nor label contains "iam"
        assert!(!app.search_matches_item(0));
    }

    #[test]
    fn search_case_insensitive() {
        let mut app = make_app();
        app.collector_search.value = "IAM".to_string();
        app.collector_search.cursor = 3;
        assert!(app.search_matches_item(55));
    }

    #[test]
    fn search_matches_label_text() {
        let mut app = make_app();
        // "cloudtrail" appears in many keys/labels in the Audit Trail category
        app.collector_search.value = "cloudtrail".to_string();
        app.collector_search.cursor = 10;
        // index 9 is ("cloudtrail", "CloudTrail API …")
        assert!(app.search_matches_item(9));
        // index 0 is "api-gateway" — no "cloudtrail"
        assert!(!app.search_matches_item(0));
    }

    #[test]
    fn visible_categories_empty_search_returns_all() {
        let app = make_app();
        let visible = app.visible_categories();
        assert_eq!(visible.len(), COLLECTOR_CATEGORIES.len());
        assert_eq!(visible, (0..COLLECTOR_CATEGORIES.len()).collect::<Vec<_>>());
    }

    #[test]
    fn visible_categories_filters_to_matching_categories() {
        let mut app = make_app();
        app.collector_search.value = "iam".to_string();
        app.collector_search.cursor = 3;
        let visible = app.visible_categories();
        // "Identity & Access" (index 6) has IAM collectors — must be present
        assert!(visible.contains(&6));
        // "Audit Trail" (index 1) has "ct-iam-changes" — must be present
        assert!(visible.contains(&1));
        // "Containers" (index 3) has no IAM items — must be absent
        assert!(!visible.contains(&3));
        // "Database & Backup" (index 4) has no IAM items — must be absent
        assert!(!visible.contains(&4));
    }

    #[test]
    fn visible_items_empty_search_returns_full_category() {
        let app = make_app();
        let (start, end) = app.category_bounds(0);
        let visible = app.visible_items_in_category(0);
        assert_eq!(visible, (start..end).collect::<Vec<_>>());
    }

    #[test]
    fn visible_items_filters_within_category() {
        let mut app = make_app();
        app.collector_search.value = "iam".to_string();
        app.collector_search.cursor = 3;
        // Identity & Access category (index 6) — all items have "iam" in key or label
        let visible = app.visible_items_in_category(6);
        assert!(!visible.is_empty());
        for &i in &visible {
            assert!(app.search_matches_item(i), "item {i} should match 'iam'");
        }
        // Containers category (index 3) — no IAM items
        let visible_containers = app.visible_items_in_category(3);
        assert!(visible_containers.is_empty());
    }

    #[test]
    fn clamp_cursors_snaps_to_first_visible_category() {
        let mut app = make_app();
        // Force cursor to Containers (index 3), which has no IAM items
        app.collector_category_cursor = 3;
        app.collector_search.value = "iam".to_string();
        app.collector_search.cursor = 3;
        app.clamp_collector_cursors();
        let visible = app.visible_categories();
        assert!(
            visible.contains(&app.collector_category_cursor),
            "category_cursor should be in visible set after clamp"
        );
    }

    #[test]
    fn clamp_cursors_noop_on_empty_search() {
        let mut app = make_app();
        app.collector_category_cursor = 5;
        app.collector_cursor = 50;
        app.clamp_collector_cursors();
        // No-op when search is empty — all categories visible
        assert_eq!(app.collector_category_cursor, 5);
        assert_eq!(app.collector_cursor, 50);
    }
}
```

- [ ] **Step 3: Run the unit tests**

```bash
cd /Users/austin-songer/code/grabber && cargo test 2>&1 | grep -E "test |FAILED|ok|error"
```

Expected output (all pass, no errors):

```
test tests::clamp_cursors_noop_on_empty_search ... ok
test tests::clamp_cursors_snaps_to_first_visible_category ... ok
test tests::search_case_insensitive ... ok
test tests::search_empty_matches_all_items ... ok
test tests::search_matches_key_substring ... ok
test tests::search_matches_label_text ... ok
test tests::visible_categories_empty_search_returns_all ... ok
test tests::visible_categories_filters_to_matching_categories ... ok
test tests::visible_items_empty_search_returns_full_category ... ok
test tests::visible_items_filters_within_category ... ok
```

If any test fails, re-read the collector_items list in `App::new()` and verify the expected indices: index 0 = `api-gateway`, index 9 = `cloudtrail`, index 55 = `access-analyzer` (label "IAM Access Analyzer …").

- [ ] **Step 4: Commit**

```bash
git add src/tui/mod.rs
git commit -m "feat(tui): add collector search filter helpers with unit tests"
```

---

## Task 3: Update `Screen::SelectCollectors` key handler

**Files:**
- Modify: `src/tui/mod.rs:1758-1839` — replace the entire `Screen::SelectCollectors` match arm

- [ ] **Step 1: Replace the `Screen::SelectCollectors` arm**

Locate the block (currently lines 1758–1839):

```rust
        Screen::SelectCollectors => match key {
            // ── Panel switching ──────────────────────────────────────────
            KeyCode::Tab | KeyCode::Left | KeyCode::Right => {
```

Replace the entire `Screen::SelectCollectors => match key { … },` arm (all the way to its closing `},`) with:

```rust
        Screen::SelectCollectors => match key {
            // ── Panel switching ──────────────────────────────────────────
            KeyCode::Tab => {
                app.collector_focus = match app.collector_focus {
                    CollectorFocus::Search => CollectorFocus::Categories,
                    CollectorFocus::Categories => CollectorFocus::Items,
                    CollectorFocus::Items => CollectorFocus::Search,
                };
            }
            // Left/Right only toggles Categories ↔ Items (not Search)
            KeyCode::Left | KeyCode::Right
                if app.collector_focus != CollectorFocus::Search =>
            {
                app.collector_focus = match app.collector_focus {
                    CollectorFocus::Categories => CollectorFocus::Items,
                    CollectorFocus::Items | CollectorFocus::Search => CollectorFocus::Categories,
                };
            }

            // ── Search panel ─────────────────────────────────────────────
            KeyCode::Left if app.collector_focus == CollectorFocus::Search => {
                app.collector_search.move_left();
            }
            KeyCode::Right if app.collector_focus == CollectorFocus::Search => {
                app.collector_search.move_right();
            }
            KeyCode::Char(c) if app.collector_focus == CollectorFocus::Search => {
                app.collector_search.insert(c);
                app.clamp_collector_cursors();
            }
            KeyCode::Backspace if app.collector_focus == CollectorFocus::Search => {
                app.collector_search.backspace();
                app.clamp_collector_cursors();
            }
            KeyCode::Down if app.collector_focus == CollectorFocus::Search => {
                app.collector_focus = CollectorFocus::Categories;
            }
            // Esc with non-empty search: clear search, stay on screen
            KeyCode::Esc
                if app.collector_focus == CollectorFocus::Search
                    && !app.collector_search.value.is_empty() =>
            {
                app.collector_search.clear();
                app.clamp_collector_cursors();
            }

            // ── Category panel navigation ────────────────────────────────
            KeyCode::Up if app.collector_focus == CollectorFocus::Categories => {
                let visible = app.visible_categories();
                if let Some(pos) = visible
                    .iter()
                    .position(|&c| c == app.collector_category_cursor)
                {
                    if pos > 0 {
                        app.collector_category_cursor = visible[pos - 1];
                        let items =
                            app.visible_items_in_category(app.collector_category_cursor);
                        if let Some(&first) = items.first() {
                            app.collector_cursor = first;
                        }
                    }
                }
            }
            KeyCode::Down if app.collector_focus == CollectorFocus::Categories => {
                let visible = app.visible_categories();
                if let Some(pos) = visible
                    .iter()
                    .position(|&c| c == app.collector_category_cursor)
                {
                    if pos + 1 < visible.len() {
                        app.collector_category_cursor = visible[pos + 1];
                        let items =
                            app.visible_items_in_category(app.collector_category_cursor);
                        if let Some(&first) = items.first() {
                            app.collector_cursor = first;
                        }
                    }
                }
            }
            // Number keys jump to category (only in Categories focus)
            KeyCode::Char(c)
                if c.is_ascii_digit()
                    && app.collector_focus == CollectorFocus::Categories =>
            {
                let digit = c as usize - '0' as usize;
                if digit > 0 && digit <= COLLECTOR_CATEGORIES.len() {
                    app.jump_to_category(digit - 1);
                }
            }

            // ── Item panel navigation ────────────────────────────────────
            KeyCode::Up if app.collector_focus == CollectorFocus::Items => {
                let items = app.visible_items_in_category(app.collector_category_cursor);
                if let Some(pos) = items.iter().position(|&i| i == app.collector_cursor) {
                    if pos > 0 {
                        app.collector_cursor = items[pos - 1];
                    } else {
                        // Jump to previous visible category, land on its last item
                        let visible_cats = app.visible_categories();
                        if let Some(cat_pos) = visible_cats
                            .iter()
                            .position(|&c| c == app.collector_category_cursor)
                        {
                            if cat_pos > 0 {
                                app.collector_category_cursor = visible_cats[cat_pos - 1];
                                let prev_items =
                                    app.visible_items_in_category(app.collector_category_cursor);
                                if let Some(&last) = prev_items.last() {
                                    app.collector_cursor = last;
                                }
                            }
                        }
                    }
                }
            }
            KeyCode::Down if app.collector_focus == CollectorFocus::Items => {
                let items = app.visible_items_in_category(app.collector_category_cursor);
                if let Some(pos) = items.iter().position(|&i| i == app.collector_cursor) {
                    if pos + 1 < items.len() {
                        app.collector_cursor = items[pos + 1];
                    } else {
                        // Jump to next visible category, land on its first item
                        let visible_cats = app.visible_categories();
                        if let Some(cat_pos) = visible_cats
                            .iter()
                            .position(|&c| c == app.collector_category_cursor)
                        {
                            if cat_pos + 1 < visible_cats.len() {
                                app.collector_category_cursor = visible_cats[cat_pos + 1];
                                let next_items =
                                    app.visible_items_in_category(app.collector_category_cursor);
                                if let Some(&first) = next_items.first() {
                                    app.collector_cursor = first;
                                }
                            }
                        }
                    }
                }
            }

            // ── Toggle (Space) ───────────────────────────────────────────
            KeyCode::Char(' ') if app.collector_focus == CollectorFocus::Items => {
                let i = app.collector_cursor;
                if app.collector_selected.contains(&i) {
                    app.collector_selected.remove(&i);
                } else {
                    app.collector_selected.insert(i);
                }
            }
            KeyCode::Char(' ') if app.collector_focus == CollectorFocus::Categories => {
                let sel = app.selected_in_category(app.collector_category_cursor);
                let (start, end) = app.category_bounds(app.collector_category_cursor);
                let total = end.saturating_sub(start);
                app.set_category_selection(app.collector_category_cursor, sel < total);
            }

            // ── Select / Deselect all (guarded: not while typing in search) ──
            KeyCode::Char('a')
                if app.collector_focus != CollectorFocus::Search =>
            {
                app.set_category_selection(app.collector_category_cursor, true);
            }
            KeyCode::Char('d')
                if app.collector_focus != CollectorFocus::Search =>
            {
                app.set_category_selection(app.collector_category_cursor, false);
            }

            KeyCode::Enter => {
                if app.validate_current() {
                    app.next_screen();
                }
            }
            KeyCode::Esc => app.prev_screen(),
            _ => {}
        },
```

- [ ] **Step 2: Compile check**

```bash
cd /Users/austin-songer/code/grabber && cargo check 2>&1 | head -20
```

Expected: zero errors. If there is a "non-exhaustive patterns" error on `CollectorFocus`, check that all three variants are covered in every match expression.

- [ ] **Step 3: Run tests to confirm no regressions**

```bash
cd /Users/austin-songer/code/grabber && cargo test 2>&1 | grep -E "test |FAILED|ok|error"
```

Expected: all tests pass.

- [ ] **Step 4: Commit**

```bash
git add src/tui/mod.rs
git commit -m "feat(tui): update SelectCollectors key handler for search focus"
```

---

## Task 4: Update `draw_collectors` rendering

**Files:**
- Modify: `src/tui/ui.rs:1243-1422` — replace the entire `draw_collectors` function

- [ ] **Step 1: Replace `draw_collectors` in full**

Locate the function (lines 1243–1422 in `src/tui/ui.rs`) and replace the **entire** function body with the following. The function signature stays identical (`fn draw_collectors(f: &mut Frame, area: Rect, app: &App)`).

```rust
fn draw_collectors(f: &mut Frame, area: Rect, app: &App) {
    let selected_count = app.collector_selected.len();
    let total_count = app.collector_items.len();
    let search_term = &app.collector_search.value;

    let title = if search_term.is_empty() {
        format!(
            " Collectors \u{2500}\u{2500}\u{2500} {} of {} selected ",
            selected_count, total_count,
        )
    } else {
        let match_count: usize = (0..total_count)
            .filter(|&i| app.search_matches_item(i))
            .count();
        format!(
            " Collectors \u{2500}\u{2500}\u{2500} {} of {} selected  \u{2022}  {} matches ",
            selected_count, total_count, match_count,
        )
    };

    let block = Block::bordered()
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(BORDER_SUBTLE))
        .title(Line::from(vec![Span::styled(
            &title,
            Style::default().fg(CYAN_DIM),
        )]));

    let inner = block.inner(area);
    f.render_widget(block, area);

    // Layout: search bar (3) | main panels (fill) | separator (1) | help (1)
    let v_chunks = Layout::vertical([
        Constraint::Length(3),
        Constraint::Fill(1),
        Constraint::Length(1),
        Constraint::Length(1),
    ])
    .split(inner);

    let search_area = v_chunks[0];
    let main_area = v_chunks[1];
    let help_area = v_chunks[3];

    // ── Search bar ───────────────────────────────────────────────
    let search_focused = app.collector_focus == CollectorFocus::Search;
    let has_search = !search_term.is_empty();
    let search_label = if has_search {
        " Search collectors  [\u{2715} Esc to clear] ".to_string()
    } else {
        " Search collectors\u{2026} ".to_string()
    };
    let search_block = Block::bordered()
        .border_type(BorderType::Rounded)
        .border_style(if search_focused {
            Style::default().fg(CYAN)
        } else {
            Style::default().fg(BORDER_SUBTLE)
        })
        .title(Span::styled(
            search_label,
            if search_focused {
                Style::default().fg(CYAN)
            } else {
                Style::default().fg(TEXT_DIM)
            },
        ))
        .padding(Padding::horizontal(1));

    f.render_widget(
        Paragraph::new(Span::styled(
            search_term.as_str(),
            Style::default().fg(TEXT_BRIGHT),
        ))
        .block(search_block),
        search_area,
    );

    if search_focused {
        // border(1) + padding(1) + cursor byte offset
        f.set_cursor_position((
            search_area.x + 2 + app.collector_search.cursor as u16,
            search_area.y + 1,
        ));
    }

    // ── Resolve visible set ───────────────────────────────────────
    let visible_cats = app.visible_categories();

    // ── Empty state: no categories have any matching item ─────────
    if visible_cats.is_empty() {
        let empty_msg = format!(
            "No collectors match \"{}\"   \u{2022}   Esc to clear",
            search_term
        );
        f.render_widget(
            Paragraph::new(Span::styled(empty_msg, Style::default().fg(TEXT_DIM)))
                .alignment(Alignment::Center),
            main_area,
        );
        f.render_widget(
            Paragraph::new("Type to filter  \u{2022}  Down/Tab switch panel  \u{2022}  Esc clear")
                .style(Style::default().fg(TEXT_DIM))
                .alignment(Alignment::Center),
            help_area,
        );
        return;
    }

    // ── Split into left (categories) and right (items) ───────────
    let h_split =
        Layout::horizontal([Constraint::Percentage(30), Constraint::Percentage(70)])
            .split(main_area);
    let left_area = h_split[0];
    let right_area = h_split[1];

    // ── Left panel: visible categories ───────────────────────────
    let cat_focused = app.collector_focus == CollectorFocus::Categories;

    let visible_cat_pos = visible_cats
        .iter()
        .position(|&c| c == app.collector_category_cursor)
        .unwrap_or(0);

    let mut cat_items: Vec<ListItem> = Vec::new();
    for &cat_idx in &visible_cats {
        let (_, cat_name) = COLLECTOR_CATEGORIES[cat_idx];
        let sel = app.selected_in_category(cat_idx);
        let (start, end) = app.category_bounds(cat_idx);
        let total = end.saturating_sub(start);
        let is_selected_cat = cat_idx == app.collector_category_cursor;

        let num = cat_idx + 1;
        let count_str = format!("{}/{}", sel, total);
        let label = format!("{}.{:<22} {:>5}", num, cat_name, count_str);

        let mut style = Style::default().fg(TEXT_NORMAL);
        if is_selected_cat {
            style = if cat_focused {
                Style::default().fg(AMBER).add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(AMBER)
            };
            style = style.patch(Style::default().bg(BG_SELECTED));
        }

        cat_items.push(ListItem::new(Line::from(Span::styled(label, style))));
    }

    let cat_block = Block::bordered()
        .border_type(BorderType::Rounded)
        .border_style(if cat_focused {
            Style::default().fg(CYAN)
        } else {
            Style::default().fg(BORDER_SUBTLE)
        })
        .title(Line::from(vec![Span::styled(
            " Categories ",
            Style::default().fg(if cat_focused { CYAN } else { CYAN_DIM }),
        )]));

    let mut cat_state = ListState::default();
    cat_state.select(Some(visible_cat_pos));

    f.render_stateful_widget(
        List::new(cat_items)
            .block(cat_block)
            .highlight_symbol("▸ ")
            .highlight_style(Style::default()),
        left_area,
        &mut cat_state,
    );

    // ── Right panel: visible items in selected category ───────────
    let item_focused = app.collector_focus == CollectorFocus::Items;
    let visible_items = app.visible_items_in_category(app.collector_category_cursor);
    let cat_name = COLLECTOR_CATEGORIES[app.collector_category_cursor].1;

    let item_block = Block::bordered()
        .border_type(BorderType::Rounded)
        .border_style(if item_focused {
            Style::default().fg(CYAN)
        } else {
            Style::default().fg(BORDER_SUBTLE)
        })
        .title(Line::from(vec![Span::styled(
            format!(" {} ", cat_name),
            Style::default().fg(if item_focused { CYAN } else { CYAN_DIM }),
        )]));

    let mut item_list: Vec<ListItem> = Vec::new();
    for &i in &visible_items {
        let (_, label) = &app.collector_items[i];
        let checked = app.collector_selected.contains(&i);
        let focused = i == app.collector_cursor;

        let checkbox = if checked { "[✓]" } else { "[ ]" };
        let checkbox_style = if checked {
            Style::default().fg(GREEN).add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(TEXT_DIM)
        };
        let name_style = if focused && item_focused {
            Style::default().fg(AMBER).add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(TEXT_NORMAL)
        };

        let parts: Vec<&str> = label.splitn(2, '(').collect();
        let name = parts[0].trim();
        let desc = if parts.len() > 1 {
            format!("({}", parts[1])
        } else {
            String::new()
        };

        let mut line_spans = vec![
            Span::styled(format!("{} ", checkbox), checkbox_style),
            Span::styled(format!("{:<28}", name), name_style),
        ];
        if !desc.is_empty() {
            line_spans.push(Span::styled(desc, Style::default().fg(TEXT_DIM)));
        }

        let mut item = ListItem::new(Line::from(line_spans));
        if focused && item_focused {
            item = item.style(Style::default().bg(BG_SELECTED));
        }
        item_list.push(item);
    }

    let local_cursor = visible_items
        .iter()
        .position(|&i| i == app.collector_cursor)
        .unwrap_or(0);

    let mut item_state = ListState::default();
    item_state.select(Some(local_cursor));

    f.render_stateful_widget(
        List::new(item_list)
            .block(item_block)
            .highlight_symbol("")
            .highlight_style(Style::default()),
        right_area,
        &mut item_state,
    );

    // ── Help text ─────────────────────────────────────────────────
    let help_text = match app.collector_focus {
        CollectorFocus::Search => {
            "Type to filter  \u{2022}  Down/Tab switch panel  \u{2022}  Esc clear"
        }
        CollectorFocus::Categories => {
            if has_search {
                "↑↓ navigate • 1-9 jump • Tab/→ switch panel • Space toggle category • a/d all/none  •  Tab → search"
            } else {
                "↑↓ navigate • 1-9 jump • Tab/→ switch panel • Space toggle category • a/d all/none"
            }
        }
        CollectorFocus::Items => {
            if has_search {
                "↑↓ navigate • Space toggle • a/d all/none • Tab/← switch panel • Enter confirm  •  Tab → search"
            } else {
                "↑↓ navigate • Space toggle • a/d all/none • Tab/← switch panel • Enter confirm"
            }
        }
    };

    f.render_widget(
        Paragraph::new(help_text)
            .style(Style::default().fg(TEXT_DIM))
            .alignment(Alignment::Center),
        help_area,
    );
}
```

- [ ] **Step 2: Compile check**

```bash
cd /Users/austin-songer/code/grabber && cargo check 2>&1 | head -30
```

Expected: zero errors. Common issues:
- "cannot find value `CollectorFocus` in scope" → the `use super::{…}` import at the top of `ui.rs` (line 9) already imports `CollectorFocus`; no change needed there.
- "unused variable" warnings are fine.

- [ ] **Step 3: Run all tests**

```bash
cd /Users/austin-songer/code/grabber && cargo test 2>&1 | grep -E "test |FAILED|ok|error"
```

Expected: all tests pass.

- [ ] **Step 4: Manual smoke test**

Run the binary and navigate to the SelectCollectors screen:

```bash
cd /Users/austin-songer/code/grabber && cargo run 2>&1
```

Verify each of the following by hand:

| Scenario | Expected |
|----------|---------|
| Screen loads | Search bar visible at top; Categories and Items panels below |
| Press `Tab` | Focus cycles: Search → Categories → Items → Search |
| Type `iam` in Search | Left panel narrows to ~2 categories; right panel shows only IAM items; title shows `• N matches` |
| Press `Down` in Search | Focus moves to Categories panel |
| Navigate categories with `↑↓` | Skips hidden categories; right panel updates |
| Navigate items with `↑↓` past last item | Jumps to next visible category's first item |
| Navigate items with `↑↓` before first item | Jumps to previous visible category's last item |
| Press `Tab` from Items | Focus moves to Search |
| Press `Esc` in Search with text | Clears search; all categories/items return |
| Press `Esc` in Search when empty | Navigates back to previous screen |
| Type a term with no matches | Empty state message: `No collectors match "…"` |
| Type `a` in Search | Types the letter (does NOT trigger select-all) |
| Press `Space` in Items | Toggles item; count in title updates |
| Press `Enter` | Advances to SetOptions screen |

- [ ] **Step 5: Commit**

```bash
git add src/tui/ui.rs
git commit -m "feat(tui): update draw_collectors with search bar and filtered panels"
```

---

## Self-Review Checklist

**Spec coverage:**

| Requirement | Task |
|-------------|------|
| Search input field at top | Task 4 (search bar render) |
| Real-time filtering as user types | Task 3 (char → insert + clamp) + Task 4 (visible_items render) |
| Cross-category filtering ("iam" shows all IAM) | Task 2 (visible_categories) + Task 4 (left panel) |
| Two-panel layout; only matching categories shown | Task 4 (visible_cats loop in left panel) |
| Count display reflects filtered view | Task 4 (title with match_count) |
| Arrow key navigation through filtered results | Task 3 (Up/Down guards + auto-jump) |
| Clear button (✕) | Task 4 (search_label with ✕) |
| Works with existing selection mechanisms | Task 3 (Space/a/d guarded from Search, still use collector_selected) |

All 8 requirements are covered. No gaps.
