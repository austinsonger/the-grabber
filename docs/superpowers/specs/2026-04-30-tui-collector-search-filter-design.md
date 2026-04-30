# TUI Collector Search/Filter — Design Spec

**Date:** 2026-04-30  
**Status:** Approved  
**Scope:** `src/tui/mod.rs`, `src/tui/ui.rs`

---

## Problem

The SelectCollectors screen lists 126+ collectors across 12 categories. Finding a specific collector requires manually navigating every category. There is no way to search by name or keyword.

---

## Approach

Option B — filter-in-place two panels. Keep the existing two-panel layout (categories left, items right). Add a search bar above the panels. When search is active, the left panel narrows to only categories that contain matches; the right panel narrows to only matching items within the focused category. The two-panel navigation model is otherwise unchanged.

---

## State Changes (`src/tui/mod.rs`)

### `CollectorFocus` — new variant

```rust
pub enum CollectorFocus {
    Search,      // NEW: search box at top has focus
    Categories,
    Items,
}
```

### `App` — new field

```rust
pub collector_search: TextInput,
```

Initialized to `TextInput::default()` in `App::new()`.  
Cleared in `App::reset()`.

### New helper methods on `App`

| Method | Returns | Purpose |
|--------|---------|---------|
| `search_matches_item(global_idx: usize) -> bool` | `bool` | Case-insensitive substring match on item key + label. Returns `true` when search is empty. |
| `visible_categories() -> Vec<usize>` | `Vec<usize>` | Category indices that have ≥1 matching item. Returns all categories when search is empty. |
| `visible_items_in_category(cat_idx: usize) -> Vec<usize>` | `Vec<usize>` | Global item indices within a category that pass the current filter. |
| `clamp_collector_cursors()` | `()` | After search text changes, snaps `collector_category_cursor` to the first visible category (if current is no longer visible) and `collector_cursor` to the first visible item in that category. |

---

## Key Handling (`handle_key` → `Screen::SelectCollectors`)

### Focus cycling

| Key | Behavior |
|-----|----------|
| `Tab` | `Search → Categories → Items → Search` |
| `Left` / `Right` | Toggle `Categories ↔ Items` only (unchanged for existing users) |

### Search focus

| Key | Behavior |
|-----|----------|
| Printable char | `collector_search.insert(c)` then `clamp_collector_cursors()` |
| `Backspace` | `collector_search.backspace()` then `clamp_collector_cursors()` |
| `Left` / `Right` | Move text cursor within search value |
| `Down` | Move focus to `Categories` |
| `Esc` | Clear `collector_search`; stay on Search focus. Second `Esc` = prev screen (unchanged). |

### Category navigation when search active

`Up`/`Down` navigate only through `visible_categories()`. Moving to a new category snaps `collector_cursor` to the first visible item in that category.

### Item navigation when search active

`Up`/`Down` navigate only through `visible_items_in_category(current_cat)`.

**Auto-jump at category boundaries:**
- `Down` at last match in category → advance `collector_category_cursor` to the next visible category, set `collector_cursor` to its first visible item.
- `Up` at first match in category → retreat `collector_category_cursor` to the previous visible category, set `collector_cursor` to its last visible item.

### Guard fix

`'a'` / `'d'` shortcut handlers add guard `&& app.collector_focus != CollectorFocus::Search` so typing those letters in the search box does not trigger select-all / deselect-all.

Number-key category jump already guarded by `CollectorFocus::Categories` — no change needed.

---

## UI Rendering (`draw_collectors` in `src/tui/ui.rs`)

### Layout

```
inner area (vertical split):
  [0]  search bar         3 rows
  [1]  main panels        Fill(1)
  [2]  separator          1 row
  [3]  help text          1 row
```

Main panels horizontal split unchanged: 30% categories / 70% items.

### Search bar

- Rendered using `draw_text_field`
- Label: `" 🔍 Search collectors… "` when empty
- When search has content, label includes `" [✕ Esc to clear] "` hint
- Focused state: `app.collector_focus == CollectorFocus::Search`
- Terminal cursor positioned at `collector_search.cursor` (byte offset), not `value.len()` — the only place in the app that needs mid-string cursor placement. Inline the cursor call rather than relying on `draw_text_field`'s end-of-string default.

### Title count

| State | Title text |
|-------|-----------|
| No search | `" Collectors ─── X of Y selected "` |
| Search active | `" Collectors ─── X of Y selected  •  N matches "` |

Where N = total number of items passing the filter across all categories.

### Left panel — categories

- Only renders rows for indices in `visible_categories()`
- `ListState` selection index = position within the visible list (not the global category index)
- Row counts show `selected_in_category(cat_idx)` / `total_in_category` where `total_in_category` = ALL items in that category (not just filtered matches). This means `2/6` when 2 are selected and 6 exist, even if only 3 are visible due to the search. This preserves the existing count format exactly.

### Right panel — items

- Only renders items from `visible_items_in_category(collector_category_cursor)`
- `local_cursor` = position of `collector_cursor` within that filtered slice
- Panel title still shows the current category name

**Empty state:** when `visible_categories()` is empty (search term has no matches), render centered text in the items panel: `No collectors match "…"` with a dim hint `Esc to clear search`.

### Help text

| Focus | Text |
|-------|------|
| `Search` | `Type to filter  •  Down/Tab switch panel  •  Esc clear` |
| `Categories` or `Items`, search active | existing text + `  •  Tab → search` |
| `Categories` or `Items`, no search | unchanged |

---

## What Does NOT Change

- `collector_selected` logic — Space toggle, 'a', 'd' all operate on global indices as today.
- `validate_current` — still checks `collector_selected.is_empty()`.
- `selected_collectors()` — returns all selected regardless of search state.
- `COLLECTOR_CATEGORIES` constant — untouched.
- All other screens — no changes.

---

## Edge Cases

| Scenario | Behavior |
|----------|----------|
| Search term matches nothing | Empty state shown; both panels empty; `collector_cursor` unchanged |
| Search clears (Esc) | `clamp_collector_cursors()` runs; cursors stay at current position if still valid |
| Category with 0 matches | Hidden from left panel; if `collector_category_cursor` pointed here, snapped to first visible |
| Single matching item across all categories | Left panel shows 1 category; right panel shows 1 item; navigation works normally |
| Very long search term | Truncated by terminal width in the field label area; `TextInput` has no max length |
