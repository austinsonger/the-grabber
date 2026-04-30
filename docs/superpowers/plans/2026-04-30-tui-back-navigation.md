# TUI Back Navigation Fix Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix the two spots where the TUI wizard shows "Esc: Quit" or quits outright instead of going back to the previous screen.

**Architecture:** The back-navigation infrastructure (`prev_screen()`) is already fully implemented and wired to `KeyCode::Esc` on all wizard screens except `FeatureSelection`. Two hint strings in `get_hints()` are also mislabelled "Quit" when they should say "Back". This plan makes three surgical line-level edits — no new logic needed.

**Tech Stack:** Rust, Ratatui, Crossterm

---

## File Map

| File | Change |
|---|---|
| `src/tui/mod.rs` | 1 line: `FeatureSelection` Esc branch — quit → `prev_screen()` |
| `src/tui/ui.rs` | 2 lines: `get_hints()` hint text for `FeatureSelection` and `SelectAccount` — "Quit" → "Back" |

---

### Task 1: Fix FeatureSelection Esc handler in `mod.rs`

**Files:**
- Modify: `src/tui/mod.rs` (inside `handle_key()`, `Screen::FeatureSelection` arm)

Current code (search for this block):
```rust
Screen::FeatureSelection => match key {
    ...
    KeyCode::Enter | KeyCode::Char(' ') => app.next_screen(),
    KeyCode::Esc => return Action::Quit,
    _ => {}
},
```

- [ ] **Step 1: Make the edit**

Change:
```rust
KeyCode::Esc => return Action::Quit,
```
To:
```rust
KeyCode::Esc => app.prev_screen(),
```

`prev_screen()` already maps `FeatureSelection → Welcome` (see `prev_screen()` function, `Screen::FeatureSelection => Screen::Welcome` arm). No other changes needed.

- [ ] **Step 2: Build to confirm it compiles**

```bash
cargo build
```
Expected: no errors.

- [ ] **Step 3: Commit**

```bash
git add src/tui/mod.rs
git commit -m "fix(tui): FeatureSelection Esc now goes back to Welcome instead of quitting"
```

---

### Task 2: Fix mislabelled "Esc: Quit" footer hints in `ui.rs`

**Files:**
- Modify: `src/tui/ui.rs` (inside `get_hints()`)

The `SelectAccount` keyboard handler already calls `app.prev_screen()` on Esc — its hint just says the wrong thing. `FeatureSelection`'s hint will now also be wrong after Task 1 fixes the behavior.

- [ ] **Step 1: Fix FeatureSelection hint**

Find:
```rust
Screen::FeatureSelection => vec![("↑↓", "Navigate"), ("⏎", "Select"), ("Esc", "Quit")],
```
Change to:
```rust
Screen::FeatureSelection => vec![("↑↓", "Navigate"), ("⏎", "Select"), ("Esc", "Back")],
```

- [ ] **Step 2: Fix SelectAccount hint**

Find:
```rust
Screen::SelectAccount => vec![
    ("↑↓", "Navigate"),
    ("␣", "Toggle"),
    ("a", "All"),
    ("d", "None"),
    ("⏎", "Confirm"),
    ("Esc", "Quit"),
],
```
Change `("Esc", "Quit")` to `("Esc", "Back")`.

- [ ] **Step 3: Build to confirm it compiles**

```bash
cargo build
```
Expected: no errors.

- [ ] **Step 4: Commit**

```bash
git add src/tui/ui.rs
git commit -m "fix(tui): correct Esc footer hint from Quit to Back on FeatureSelection and SelectAccount"
```

---

## Manual Verification

- [ ] Launch the TUI
- [ ] Press Enter past Welcome → land on FeatureSelection; press **Esc** → should return to Welcome (previously quit the app)
- [ ] Press Enter → land on SelectAccount; press **Esc** → should return to FeatureSelection
- [ ] Advance to any later screen (SetDates, SelectCollectors, SetOptions, Confirm) and press **Esc** at each — each should step back one screen with all prior selections preserved
- [ ] Confirm footer on FeatureSelection shows **"Esc: Back"** (not "Esc: Quit")
- [ ] Confirm footer on SelectAccount shows **"Esc: Back"** (not "Esc: Quit")
- [ ] Confirm Welcome screen still shows **"Esc: Quit"** (correct — no previous screen exists)
