# Provider Selection screen redesign — list + detail panel

## Problem

The "Select a cloud provider" screen (Step 1 of 7, `Screen::ProviderSelection`) renders
each provider as a fixed-height (5-row) bordered card, manually stacked vertically with
raw `Rect` math in `draw_provider_selection` (`src/tui/ui/account_screens.rs:17-151`).
The card stack is centered by two `Fill(1)` layout chunks but the card region itself is a
fixed `Constraint::Length(total_cards_height)` — there is no scrolling, clipping, or
overflow handling anywhere in the function. If `total_cards_height` exceeds the available
frame height, ratatui gives the `Fill(1)` chunks zero height and cards are pushed off
screen with no way to reach them.

Today 5 providers ship by default (AWS, Tenable, Okta, Jira, Elastic), 7 with
`--features azure,gcp`, and an 8th (JumpCloud) is planned
(`docs/plans/2026-07-17-add-jumpcloud-provider-plan.md`). Every additional provider adds
6 rows to a layout with no upper bound — this screen is on a fixed collision course with
its own frame height.

A second, related problem: the provider list is hand-duplicated in two places —
`draw_provider_selection` (render) and `handle_provider_selection`
(`src/tui/events.rs:855-898`, key handling) — each with its own copy of the
`#[cfg(feature = "...")]` push chain. A code comment at `events.rs:857-859` already flags
the risk: if the two lists ever drift out of order, arrow-key navigation desynchronizes
from the rendered rows.

`Screen::FeatureSelection` (`src/tui/ui/setup.rs::draw_feature_selection`, lines
102-199) uses the identical fixed-height manual-card pattern, copy-pasted from the same
origin. It has a fixed cardinality of 3 (Collectors/Inventory/POAM) so it isn't at
overflow risk today, but shares the duplicated rendering code.

## Goals

1. Provider Selection scales to an arbitrary number of providers with no layout
   overflow, using the auto-scrolling `List`/`ListState` pattern already established
   elsewhere in this TUI (`collectors.rs`, `scan_selection.rs`, `setup.rs`'s date/endpoint
   pickers).
2. Eliminate the provider-list duplication between render and event-handling code by
   introducing a single source of truth on `CloudProvider` itself.
3. Extract the shared list+detail rendering into one reusable component, and apply it to
   both Provider Selection and Feature Selection, removing the duplicated card-drawing
   code between the two screens.

## Non-goals

- No responsive/narrow-terminal breakpoint. The layout is always side-by-side
  (30/70 split), matching every other split-pane screen in this codebase
  (`collectors.rs`'s Categories/Items split), none of which special-case narrow
  terminals today.
- Not fixing the separate latent bug where selecting Azure or GCP would panic in
  `menu_for()` (`src/tui/menus/mod.rs:50-55`) because those providers have no
  `src/tui/menus/` entry yet. Found during investigation, unrelated to this layout work.
- Not adding JumpCloud or any other new provider. This only makes room for future ones.
- Not changing `Screen::FeatureSelection`'s cyclic (wrap-around) Up/Down navigation
  behavior — only its rendering is unified with Provider Selection.

## Design

### 1. Single source of truth: `CloudProvider::available()`

Add to `src/providers/mod.rs`, alongside the existing `impl fmt::Display for
CloudProvider`:

```rust
impl CloudProvider {
    /// Every provider compiled into this build, in canonical UI order.
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

    /// Long-form display name for the provider-selection UI, e.g.
    /// "Amazon Web Services (AWS)". Distinct from `Display`, which yields the
    /// short form ("AWS") used in filenames/report metadata.
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

    /// One-line description shown in the provider-selection detail panel.
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
            CloudProvider::Jira => "Collect projects and issues from Jira Cloud or Jira Server",
            CloudProvider::Elastic => {
                "Collect detection rules, exception items, alerts, and cases from Elastic SIEM"
            }
        }
    }
}
```

Text content is carried over verbatim from the current `draw_provider_selection` tuples
— no copy changes.

`draw_provider_selection` and `handle_provider_selection` both call
`CloudProvider::available()` instead of maintaining their own
`#[cfg(feature = "...")]` chains. The `events.rs:857-859` sync-drift comment and the risk
it describes are removed, not just documented around.

### 2. Shared `draw_list_with_detail` widget

New function in `src/tui/ui/widgets.rs`, next to `content_inset`:

```rust
pub(super) fn draw_list_with_detail(
    f: &mut Frame,
    area: Rect,
    list_title: &str,
    items: &[(String, String)], // (name, description)
    selected: usize,
)
```

Layout: `Layout::horizontal([Constraint::Percentage(30), Constraint::Percentage(70)])`
— same ratio as `collectors.rs`'s Categories/Items split (`collectors.rs:134`).

Unlike `collectors.rs`, there is no second focusable panel to tab into here — the list is
the only interactive element on screen, and the detail pane just mirrors whatever is
highlighted. So the border/title is always styled CYAN (the "focused" look in
`collectors.rs:172-182`), with no `focused` parameter to thread through.

- **Left pane**: `Block::bordered().border_type(BorderType::Rounded)`, CYAN border/title.
  Contents are a `List` of `ListItem`s, one per item, rendered via
  `render_stateful_widget` with a `ListState` whose `select()` is set to `selected`.
  Ratatui scrolls the viewport automatically as `selected` moves past the visible range
  — no manual height math, no overflow.
- **Right pane**: bordered "Details" block. Top line is the selected item's name in
  `TEXT_BRIGHT` + `Modifier::BOLD`; below (after a blank line) is the description in
  `TEXT_DIM`, wrapped via `Paragraph::wrap`.

This is the same visual language as the current cards (CYAN selection color, TEXT_DIM
descriptions) but restructured as list + persistent detail pane instead of N independent
bordered boxes.

### 3. Screen integration

**`draw_provider_selection`** (`account_screens.rs`): replace the manual card-loop body
with:

```rust
let providers = CloudProvider::available();
let items: Vec<(String, String)> = providers
    .iter()
    .map(|p| (p.display_name().to_string(), p.description().to_string()))
    .collect();
let selected = providers.iter().position(|p| *p == app.selected_provider).unwrap_or(0);
draw_list_with_detail(f, cards_area, "Providers", &items, selected);
```

Title/subtitle text ("Select a cloud provider:" / "Use ↑↓ to select a provider, then
press Enter") and the outer `Fill(1)`/title/subtitle layout chunks are unchanged; only
the card region (today's `chunks[4]`) is replaced.

**`draw_feature_selection`** (`setup.rs`): same treatment, keeping its existing fixed
3-item `[(Feature, name, description); 3]` array as the data source, mapped into the same
`(String, String)` shape and passed to `draw_list_with_detail`.

Footer hints (`frame.rs:369` and the Feature Selection equivalent) are unchanged —
`↑↓ Navigate  ⏎ Select  Esc Back` — since the interaction model (single-column list,
vertical movement only) doesn't change.

### 4. Event handling

**`handle_provider_selection`** (`events.rs`): replace the hand-rolled
`Vec<CloudProvider>` (lines 860-875) with `CloudProvider::available()`. The
clamped-cursor Up/Down logic (lines 877-888) and Enter/Esc handling are unchanged.

**`handle_feature_selection`**: unchanged. It cycles through the 3 `Feature` variants
with wraparound, which is a deliberately different (and fine) navigation feel for a
fixed 3-option screen — there's no cfg-gated list here to desync from, so there's nothing
to consolidate on the event-handling side.

## Files touched

- `src/providers/mod.rs` — add `CloudProvider::available()`, `.display_name()`,
  `.description()`.
- `src/tui/ui/widgets.rs` — add `draw_list_with_detail`.
- `src/tui/ui/account_screens.rs` — rewrite `draw_provider_selection` to use
  `CloudProvider::available()` + `draw_list_with_detail`.
- `src/tui/ui/setup.rs` — rewrite `draw_feature_selection` to use
  `draw_list_with_detail`.
- `src/tui/events.rs` — `handle_provider_selection` uses `CloudProvider::available()`.

No changes to `src/tui/state.rs` (`Screen` enum) or `App` state fields
(`selected_provider`, `provider_cursor`, `selected_feature`) — this is a rendering and
data-source change, not a new screen or new navigation state.
