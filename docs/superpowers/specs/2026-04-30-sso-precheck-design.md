# SSO Session Pre-Check Feature — Design Spec

**Date:** 2026-04-30  
**Status:** Approved

---

## Summary

Before the TUI opens, perform a concurrent `STS GetCallerIdentity` call for each configured AWS profile. Store results in `App`. Display a session-status summary on the Welcome screen — how many profiles have active sessions — and a scrollable list of inactive accounts with the exact `aws sso login` command the user needs to run.

---

## Architecture

```
async_main()
  │
  ├─ read_aws_profiles()                        [existing, unchanged]
  ├─ check_sso_sessions(&accounts, &profiles)   [NEW: sso_check.rs]
  │    └─ tokio::join_all per-profile STS call  [concurrent, 3s timeout each]
  │         returns Vec<SsoCheckResult>
  │
  ├─ App::new(profiles, sso_checks)             [modified: takes sso_checks]
  │    └─ stores sso_checks in App field
  │
  └─ run_tui(app)
       └─ draw_welcome(f, area, app)            [modified: accepts &App]
            ├─ existing: logo, title, description, CTA
            ├─ NEW: "X/Y profiles active" badge
            └─ NEW: scrollable inactive-account list + aws sso login hint
```

The check runs before `setup_terminal()`, so the terminal is still in normal mode. A single stdout line (`Checking sessions…`) is printed during the wait. Once the TUI opens in alternate screen mode that line is no longer visible.

No new crate dependencies are needed — `aws-sdk-sts` is already in `Cargo.toml`.

---

## Module: `src/sso_check.rs`

### Types

```rust
pub enum SsoStatus {
    Active { account_id: String, arn: String },
    Expired,   // STS returned an auth error (ExpiredTokenException, InvalidClientTokenId, etc.)
    Unknown,   // timeout, network failure, or misconfigured profile
}

pub struct SsoCheckResult {
    pub profile: String,       // AWS CLI profile name, e.g. "corp:ProdAdmin-178355776554"
    pub display_name: String,  // Human label: account name from config.toml, or == profile
    pub status: SsoStatus,
}
```

### Function signature

```rust
pub async fn check_sso_sessions(
    accounts: &[Account],
    legacy_profiles: &[String],
) -> Vec<SsoCheckResult>
```

### Behaviour

- When `accounts` is non-empty (TOML-configured mode), check those profiles. The `display_name` comes from `account.name`.
- When `accounts` is empty (legacy mode), check all entries in `legacy_profiles`. The `display_name` equals the profile string.
- For each profile: load an `aws_config::from_env().profile_name(profile).load().await` SDK config, build an `StsClient`, and call `get_caller_identity`.
- Each call is wrapped in `tokio::time::timeout(Duration::from_secs(3), …)`.
- Error classification:
  - Timeout → `Unknown`
  - STS error containing `ExpiredToken`, `InvalidClientTokenId`, or `NotAuthorized` → `Expired`
  - Any other error → `Unknown`
- The function never returns `Err` — every profile always produces a result.
- All futures are spawned with `tokio::join_all` for full concurrency.

---

## Changes to `App` (`src/tui/mod.rs`)

### New fields on `App`

```rust
pub sso_checks: Vec<SsoCheckResult>,
pub welcome_scroll: usize,
```

### `App::new` signature change

```rust
pub fn new(profiles: Vec<String>, config: AppConfig, sso_checks: Vec<SsoCheckResult>) -> Self
```

The `sso_checks` parameter is stored directly. No logic inside `App::new` depends on the check results.

### Key handling for `Screen::Welcome`

Add `Up`/`Down` handlers that move `welcome_scroll`. Clamped to the number of inactive+unknown results minus the visible rows (minimum 0). Scroll state is reset in `App::reset()`.

---

## Changes to `async_main` (`src/main.rs`)

```
1. Parse CLI args (existing)
2. read_aws_profiles() → profiles          (existing)
3. load_config() → config                  (called once here; result passed into App::new)
4. eprintln!("Checking SSO sessions…")
5. check_sso_sessions(&config.accounts, &profiles).await → sso_checks
6. App::new(profiles, config, sso_checks)  (modified signature)
```

`load_config()` is currently called inside `App::new`. It is moved to `async_main` and called exactly once before the SSO check. `App::new` is changed to accept `AppConfig` directly, removing the internal `load_config()` call.

---

## Welcome Screen Rendering (`src/tui/ui.rs`)

### Signature change

```rust
fn draw_welcome(f: &mut Frame, area: Rect, app: &App)
```

The callsite in `draw()` is updated accordingly.

### Layout additions

The existing layout rows are preserved. Two new layout sections are appended below the CTA:

1. **Session status badge** — one line:
   - `X` = count of `Active` results; `Y` = total profiles checked (Active + Expired + Unknown)
   - All active (`X == Y`): `"✓  X/Y profiles have active sessions"` in green
   - Any non-active (`X < Y`): `"⚠  X/Y profiles have active sessions"` in amber
   - Hidden entirely when `sso_checks` is empty (no profiles found at all)

2. **Inactive account list** — shown only when at least one profile is `Expired` or `Unknown`:
   - Bordered box with title `" Accounts needing login "`
   - Each row: `profile-name   →   aws sso login --profile <profile>`
   - `Expired` rows in amber; `Unknown` rows in dim text with `(check network/config)` suffix
   - Scrollable with `↑`/`↓` keys; scroll indicator shown if list overflows
   - The list height is capped at 6 visible rows to preserve the Welcome screen's compact feel

### Scroll state

`welcome_scroll` is reset to `0` in `App::reset()` and whenever the Welcome screen is re-entered.

---

## Error Handling

| Condition | Behaviour |
|---|---|
| Profile doesn't exist in `~/.aws/config` | `Unknown` — shown in dim text |
| Network unreachable (all checks timeout) | All `Unknown` — TUI still opens normally |
| All checks fail | Badge shows "0/N active" in amber; user can still proceed |
| `Unknown` profiles | Not counted in the "needs login" total; shown separately with a dim note |

The pre-check is purely informational. It never blocks the user from proceeding. `Enter` on the Welcome screen always advances regardless of session state.

---

## Files Changed

| File | Change |
|---|---|
| `src/sso_check.rs` | New module |
| `src/main.rs` | Add module declaration, call `check_sso_sessions`, pass result to `App::new`; move `load_config()` call before `App::new` |
| `src/tui/mod.rs` | Add `sso_checks` + `welcome_scroll` fields; update `App::new` signature; add Welcome scroll key handlers; reset scroll in `App::reset()` |
| `src/tui/ui.rs` | Update `draw_welcome` signature and callsite; add badge + scrollable inactive list |
