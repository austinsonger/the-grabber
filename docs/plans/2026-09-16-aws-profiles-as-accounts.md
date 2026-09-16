# AWS profiles as accounts when no config.toml exists

## Goal

Run `grabber` from any directory with no `config.toml`. The account picker lists
every profile in `~/.aws/config`. Select all with `a`. A single `assume` covers
every account through the Granted credential fallback (already uncommitted in
`src/aws_loader.rs`).

## Current behaviour

- `load_config()` (`src/app_config.rs`) reads `./config.toml`, then
  `~/.config/evidence/config.toml`. If neither exists it returns `None`.
- When `None` is returned, the TUI uses `AppConfig::default()`: no accounts, so
  `has_accounts()` is false and the wizard shows the single-profile picker.
- The sibling provider files (`tenable-config.toml` and so on) are merged only
  after a primary config loads, so without one they're ignored.
- `--inventory-all-accounts` bails without a config.
- `--inventory --accounts 'fed:*'` already works without config (CLI only).
- The TUI prep loop (`src/runner/tui_session.rs`) does **not** skip duplicate
  account IDs. The CLI (`collect_inventory_across_targets`) does.

## Changes

### 1. Accounts from AWS profiles (`src/app_config.rs`)

- Add a third lookup step to `load_config()`. If neither config file exists,
  build `AppConfig { account, ..Default::default() }` from
  `crate::credentials::aws_profiles::detect_aws_profiles()`.
- Each profile except `default` becomes one account:
  - `name`: the profile name
  - `profile`: the profile name
  - `region`: the profile's `region`, if it has one
  - `account_id`: `crate::aws_loader::expected_account_id(name)`
  - `provider`: AWS (serde default)
- `Account` doesn't derive `Default`, so build each one as a `toml::Table` and
  `try_into::<Account>()`. That avoids listing every optional field.
- Rework the existing early `?` returns so the sibling provider merges still run
  when accounts came from AWS profiles.
- Update the `load_config()` doc comment to describe the three-step lookup.

If a `config.toml` exists, nothing changes. It always wins.

### 2. Skip duplicate accounts in the TUI (`src/runner/tui_session.rs`)

`fed:*` and `corp:*` profiles can reach the same account, and selecting all
would collect it twice. Once the credential check resolves the real account ID,
keep a `HashMap<account_id, profile>`. If the ID was already seen, log
`↷ Skipped: account <id> already collected via <profile>` and `continue`, the
same way the CLI path does.

### 3. Output directory

With no `output_dir`, multi-account runs already write to
`<base>/<sanitized name>`. Sanitizing maps `fed:OpsAdmin-187940674018` to
`fed_OpsAdmin-187940674018`. That's acceptable, so no change.

## Tests

- `app_config`: write a temporary AWS config with one SSO profile and one
  `default` profile, then point `AWS_CONFIG_FILE` / `AWS_SHARED_CREDENTIALS_FILE`
  at it. Assert one account comes back with the right name, profile, region and
  `account_id`. Because it sets environment variables, keep it as the only test
  in its module that touches them.
- The TUI deduplication runs against live STS, so it's exempt from unit tests.
  Verify it manually.

## Docs

- `CHANGELOG.md` → Added: "With no config.toml, AWS profiles become accounts."
- `README.md` config section: one paragraph on the fallback.

## Manual verification

1. Move `config.toml` aside (or run from `/tmp`).
2. `assume fed:SecurityAdmin-132576345808`.
3. `cargo build --release`, then run `target/release/grabber`, choose
   Inventory, press `a`, and continue.
4. Expect `Credentials OK via Granted` for each `fed:` and `corp:` profile,
   duplicate-account skips where two profiles share an account, and one
   inventory CSV containing multiple account IDs.

## Out of scope

- Per-account collector overrides and `output_dir` (still need `config.toml`).
- Reading the sibling provider configs from `~/.config/evidence/`.

## Prerequisite

The disk is full (about 300 MB free, `target/` is 35 GB). Run `cargo clean`
before building.
