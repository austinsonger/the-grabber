# Changelog

All notable changes to The Grabber are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- **Named AWS profiles were ignored when the shell held its own credentials.**
  Configs were built with `aws_config::defaults().profile_name(…)`, which only
  tells the *default credential chain* which profile to read. Environment
  variables rank ahead of the profile in that chain, so with
  `AWS_ACCESS_KEY_ID` / `AWS_SESSION_TOKEN` exported — as `assume`, `granted`,
  `aws-vault` and similar tools do — every profile silently resolved to whatever
  the shell already held.

  In a multi-account run this corrupted the evidence rather than failing it: one
  account's assets were written under all the other accounts' names, and nothing
  in the output said so. A run selecting five accounts produced one account's
  inventory repeated five times, at a row count plausible enough to look correct.

  Configs built from a named profile now attach an explicit
  `ProfileFileCredentialsProvider`, taking the environment out of the decision.
  A profile now always resolves to its own account.

  This affected both the CLI and the TUI wizard.

- **Unauthenticated accounts could be silently replaced by the shell's account.**
  When a profile failed to resolve, collection fell back to ambient shell
  credentials. That is reasonable for a single-account run and wrong for a
  multi-account one, where it attributes the shell account's assets to whichever
  profile failed. Multi-account inventory no longer falls back; an
  unauthenticated profile is skipped with a warning naming it, and the run
  continues against the rest.

- **The same account could be inventoried twice.** Two profiles may be different
  roles into one account (for example `org:OpsAdmin-123456789012` and
  `other:OpsAdmin-123456789012`). Both being collected duplicated every row.
  Targets are now deduplicated by the account ID STS reports, with a warning
  naming the profile that was skipped and the one that claimed the account.

### Added

- **`--accounts <pattern>[,<pattern>…]`** — run inventory against every AWS
  profile matching the patterns, merged into one CSV/XLSX. Profiles are
  discovered from `~/.aws/config` and `~/.aws/credentials`, so the account set
  tracks whatever the operator actually has; nothing is read from `config.toml`
  and nothing is hardcoded.

  Patterns match profile names case-insensitively and accept `*` as a wildcard
  anywhere:

  ```bash
  grabber --inventory --accounts 'fed:*'
  grabber --inventory --accounts 'prod-*,staging-*'
  grabber --inventory --accounts '*SecurityAdmin*'
  ```

  A pattern matching no profile is a hard error that lists the profiles which do
  exist. Silently producing a short inventory because of a typo would be a bad
  evidence artifact.

  Requires `--inventory`. Cannot be combined with `--profile` (profiles come from
  the patterns) or `--inventory-all-accounts`.

- **`--accounts-dry-run`** — print the profiles a pattern matches and exit
  without calling AWS, to check a pattern before starting a long multi-account
  collection.

### Changed

- Inventory collection across accounts is now one shared code path. The
  `--inventory-all-accounts` (config.toml-driven) and `--accounts`
  (profile-driven) modes differ only in how they resolve the account list, so
  region handling, row merging, and skip/dedup reporting cannot drift apart.

- AWS config construction is centralised in `aws_loader::cli_config_loader()`.
  The TUI previously built configs inline in five places, each carrying its own
  copy of the profile-selection logic and therefore its own copy of the bug
  above. It returns a loader rather than a loaded config, preserving the
  existing constraint that a config which has made an AWS call must not be
  reused for building collectors.

- The write/zip/sign tail shared by every inventory entry point is now a single
  `finalize_inventory_outputs()` helper instead of three copies.

### Notes for operators

- `--inventory-all-accounts` is unchanged and still collects every AWS account in
  `config.toml`. Use `--accounts` when you want a subset, or when you would
  rather not maintain a `config.toml` at all.

- Credential-brokering tools such as `assume` keep their own token cache and
  export credentials into the shell for **one** profile at a time; running them
  repeatedly replaces the previous credentials rather than accumulating them.
  They do not give the AWS SDK usable sessions for other profiles. For a
  multi-account run, log the SDK in directly — one call covers every profile
  sharing that session:

  ```bash
  aws sso login --sso-session <session-name>
  ```

  With the fix above, exported shell credentials no longer interfere either way.
