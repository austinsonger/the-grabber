# GitHub Evidence Provider — Design

**Goal:** Add GitHub as a first-class evidence-collection provider, following the exact architectural pattern established by Okta, Jira, and Tenable — a hand-rolled REST client crate plus a `src/providers/github` module of `CsvCollector` implementations, wired into the existing TUI/CLI plumbing.

**Architecture:** A new `crates/github-rs` workspace crate wraps the GitHub REST API (`Authorization: Bearer <PAT>` auth, RFC 5988 Link-header pagination, primary/secondary rate-limit retry). A new `src/providers/github` module implements `ProviderFactory` and produces collectors using the existing `CsvCollector` trait — **not** `JsonCollector`/`EvidenceCollector`; a survey of the current codebase shows every non-AWS provider (Okta: 24 collectors, Jira: 27, Tenable: 5) uses `CsvCollector` exclusively, with the `dates: Option<(i64,i64)>` parameter handling time-windowed data generically. GitHub-specific config lives in `github-config.toml` (gitignored), merged into `AppConfig` at startup exactly like `okta-config.toml`. The TUI gains a `Github` variant on `CloudProvider`, a `src/tui/menus/github.rs` category list, and a `ProviderSelection → SelectCollectors` transition with no intermediate picker screen — GitHub tenant scope (one org) is fixed in config, same as Okta's per-tenant domain, so no `TenableEndpoint`- or `JiraProjectSelection`-style extra screen is needed.

**Tech Stack:** Rust 1.75+, `reqwest` (rustls), `serde`/`serde_json`, `tokio`, `async_trait`, `wiremock` for HTTP tests. Optional Cargo feature `github`, matching the `okta`/`jira`/`tenable` feature-gating convention.

**Reference patterns to mirror:**
- API client + Link-header pagination: `crates/okta-rs/src/client.rs` (the `next_link` parser is copy-paste reusable — GitHub uses the identical RFC 5988 `Link: <url>; rel="next"` format)
- Rate-limit retry: `crates/okta-rs/src/client.rs::send_with_retry` (adapt header names: GitHub uses `X-RateLimit-Remaining` / `X-RateLimit-Reset` for primary limits and `Retry-After` for secondary/abuse limits, vs Okta's `X-Rate-Limit-Reset`)
- Provider factory + flat collector registration by string key: `src/providers/okta/factory.rs`
- TUI collector menu: `src/tui/menus/okta.rs` + `src/tui/menus/mod.rs`
- Account config fields + resolvers + config-file merge: `src/app_config.rs` Okta fields/methods (~line 184–246) and the `okta-config.toml` merge block (~line 311–319)
- TUI session account-prep block (build client + factory, no project/endpoint sub-selection): `src/runner/tui_session.rs` Okta block (~line 721–826) — simpler than Jira's block, which additionally threads project-key filtering
- Provider-switch nav wiring: `src/tui/app/nav.rs` Okta arms (simpler path, no extra screen) alongside the Jira/Tenable arms that do need one
- Provider tile on the picker screen: `src/tui/ui/account_screens.rs` Jira block (~line 50–54)
- Provider list construction: `src/tui/events.rs` (~line 741–744)

**Out of scope:**
- GitHub App authentication (JWT + installation tokens) — PAT only for this plan.
- Multi-org fan-out from a single account/token — one `[[account]]` entry = one org, matching Okta's per-tenant model. Multiple orgs = multiple account entries.
- FedRAMP requirement/control-ID mapping (`assets/fedramp-map.json`) — **every** baseline collector across every existing provider (all 6 Okta baseline collectors, all 5 Tenable collectors) ships with zero entries in that table; entries only exist for later, narrowly-purpose-built collectors added in dedicated follow-up plans (e.g. `docs/plans/2026-07-16-fedramp-okta-collectors.md`) engineered to satisfy one specific identified requirement gap. This plan follows that same precedent — no fedramp-map.json changes. A future `fedramp-github-collectors` plan can add requirement-driven collectors once specific gaps are identified.
- GitHub GraphQL API (e.g. SAML SSO identity provider config, which REST doesn't expose) — REST-only for this plan.
- Branch protection for non-default branches, or repository rulesets (the newer, more flexible replacement for classic branch protection) — classic branch-protection API on the default branch only.
- A repo/team picker TUI screen — collectors that need repo or team lists (branch protection, team membership) enumerate every repo/team in the org automatically when their collector key is selected, same as how Okta's group-members collector doesn't require hand-picking which groups.

---

## Collectors

All ten are `CsvCollector` implementations. Every endpoint that requires a GitHub plan feature the org may not have (Enterprise Cloud, Advanced Security) degrades to an **empty result on 403/404**, not a hard error — one missing feature must not fail the other nine collectors. This mirrors the existing 404→`Ok(vec![])` handling in `src/providers/okta/system_log.rs`.

| Key | Name | Endpoint(s) | Notes |
|---|---|---|---|
| `github-members` | Org Members | `GET /orgs/{org}/members?role=admin`, `?role=member`, `?filter=2fa_disabled` | Two role-filtered lists merged by login to attach a role column; the 2FA-disabled list needs an org-owner token — 403 → "unknown" instead of failing |
| `github-teams` | Org Teams | `GET /orgs/{org}/teams` | slug, name, privacy, permission, description |
| `github-team-members` | Team Membership | `GET /orgs/{org}/teams/{slug}/members` | Depends on the team list — enumerates every team returned by `github-teams`'s endpoint internally (not gated on that key being selected) |
| `github-security-settings` | Org Security Settings | `GET /orgs/{org}` | Single-row snapshot: `two_factor_requirement_enabled`, `default_repository_permission`, `members_can_create_repositories`, `members_can_create_private_repositories` |
| `github-repos` | Repositories | `GET /orgs/{org}/repos?type=all` | name, visibility, default_branch, archived, created_at, pushed_at |
| `github-branch-protection` | Branch Protection | `GET /repos/{owner}/{repo}/branches/{default_branch}/protection` | Depends on the repo list (same internal-enumeration approach as team membership). 404 → row with `protected=false`, not an error — most repos won't have protection configured |
| `github-audit-log` | Org Audit Log | `GET /orgs/{org}/audit-log?phrase=created:{start}..{end}` | **Requires GitHub Enterprise Cloud** — 403/404 → empty result. Time-windowed via the `dates` param, server-side filtered via `phrase`. 180-day retention on GitHub's side |
| `github-dependabot-alerts` | Dependabot Alerts | `GET /orgs/{org}/dependabot/alerts` | Requires Dependabot alerts enabled (Advanced Security or public repo). Client-side filter on `created_at` using `dates` |
| `github-secret-scanning-alerts` | Secret Scanning Alerts | `GET /orgs/{org}/secret-scanning/alerts` | Requires secret scanning enabled. Client-side date filter |
| `github-code-scanning-alerts` | Code Scanning Alerts | `GET /orgs/{org}/code-scanning/alerts` | Requires code scanning (e.g. CodeQL) configured. Client-side date filter |

**Default TUI selection:** `github-members`, `github-teams`, `github-team-members`, `github-security-settings`, `github-repos`, `github-branch-protection` are enabled by default (work on any GitHub plan with a valid PAT). `github-audit-log`, `github-dependabot-alerts`, `github-secret-scanning-alerts`, `github-code-scanning-alerts` are **opt-in** by default (added to `hardcoded_optins` in `src/tui/app/mod.rs`) since they depend on plan/feature availability the token owner may not have — same treatment as `tenable-was`/`tenable-pci-asv`, which need specific Tenable product licenses.

**TUI menu categories** (`src/tui/menus/github.rs`):
- **Access Control**: Org Members, Org Teams, Team Membership, Org Security Settings
- **Repositories & Change Control**: Repositories, Branch Protection
- **Audit & Security Alerts**: Org Audit Log, Dependabot Alerts, Secret Scanning Alerts, Code Scanning Alerts

---

## Auth & Config

- **Auth:** Personal Access Token (fine-grained or classic), sent as `Authorization: Bearer <token>`, plus `Accept: application/vnd.github+json` and `X-GitHub-Api-Version: 2022-11-28` on every request.
- **Deployment:** configurable base URL — `https://api.github.com` (GitHub.com, the default) or `https://{host}/api/v3` (GitHub Enterprise Server), mirroring Okta's per-tenant `okta_domain` field.
- **`Account` fields (`src/app_config.rs`):** `github_org: Option<String>`, `github_token: Option<String>`, `github_base_url: Option<String>` (defaults to `https://api.github.com` when unset).
- **Env var overrides** (env wins over TOML, same precedence as every other provider): `GITHUB_TOKEN`, `GITHUB_ORG`, `GITHUB_BASE_URL`.
- **`github-config.toml`** (gitignored): merged into `AppConfig.account` at startup if present, same merge block shape as `tenable-config.toml`/`okta-config.toml`/`jira-config.toml`.
- **`github-config.example.toml`**: committed template, same shape as `okta-config.example.toml`.

## Rate Limiting & Retry

GitHub's REST API signals rate limits two ways, both need handling in `crates/github-rs`'s `send_with_retry`:
1. **Primary limit exhausted:** HTTP 403 (or 429) with `X-RateLimit-Remaining: 0` — wait until the Unix-epoch-seconds value in `X-RateLimit-Reset`.
2. **Secondary/abuse limit:** HTTP 403 (or 429) with a `Retry-After` header (seconds) — wait that long.

Both follow the same shape as Okta's `X-Rate-Limit-Reset` handling — different header names, same wait-then-retry loop, capped at the same `MAX_RETRIES`/backoff structure.

## Testing

`wiremock`-based HTTP tests per API module in `crates/github-rs/tests/`, following the exact TDD shape used for `okta-rs`: mock the endpoint (including a paginated `Link` header response), assert the parsed struct fields, assert pagination is followed to completion, assert a 403/404 on a plan-gated endpoint produces an empty result rather than an error.
