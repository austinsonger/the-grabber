# KnowBe4 Provider — Design

**Status:** Approved 2026-07-19. Feeds into `docs/plans/2026-07-19-add-knowbe4.md`.

## Goal

Add KnowBe4 (security awareness training / phishing simulation SaaS) as a first-class evidence-collection provider, following the same shape as the existing Okta and Jira integrations: a hand-rolled API client crate, a `ProviderFactory` implementation, config-file-driven credentials, and TUI wiring — no new architectural concepts.

## Why Okta is the reference pattern (not Tenable or Jira)

- Auth is a single static credential (API key), like Okta's SSWS token — not Jira's email+token Basic auth, not Tenable's access+secret key pair.
- No sub-resource selection concept — KnowBe4 doesn't need Jira's project-picker screen or Tenable's endpoint/scan-selection screens. Every KnowBe4 collector operates account-wide.
- Credentials come exclusively from a gitignored `knowbe4-config.toml` (merged at startup), like `okta-config.toml`/`jira-config.toml`. No interactive credential-entry TUI screen.

The one addition beyond Okta's shape: KnowBe4's Reporting API is split across five regional hosts (`{region}.api.knowbe4.com` for us/eu/ca/uk/de), so the client needs a region concept that Okta (single per-tenant domain) doesn't.

## Data scope (confirmed)

All four KnowBe4 data domains, as eight collectors:

| Collector key | Default | Time-windowed | Notes |
|---|---|---|---|
| `knowbe4-users` | on | no | roster + `current_risk_score` snapshot field |
| `knowbe4-groups` | on | no | group/org-unit listing |
| `knowbe4-group-members` | **opt-in** | no | O(n) API calls, one per group — mirrors Okta's own `okta-group-members` opt-in precedent |
| `knowbe4-risk-score-history` | **opt-in** | yes | O(n) API calls, one per user — explicit user decision |
| `knowbe4-phishing-campaigns` | on | no | campaign-level summaries |
| `knowbe4-phishing-test-recipients` | on | yes | per-recipient phishing simulation results |
| `knowbe4-training-campaigns` | on | no | assigned training campaign summaries |
| `knowbe4-training-enrollments` | on | yes | per-user training completion status |

"Time-windowed" means the collector honors the `dates: Option<(i64,i64)>` param already on `CsvCollector::collect_rows`, filtering client-side on the resource's own timestamp field (KnowBe4's Reporting API has no documented server-side date-range query parameter). No range provided → default to the last 90 days, mirroring `OktaSystemLogCollector`'s fallback.

## Architecture

```
crates/knowbe4-rs/          new workspace crate — REST client
src/providers/knowbe4/      new provider module — ProviderFactory + 8 collectors
src/providers/mod.rs        + CloudProvider::Knowbe4 variant
src/app_config.rs           + Account fields, resolvers, knowbe4-config.toml merge
src/tui/menus/knowbe4.rs    new — TUI collector catalog (3 categories, 8 items)
src/tui/menus/mod.rs        + PROVIDER_MENUS entry
src/tui/app/nav.rs          + route Knowbe4 through ProviderSelection/SelectCollectors like Okta
src/tui/app/mod.rs          + knowbe4-group-members, knowbe4-risk-score-history in hardcoded_optins
src/tui/ui/account_screens.rs  + provider selection card
src/runner/tui_session.rs   + Knowbe4 account preparation block
assets/fedramp-map.json     + mappings for phishing-test-recipients / training-enrollments
```

Feature-gated behind a new `knowbe4` Cargo feature, added to `default = [...]` alongside `tenable`/`okta`/`jira`.

### `knowbe4-rs` crate

Same dependency set as `okta-rs` (`reqwest` rustls-tls, `serde`, `serde_json`, `tokio` (time), `thiserror` 2, `anyhow`, `futures`, `url`, `chrono`).

- **`region.rs`**: `Knowbe4Region { Us, Eu, Ca, Uk, De }` (default `Us`), `base_url()` → `https://{region}.api.knowbe4.com`, `FromStr` for parsing the config string.
- **`client.rs`**: `Knowbe4Client::new(region: Knowbe4Region, api_key: &str) -> Result<Self, Knowbe4Error>`. Header `Authorization: Bearer <api_key>`. Pagination is `page`/`per_page=500` query params, looped until an empty page — different from Okta's `Link`-header pagination since KnowBe4's Reporting API doesn't use RFC 5988 links. Retry on HTTP 429 with pure exponential backoff (1s→2s→4s→8s→16s, cap 30s, 5 attempts) — no `X-Rate-Limit-Reset`-style header to honor (undocumented for this API), unlike Okta.
- **`error.rs`**: `Knowbe4Error` — same shape as `OktaError` (`Http`, `Header`, `Json`, `Url`, `Api{status,message}`).
- **`api/{users,groups,phishing,training}.rs`** + **`types/{user,group,phishing,training,common}.rs`**: one API-accessor module and one types module per resource family, mirroring `okta-rs`'s `api/`/`types/` split.

### `src/providers/knowbe4/`

`factory.rs` (`Knowbe4ProviderFactory`, `csv_collectors()` only — `json_collectors()`/`evidence_collectors()` return empty `Vec`, matching Okta). Five collector files, pairing tightly-coupled resources in one file the way Okta's `groups.rs` holds both `OktaGroupsCollector` and `OktaGroupMembersCollector`:

- `users.rs` → `knowbe4-users`
- `groups.rs` → `knowbe4-groups`, `knowbe4-group-members`
- `risk_score_history.rs` → `knowbe4-risk-score-history`
- `phishing.rs` → `knowbe4-phishing-campaigns`, `knowbe4-phishing-test-recipients`
- `training.rs` → `knowbe4-training-campaigns`, `knowbe4-training-enrollments`

### Config

`Account` gains `knowbe4_api_key: Option<String>` and `knowbe4_region: Option<String>`, with `knowbe4_api_key_resolved()` (env `KNOWBE4_API_KEY` wins over TOML) and `knowbe4_region_resolved() -> Knowbe4Region` (env `KNOWBE4_REGION`; unrecognized or missing value defaults to `Us`, matching the existing infallible-resolver style used by `okta_domain_resolved`/`tenable_url_resolved` — no new fallible path introduced). `load_config()` gets a `knowbe4-config.toml` merge block identical in shape to the Tenable/Okta/Jira ones. New `knowbe4-config.example.toml` at repo root; `.gitignore` gets `knowbe4-config.toml`.

### TUI

No new `Screen` variant. `ProviderSelection → next` routes `Knowbe4` the same way Okta/Jira are routed today (`auto_select_provider_accounts(); clamp_collector_cursors(); Screen::SelectCollectors`), `SelectCollectors → prev` adds `Knowbe4` to the existing Okta/Jira check, and `validate_current`'s `ProviderSelection` arm gets a `#[cfg(feature = "knowbe4")]` "no accounts configured" guard identical in shape to Okta's. `SelectCollectors → next` needs no change — it already falls through to `SetOptions` for any provider that isn't Tenable or Jira-with-`jira-issues`-selected.

## FedRAMP mapping

Looked up directly in `assets/fedramp-map.json`'s `requirements` section (not fabricated):

| Collector | req_ids | control_ids |
|---|---|---|
| `Knowbe4_Training_Campaigns` | `NIST-1113` | `AT-02a.01[01][03]` |
| `Knowbe4_Training_Enrollments` | `NIST-1113` | `AT-02a.01[01][03]` |
| `Knowbe4_Phishing_Campaigns` | `NIST-1116` | `AT-02b.` |
| `Knowbe4_Phishing_Test_Recipients` | `NIST-1116`, `NIST-1120` | `AT-02b.`, `AT-02(03)` |

`Knowbe4_Users`, `Knowbe4_Groups`, `Knowbe4_Group_Members`, `Knowbe4_Risk_Score_History` get no `fedramp-map.json` entry, matching the precedent that core inventory collectors (`Okta_Users`, `Okta_Groups`, etc.) are also unmapped — `bundled().get()` returns an empty `FedRampMapping` for them safely.

## Error handling

404 responses from list endpoints return an empty `Vec` (matches every existing Okta collector's `Err(OktaError::Api { status: 404, .. }) => return Ok(vec![])` pattern). All other errors propagate via `anyhow`. No `unwrap`/`expect` in production code.

## Known unknowns / assumptions

KnowBe4's Reporting API is not fully covered by fetchable public documentation (the developer portal is JS-rendered and the knowledge-base articles return 403 to automated fetches). Endpoint paths, auth scheme (Bearer token), pagination style (`page`/`per_page`), and the general shape of users/groups/phishing/training resources are corroborated by KnowBe4's own knowledge-base search snippets and general REST-API conventions, but exact JSON field names for some resources (e.g. whether a phishing security test's identifier key is `pst_id` vs `id`) are best-effort. All `types/*.rs` structs use `#[serde(default)]` on non-critical fields so unexpected/missing JSON keys don't break deserialization — the plan calls out where field names should be verified against a live/sandbox KnowBe4 account during implementation and adjusted with `#[serde(rename = "...")]` if they differ.

## Testing

Per established project convention, no unit-test-writing steps. Each task is verified with `cargo check --features knowbe4`, `cargo clippy --features knowbe4 -- -D warnings`, and `cargo fmt`; the final task is a manual CLI/TUI smoke run. No wiremock suite is authored for `knowbe4-rs`.
