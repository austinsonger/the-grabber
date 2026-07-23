# Spec: Add Jamf Provider

**Status:** Approved
**Author:** Austin Songer
**Date:** 2026-07-22
**Type:** Feature spec — implementation plan to follow

---

## Problem Statement

Grabber collects audit/compliance evidence from AWS, Azure, GCP, Tenable, Okta, Jira, and Elastic, but organizations that use **Jamf Pro** as their macOS/iOS/iPadOS device-management (MDM) platform have no way to include that evidence in a Grabber run. Auditors reviewing FedRAMP, SOC 2, HIPAA, or ISO controls for Jamf-managed endpoints (CM-6, CM-8, AC-19, SI-2) must pull evidence manually from the Jamf Pro console, which is slow, inconsistent, and breaks the single-run chain-of-custody guarantee Grabber provides for every other provider.

## Goals

1. **Ship a first-class Jamf provider** that plugs into the existing `ProviderFactory` contract with no changes to core collector plumbing.
2. **Cover device-inventory + configuration/compliance + policy/patch evidence** for Jamf Pro in the P0 release.
3. **Match Okta/JumpCloud parity for operator ergonomics** — same config-file pattern (`jamf-config.toml`, gitignored, merged at startup), same TUI selection flow, same file-naming/chain-of-custody/manifest behavior.
4. **Zero regressions** in existing providers — Jamf lives behind a Cargo feature (`jamf`) and only activates when a Jamf account is configured.
5. **Phase in Jamf Protect** (a separate EDR tenant/API) as P1 — designed now, built later as its own follow-on implementation effort.
6. **Documented in one pass** — README, `cli-examples.md`, and `docs/fedramp-coverage.md` all updated in the same PR that ships the P0 code.

## Non-Goals

1. **No writes to Jamf.** Grabber is read-only for every provider; Jamf is no exception. No policy pushes, MDM commands (remote wipe/lock), profile edits, or script deployment. *Rationale: preserves the single "collect, never mutate" invariant.*
2. **No Jamf Connect collector.** Jamf Connect is a client app configured via Jamf Pro configuration profiles — it has no standalone evidence API. Its relevant configuration surfaces through the `jamf-computer-config-profiles`/`jamf-mobile-config-profiles` collectors already; its authentication events live in the real identity provider (Okta/Azure AD/Google), not Jamf. *Rationale: no unique API surface to justify a separate client; documented here so the omission is deliberate.*
3. **No Jamf Protect in P0.** Jamf Protect is a distinct tenant URL, auth pair, and API (macOS EDR/threat data) from Jamf Pro's MDM API. Deferred to P1 so the P0 release ships faster, mirroring how the JumpCloud spec phased its lifecycle/governance collectors. *Rationale: keep P0 shippable; avoid blocking device-inventory evidence on a second full API integration.*
4. **No self-hosted-specific special-casing.** A single configurable base URL works identically for `*.jamfcloud.com` and self-hosted/on-prem Jamf Pro servers — same REST surface either way. *Rationale: YAGNI; the API doesn't differ by hosting model.*
5. **No cross-provider identity correlation** (e.g., matching a Jamf computer's assigned user to the same person's Okta or AWS IAM record). *Rationale: separate feature that would apply to every identity/device provider, not just Jamf.*
6. **No FileVault recovery-key collection.** Only FileVault **status** (enabled/disabled, compliant/non-compliant) is collected — never escrowed recovery keys or other secrets. *Rationale: evidence tooling must never become a vector for exfiltrating device-unlock secrets.*

## Architecture

- New crate `crates/jamf-rs` wraps the Jamf Pro API:
  - **Auth:** OAuth2 client-credentials flow — `POST /api/oauth/token` with `client_id`/`client_secret` → short-lived Bearer token, refreshed on expiry (a single automatic retry on a 401 caused by an expired token; a second 401 is a real auth error).
  - **Modern JSON API** (`/api/v1`, `/api/v2`) covers inventory, configuration profiles, groups, and patch management.
  - **Classic API** (`/JSSResource/*`, XML) covers policies, since Jamf Pro's newer JSON API does not yet expose policy objects. The client normalizes Classic XML responses into the same internal model so collectors never see XML directly. The same Bearer token authenticates both APIs.
  - 429 responses trigger exponential backoff with jitter, matching the Okta/Tenable clients.
- `CloudProvider::Jamf` variant added to `src/providers/mod.rs` (enum + `Display` impl), alongside the existing `Aws`/`Azure`/`Gcp`/`Tenable`/`Okta`/`Jira`/`Elastic` variants.
- New `src/providers/jamf/factory.rs` implementing `ProviderFactory`, one file per collector under `src/providers/jamf/` (mirrors every other provider's layout).
- New Cargo feature `jamf`, gated the same way as `okta`/`tenable`/`jira` in `src/providers/mod.rs` and the workspace `Cargo.toml`.
- **Config:** `jamf-config.toml` (gitignored), per-account fields: `name`, `provider = "jamf"`, `description`, `output_dir`, `jamf_base_url`, `jamf_client_id`, `jamf_client_secret`, and optionally `jamf_protect_base_url`/`jamf_protect_client_id`/`jamf_protect_client_secret` (unused until Protect ships in P1). Env var overrides: `JAMF_BASE_URL`, `JAMF_CLIENT_ID`, `JAMF_CLIENT_SECRET`. `jamf-config.example.toml` committed at repo root, fully commented, matching `okta-config.example.toml` shape. `.gitignore` updated to exclude `jamf-config.toml`.
- **TUI:** wired through the same six-touchpoint checklist CLAUDE.md documents for any new screen/provider: `src/tui/state.rs`, `src/tui/app/nav.rs`, `src/tui/events.rs`, `src/tui/ui/mod.rs` (+ render module if a Jamf-specific screen is needed), `src/tui/ui/frame.rs` (step indicator/footer hints), and `src/tui/menus/jamf.rs` for the collector category/menu data — same provider-scoped-menu pattern already built for Okta/Jira (`2026-07-16-provider-scoped-tui-menus.md`).

## P0 Collectors (`jamf-*` keys)

| Key | Type | Source | Notes |
|---|---|---|---|
| `jamf-computers` | CSV | Jamf Pro API v1 computer inventory | hostname, serial, OS version, model, last check-in, MDM enrollment status, FileVault **status only** |
| `jamf-mobile-devices` | CSV | Jamf Pro API v2 mobile devices | device name, OS version, serial, supervised state, last check-in |
| `jamf-computer-config-profiles` | CSV | Jamf Pro API computer configuration profiles | name, category, distribution method, scope |
| `jamf-mobile-config-profiles` | CSV | Jamf Pro API mobile configuration profiles | same shape, mobile-scoped |
| `jamf-computer-groups` | CSV | Computer groups (smart + static) | name, type, criteria, member count |
| `jamf-mobile-device-groups` | CSV | Mobile device groups (smart + static) | same shape, mobile-scoped |
| `jamf-policies` | JSON | Classic API policies (XML normalized to JSON) | name, category, scope, scripts/packages, frequency |
| `jamf-patch-titles` | CSV | Patch software title configurations | title, current version, minimum OS |
| `jamf-patch-compliance` | CSV | Per-title patch report | compliant vs. out-of-date device counts |

**Acceptance:** Each P0 collector produces a non-empty file against a live Jamf Pro tenant with representative data; each reports `success`, `empty`, `error`, or `timeout` in `RUN-MANIFEST-*.json`.

## P1 — Nice-to-Have Collectors

| Key | Type | Source | Notes |
|---|---|---|---|
| `jamf-admin-accounts` | CSV | Classic API accounts + API roles/clients | Jamf Pro admin users, privileges, API-client roles/scopes — AC-2/AC-6 evidence |
| `jamf-extension-attributes` | JSON | Extension attribute definitions | Custom compliance-check definitions orgs build on top of Jamf |
| `jamf-ldap-servers` | JSON | LDAP/directory server integrations | Mirrors JumpCloud's `ldap-servers` P1 item |
| `jamf-webhooks` | JSON | Webhook configurations | What external systems Jamf Pro is configured to notify |

## P1 — Jamf Protect (separate phase, own sub-client)

| Key | Type | Notes |
|---|---|---|
| `jamf-protect-computers` | CSV | Protected-device inventory from the Protect tenant |
| `jamf-protect-alerts` | Evidence (time-windowed) | Threat/detection alerts — SI-3/SI-4 evidence |
| `jamf-protect-plans` | JSON | Protection profiles/plans assigned to devices |

Jamf Protect is a distinct tenant URL with its own OAuth client-credentials pair (`jamf_protect_base_url`/`jamf_protect_client_id`/`jamf_protect_client_secret`, same `jamf-config.toml` account block, optional/unused until this phase ships). It gets its own follow-on implementation plan once P0 ships — same handoff pattern used for the rest of this feature.

## Error Handling

- Missing/invalid `jamf_client_id` or `jamf_client_secret` → single-line human-readable error, non-zero exit code, no stack trace in the TUI.
- 401 on an expired token → automatic single retry after re-fetching a token; a second 401 surfaces as a real auth error (distinguishing "bad credentials" from "token merely expired").
- 429 → exponential backoff with jitter, matching Okta/Tenable behavior.
- Per-collector 3-minute timeout, matching existing collectors.
- Classic API (XML) parse failures are reported distinctly from JSON API failures, so a Jamf Pro server-version mismatch is diagnosable from the error message alone.

## Documentation

- `README.md`: Jamf section (config example, collector list, required API-role scopes).
- `cli-examples.md`: at least three copy-paste Jamf recipes.
- `docs/fedramp-coverage.md`: rows added for each Jamf collector mapped to relevant CM/AC/SI controls.
- `jamf-config.example.toml`: fully commented.

**Acceptance:** A reader who has never used Grabber can go from `git clone` → Jamf evidence bundle following only the README.

## Open Questions (non-blocking — resolve during implementation)

- **[Engineering]** Exact endpoint paths/versions (v1 vs v2) vary by Jamf Pro server version — verify against the target tenant's live API docs during implementation rather than trusting this spec's endpoint names verbatim.
- **[Engineering]** Whether the Classic API's policies endpoint has since gained a JSON replacement in newer Jamf Pro releases (Jamf has signaled eventual Classic API retirement) — check at implementation time and prefer the JSON endpoint if available.
- **[Engineering]** Jamf Pro's pagination model (page/page-size vs. sort-cursor) may differ per endpoint — confirm per-collector during implementation, matching how `okta-rs` handles divergent pagination styles across endpoints.
- **[Engineering]** Jamf Protect's API shape (REST vs. GraphQL) needs confirmation before its P1 implementation plan is written.

## Timeline / Phasing

- **Phase 1 (P0 core):** crate skeleton + factory + config + `jamf-computers`, `jamf-mobile-devices`, `jamf-computer-config-profiles`, `jamf-mobile-config-profiles`, `jamf-computer-groups`, `jamf-mobile-device-groups`.
- **Phase 2 (P0 completion):** `jamf-policies`, `jamf-patch-titles`, `jamf-patch-compliance` + full docs + FedRAMP mapping. Ship as the tagged P0 release.
- **Phase 3 (P1 — admin/governance):** `jamf-admin-accounts`, `jamf-extension-attributes`, `jamf-ldap-servers`, `jamf-webhooks`.
- **Phase 4 (P1 — Jamf Protect):** separate follow-on spec + implementation plan for the Protect sub-client and its three collectors.

## Appendix: Reference Patterns to Mirror (for the follow-on implementation plan)

- API client: `crates/okta-rs/src/{client,error,lib}.rs`
- Provider factory: `src/providers/okta/factory.rs`
- CSV collector: `src/providers/okta/users.rs`
- Config merge: `src/app_config.rs` (Okta merge block)
- TUI wiring: search for `okta` in `src/runner/tui_session.rs`, `src/tui/app/nav.rs`, `src/tui/collector_data.rs`
- Chain-of-custody schema: existing `CHAIN-OF-CUSTODY-*.json` writer
- Sibling spec for structural comparison: `docs/plans/2026-07-17-add-jumpcloud-provider-spec.md`

An implementation plan (task-by-task, matching the structure of `docs/plans/2026-06-10-add-okta.md`) should be produced as a follow-on artifact once this design is approved.
