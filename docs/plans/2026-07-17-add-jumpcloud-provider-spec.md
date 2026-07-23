# Spec: Add JumpCloud Provider

**Status:** Draft
**Author:** Austin Songer
**Date:** 2026-07-17
**Type:** Feature spec (PRD) — implementation plan to follow

---

## Problem Statement

Grabber collects audit/compliance evidence from AWS, Azure, GCP, Tenable, Okta, and Jira, but organizations that use **JumpCloud** as their identity, directory, or device-management provider have no way to include that evidence in a Grabber run. Auditors reviewing FedRAMP, SOC 2, HIPAA, or ISO controls for JumpCloud-managed identities and endpoints must pull evidence manually from the JumpCloud Admin Console, which is slow, inconsistent, and breaks the single-run chain-of-custody guarantee Grabber provides for every other provider.

## Goals

1. **Ship a first-class JumpCloud provider** that plugs into the existing `ProviderFactory` contract with no changes to core collector plumbing.
2. **Cover the identity/access-control evidence** most commonly requested in audits: users, user groups + membership, systems (managed devices), system groups + membership, SSO applications, policies, directories, and the Directory Insights event log.
3. **Match Okta parity for operator ergonomics** — same config file pattern (`jumpcloud-config.toml`, gitignored, merged at startup), same TUI selection flow, same file-naming/chain-of-custody/manifest behavior.
4. **Zero regressions** in existing providers — JumpCloud lives behind a Cargo feature and only activates when a JumpCloud account is configured.
5. **Documented in one pass** — README, `cli-examples.md`, and `fedramp-coverage.md` all updated in the same PR that ships the code.

## Non-Goals

1. **No writes to JumpCloud.** Grabber is read-only for every provider; JumpCloud is no exception. No user creation, group edits, policy pushes, or system commands. *Rationale: preserves the single "collect, never mutate" invariant that keeps chain-of-custody defensible.*
2. **No JumpCloud Commands / command results collector in v1.** Command output can contain arbitrary shell payloads and is high-volume; deferred until we have a redaction story. *Rationale: safety and scope.*
3. **No JumpCloud Radius / LDAP-as-a-Service configuration collectors in v1.** Lower audit demand and each is a separate API surface. *Rationale: keep v1 shippable.*
4. **No cross-provider identity correlation** (e.g. matching a JumpCloud user to the same person's Okta or AWS IAM record). *Rationale: separate feature; would apply to every identity provider, not just JumpCloud.*
5. **No JumpCloud MSP multi-org fan-out.** Each JumpCloud org is a separate `[[account]]` entry, same as multi-account AWS. *Rationale: the existing account loop already covers this; a special MSP mode is premature.*

## User Stories

### Compliance operator (primary persona)
- As a compliance operator, I want to add a JumpCloud org to `config.toml` (or `jumpcloud-config.toml`) so a Grabber run automatically pulls JumpCloud evidence alongside my AWS accounts.
- As a compliance operator, I want the JumpCloud API key stored in a gitignored config file or an env var (`JUMPCLOUD_API_KEY`) so credentials never land in the shared repo.
- As a compliance operator, I want the same TUI wizard flow — pick account → pick collectors → run — so I don't have to learn a new interface for JumpCloud.
- As a compliance operator, I want output files prefixed with the account `name` (e.g. `Acme_JumpCloud_Users-2026-07-17-120000.csv`) so I can hand the evidence bundle to an auditor with no explanation.

### FedRAMP / SOC 2 auditor
- As an auditor, I want a per-collector CSV of active JumpCloud users with MFA status, suspension state, last login, and password expiration so I can spot-check access-control (AC-2) evidence.
- As an auditor, I want the JumpCloud Directory Insights event log for the last 90 days (configurable) so I can review authentication events and admin actions (AU-2, AU-3).
- As an auditor, I want SSO application → user assignment evidence so I can verify least-privilege for federated apps.

### Platform engineer running scripted collection
- As a platform engineer, I want `grabber --account "Acme JumpCloud" --collectors jumpcloud-users,jumpcloud-systems --no-tui` so I can run JumpCloud collection from CI without interactive prompts.
- As a platform engineer, I want a clear exit code and per-collector status in `RUN-MANIFEST-*.json` so I can detect partial failures in an automated pipeline.

### Edge / error cases
- As an operator, I want a helpful error (not a stack trace) when the JumpCloud API key is missing or invalid so I can fix the config quickly.
- As an operator, I want 429 rate-limit responses to trigger automatic backoff (matching Okta behavior) so long runs don't fail mid-collection.
- As an operator, I want a per-collector timeout (3 min, matching AWS/Okta) so a hung endpoint doesn't stall the whole run.

## Requirements

### Must-Have (P0)

**P0.1 — Provider plumbing**
- Add `CloudProvider::JumpCloud` variant to `src/providers/mod.rs`.
- New `crates/jumpcloud-rs` workspace crate wrapping the JumpCloud REST API v1 and v2 (auth header `x-api-key: <token>`, JSON body pagination via `skip`/`limit` for v1 and `next` cursor for v2, 429 backoff).
- New `src/providers/jumpcloud/factory.rs` implementing `ProviderFactory`.
- Cargo feature `jumpcloud`, mirroring the `okta`/`tenable` feature gating.
- **Acceptance:** `cargo build --features jumpcloud` succeeds; `cargo build` (no features) still succeeds.

**P0.2 — Configuration**
- New `jumpcloud-config.toml` (gitignored) with per-account fields: `name`, `provider = "jumpcloud"`, `description`, `output_dir`, `jumpcloud_api_key`, optional `jumpcloud_org_id` (required for MTP/MSP orgs).
- Env var overrides: `JUMPCLOUD_API_KEY`, `JUMPCLOUD_ORG_ID`.
- `jumpcloud-config.example.toml` committed at repo root, matching `okta-config.example.toml` shape.
- `.gitignore` updated to exclude `jumpcloud-config.toml`.
- **Acceptance:** Startup merges `jumpcloud-config.toml` into `AppConfig` the same way Okta does; missing file is not an error.

**P0.3 — Core inventory + audit collectors (v1 set, 15 collectors)**

Matches the Okta provider's audit/compliance-critical set, plus JumpCloud-specific device-management collectors that have no Okta analog.

*Identity & directory (mirrors Okta core)*

| Key | Type | Endpoint(s) | Okta analog |
|---|---|---|---|
| `jumpcloud-users` | CSV | `GET /api/systemusers` | `okta-users` |
| `jumpcloud-user-groups` | CSV | `GET /api/v2/usergroups` | `okta-groups` |
| `jumpcloud-user-group-members` | JSON | `GET /api/v2/usergroups/{id}/members` | `okta-group-members` |
| `jumpcloud-applications` | CSV | `GET /api/applications` | `okta-apps` |
| `jumpcloud-mfa-factors` | CSV | `GET /api/systemusers` (mfa fields) + `/api/v2/systemusers/{id}/associations` | `okta-factors` |
| `jumpcloud-directory-insights` | Evidence (time-windowed) | `POST /insights/directory/v1/events` | `okta-system-log` |

*Policy & configuration (mirrors Okta policy surface)*

| Key | Type | Endpoint(s) | Okta analog |
|---|---|---|---|
| `jumpcloud-policies` | JSON | `GET /api/v2/policies`, `GET /api/v2/policies/{id}` | `okta-policies` |
| `jumpcloud-password-policy` | JSON | `GET /api/v2/policies` (filtered to password) + `GET /api/organizations/{id}/settings` | `okta-password-policy` |
| `jumpcloud-session-policy` | JSON | `GET /api/v2/policies` (filtered to session/MFA re-auth) + org settings | `okta-session-policy` |
| `jumpcloud-admin-roles` | CSV | `GET /api/organizations/{id}/administrators` | `okta-publisher-groups` |

*Security & threat detection (mirrors Okta threat surface)*

| Key | Type | Endpoint(s) | Okta analog |
|---|---|---|---|
| `jumpcloud-directory-alerts` | Evidence (time-windowed) | `GET /insights/directory/v1/alerts` | `okta-threat-insight` |

*Device management (JumpCloud-native, no Okta analog)*

| Key | Type | Endpoint(s) | Notes |
|---|---|---|---|
| `jumpcloud-systems` | CSV | `GET /api/systems` | Managed endpoints — hostname, OS, agent version, last contact, FDE state |
| `jumpcloud-system-groups` | CSV | `GET /api/v2/systemgroups` | Device groups |
| `jumpcloud-system-group-members` | JSON | `GET /api/v2/systemgroups/{id}/members` | Per-group membership |
| `jumpcloud-system-user-associations` | JSON | `GET /api/v2/systems/{id}/users` | User↔system bindings — core JumpCloud access-control evidence |

- **Acceptance:** Each collector produces a non-empty file against a live JumpCloud tenant with representative data; each collector reports `success`, `empty`, `error`, or `timeout` in `RUN-MANIFEST-*.json`.

**P0.4 — TUI integration**
- `Provider` selection screen lists JumpCloud when at least one `[[account]]` has `provider = "jumpcloud"`.
- Collector-selection screen shows the 8 `jumpcloud-*` keys with sensible defaults selected.
- Provider-scoped menu suppresses AWS-only affordances (region picker, All-Regions toggle) — same behavior already implemented for Okta/Jira in the recent `2026-07-16-provider-scoped-tui-menus.md` work.
- **Acceptance:** A user with only JumpCloud accounts sees a clean, JumpCloud-only TUI with no AWS artifacts.

**P0.5 — CLI parity**
- `--collectors jumpcloud-users,jumpcloud-systems` (etc.) works in non-interactive mode.
- `--account "<name>"` filters to a single JumpCloud account.
- **Acceptance:** `grabber --account "Acme JumpCloud" --collectors jumpcloud-users --no-tui` produces exactly one file and one manifest entry.

**P0.6 — Chain of custody & signing**
- JumpCloud runs produce `CHAIN-OF-CUSTODY-*.json` and append to `CHAIN-OF-CUSTODY.jsonl` capturing operator, hostname, and (in place of AWS caller ARN) the JumpCloud org ID + API key fingerprint (SHA-256 of the token, first 12 hex chars).
- `--sign` HMAC manifest includes JumpCloud output files.
- **Acceptance:** Chain-of-custody JSON validates against the existing schema; signed manifest verifies.

**P0.7 — Error handling**
- Missing/invalid API key → single-line human-readable error, non-zero exit code, no stack trace in the TUI.
- 401/403 → distinguish "bad token" from "token lacks scope."
- 429 → exponential backoff with jitter, matching Okta.
- Per-collector 3-minute timeout, matching existing collectors.
- **Acceptance:** Deliberate misconfiguration surfaces the expected error message in `evidence-collection.log` and the TUI toast.

**P0.8 — Documentation**
- `README.md`: JumpCloud section (config example, collector list, required API key scopes).
- `cli-examples.md`: at least three copy-paste JumpCloud recipes.
- `docs/fedramp-coverage.md`: rows added for each JumpCloud collector mapped to relevant AC/AU/IA controls.
- `jumpcloud-config.example.toml`: fully commented.
- **Acceptance:** A reader who has never used Grabber can go from `git clone` → JumpCloud evidence bundle following only the README.

### Nice-to-Have (P1)

**Lifecycle & governance collectors — mirror the Okta compliance derivations, most of which are Directory-Insights-driven joins over the P0 raw data.**

| Key | Type | Derivation | Okta analog |
|---|---|---|---|
| `jumpcloud-hris-directories` | JSON | `GET /api/v2/directories` filtered to HRIS/IdP integrations (Google Workspace, M365, Workday-via-SCIM) with sync status | `okta-hris-config` |
| `jumpcloud-auto-provisioning` | CSV | Directory Insights filtered to `user.create`, `user_association.create`, `application.provision` events with source (SCIM / HRIS / manual) | `okta-auto-provisioning` |
| `jumpcloud-deprovisioning` | CSV | Insights: time from `user.suspend` → `user.delete` and cascade of `*_association.remove` events | `okta-deprovisioning` |
| `jumpcloud-offboarding-sla` | CSV | Insights + HRIS termination trigger → last association removed; SLA delta in hours | `okta-offboarding-sla` |
| `jumpcloud-risk-suspend-timing` | CSV | Insights: time from alert / repeated auth failures → `user.suspend` | `okta-risk-suspend` |
| `jumpcloud-group-changes` | Evidence (time-windowed) | Insights filtered to `user_group.*` and `system_group.*` events | `okta-group-changes` |
| `jumpcloud-transfer-access-diff` | JSON | Insights: before/after group/app/system associations when a user moves user groups | `okta-transfer-diff` |
| `jumpcloud-contractor-deprov` | CSV | Users tagged contractor (attribute or group) with deprovisioning timing from Insights | `okta-contractor-deprov` |
| `jumpcloud-shared-user-groups` | JSON | User groups associated with multiple applications and/or system groups (shared-access indicator) | `okta-shared-groups` |
| `jumpcloud-prod-access-recert` | CSV | User-group→system/app associations tagged `prod` (attribute or naming convention) with last-recertification date from Insights | `okta-prod-recert` |

**Additional P1 items:**

- **P1.11** — `jumpcloud-radius-servers` collector (`GET /api/v2/radiusservers`) for orgs using JumpCloud RADIUS.
- **P1.12** — `jumpcloud-ldap-servers` collector (`GET /api/v2/ldapservers`) for orgs using JumpCloud LDAP-as-a-Service.
- **P1.13** — `jumpcloud-managed-software` collector (`GET /api/v2/software/apps`) — device software inventory for vulnerability/patch evidence.
- **P1.14** — Directory Insights query filters exposed via CLI (`--jumpcloud-insights-service auth,directory,systems`) so operators can slice the event log without post-processing.
- **P1.15** — Populate `iam/`, `inventory/`, and `evidence-list.md` with JumpCloud-specific rows (parallel to what Okta already contributes).

### Okta collectors intentionally NOT ported

These Okta collectors have no clean JumpCloud equivalent and are excluded from this spec:

- **`okta-access-reviews`** — JumpCloud has no native access-certification campaign primitive. Recertification is expressed via `jumpcloud-prod-access-recert` (P1) and offline processes.
- **`okta-signin-widget`** — JumpCloud's SSO login page is not a customizable widget with a policy-relevant config surface.
- **`okta-shared-account-broker`** — no JumpCloud equivalent to Okta Advanced Server Access / PAM broker.

If demand emerges we can revisit; flagged here so the omission is deliberate, not overlooked.

### Future Considerations (P2)

- **P2.1** — Cross-provider identity graph: link JumpCloud users to Okta / AWS IAM / Azure AD identities by email or externalId. Architecture note now so we don't paint ourselves into a corner: keep the raw `email` and `externalId` columns in every identity-provider users CSV.
- **P2.2** — JumpCloud Commands collector (with a redaction pipeline for `command`/`result` bodies).
- **P2.3** — MSP multi-org fan-out — a single `[[msp_account]]` block that expands into per-org sub-runs at startup.
- **P2.4** — Real-time Directory Insights streaming for continuous monitoring (out of scope for a batch-evidence tool but worth flagging).

## Success Metrics

### Leading indicators (evaluate at 1–4 weeks post-launch)
- **Adoption**: ≥1 external user reports running a JumpCloud collection within 4 weeks of the tagged release. *Measurement: GitHub issues / discussions / support inbox.*
- **Feature-completeness self-check**: 100% of the 15 P0 collectors return non-empty files on the reference test tenant. *Measurement: manual verification against a seeded JumpCloud sandbox before release.*
- **CI green**: `cargo test --features jumpcloud` passes on every PR. *Measurement: GitHub Actions.*
- **Zero cross-provider regressions**: existing AWS/Okta/Jira integration tests remain green with the JumpCloud feature enabled and disabled. *Measurement: CI.*

### Lagging indicators (evaluate at 1 quarter)
- **Audit uptake**: ≥1 real audit engagement includes a JumpCloud evidence bundle produced by Grabber.
- **Support load**: JumpCloud-related issues account for <20% of provider bug reports in the first quarter (i.e. it's not disproportionately buggy).
- **FedRAMP coverage delta**: `fedramp-coverage.md` shows ≥5 new controls satisfied at least in part by JumpCloud evidence.

## Open Questions

- **[Product]** Which JumpCloud edition(s) are we targeting for v1? Free tier caps some endpoints; do we need to detect edition and skip gracefully, or document the requirement and let 403s surface? *(Blocking for docs, non-blocking for code.)*
- **[Engineering]** JumpCloud v1 vs v2 API split — v1 uses `skip`/`limit`, v2 uses cursor pagination. Do we build one client that transparently handles both, or two thin sub-clients? *Recommendation: one client, per-endpoint pagination helper, matches how `okta-rs` handles cursor vs. Link pagination.* *(Non-blocking; decide during implementation.)*
- **[Engineering]** Directory Insights event volume can be large (millions of events for a big org over 90 days). Do we stream to disk during pagination or buffer in memory? *Recommendation: stream, matching CloudTrail collector.* *(Non-blocking.)*
- **[Legal/Compliance]** JumpCloud API keys are effectively root-of-trust for the org. Does storing them in `jumpcloud-config.toml` (gitignored) meet our internal secrets-handling policy, or do we require env-var-only? *Recommendation: mirror Okta — support both, document env-var as preferred for CI.* *(Blocking for docs.)*
- **[Data]** Should we normalize `externalId` and `email` field names across identity providers (Okta, JumpCloud, future Azure AD) now, or wait until P2.1? *(Non-blocking; design the CSV schema with this in mind but don't refactor Okta.)*
- **[Engineering]** MTP (multi-tenant portal) orgs require the `x-org-id` header. Do we require `jumpcloud_org_id` in config always, or only when the API returns "org id required"? *Recommendation: optional in config, add on request if the tenant is MTP; document the header.* *(Non-blocking.)*

## Timeline Considerations

- **Dependencies:** None external. Internally, benefits from the provider-scoped TUI menu work landed on 2026-07-16 (commit `3374758`) — build on top of it, don't fork.
- **Phasing suggestion:**
  - **Phase 1 (P0 core, ~week 1):** crate skeleton + factory + config + identity/directory collectors (`users`, `user-groups`, `user-group-members`, `applications`, `mfa-factors`, `directory-insights`) + `systems` + `system-groups` + `system-group-members` + `system-user-associations`. Ship as `v0.x-jumpcloud-alpha`.
  - **Phase 2 (P0 completion, ~week 2):** `policies`, `password-policy`, `session-policy`, `admin-roles`, `directory-alerts` + full docs + FedRAMP mapping. Ship as the tagged release.
  - **Phase 3 (P1 lifecycle & governance):** the 10 Insights-derived compliance collectors (`auto-provisioning`, `deprovisioning`, `offboarding-sla`, `risk-suspend-timing`, `group-changes`, `transfer-access-diff`, `contractor-deprov`, `shared-user-groups`, `prod-access-recert`, `hris-directories`).
  - **Phase 4 (P1 network + inventory):** RADIUS, LDAP, managed-software, Insights CLI filters.
- **No hard external deadline.** Suggested internal target: Phase 2 complete within ~2 weeks of spec approval, matching the pace of the Okta rollout (spec → shipped in ~10 days per `2026-06-10-add-okta.md`).

---

## Appendix: Reference patterns to mirror (for the follow-on implementation plan)

- API client: `crates/okta-rs/src/{client,error,lib}.rs`
- Provider factory: `src/providers/okta/factory.rs`
- CSV collector: `src/providers/okta/users.rs`
- Time-windowed evidence collector: `src/providers/okta/system_log.rs`
- Config merge: `src/app_config.rs` (Okta merge block)
- TUI wiring: search for `okta` in `src/runner/tui_session.rs`, `src/tui/app/nav.rs`, `src/tui/collector_data.rs`
- Chain-of-custody schema: existing `CHAIN-OF-CUSTODY-*.json` writer

An implementation plan (task-by-task, matching the structure of `2026-06-10-add-okta.md`) should be produced as a follow-on artifact once this spec is approved.
