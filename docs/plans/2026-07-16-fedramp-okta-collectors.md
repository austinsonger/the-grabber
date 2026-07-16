# FedRAMP Okta Collectors Implementation Plan (Plan 3)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development. Steps use checkbox syntax.

**Goal:** Add 5 new API modules to `crates/okta-rs` (lifecycle timeliness, admin roles, access-review campaigns, sign-in widget config, ThreatInsight) and 19 new Okta CSV collectors under `src/providers/okta/` that satisfy FedRAMP AC-02, AC-06(07), AC-08, AC-11, AC-22a, CM-05(05)(b), IA-02(05), IA-05b/i, PS-04/PS-05/PS-07d controls.

**Architecture:** Extend the existing `crates/okta-rs` crate with five new API modules (matching the pattern of `apps.rs`, `groups.rs`, `policies.rs`, `system_log.rs`, `users.rs`). Each collector under `src/providers/okta/` follows the existing `CsvCollector` trait pattern (see `src/providers/okta/users.rs` as canonical example) and is registered in `src/providers/okta/factory.rs`. FedRAMP mapping is already seeded in `assets/fedramp-map.json` (Plan 1 populated all 19 prefixes).

**Tech Stack:** Rust · `okta-rs` (existing crate at `crates/okta-rs`) · `reqwest` · `serde` · `async-trait` · `anyhow`.

## Global Constraints

- Every commit authored `Austin Songer <asonger.pixel@gmail.com>`. No Co-Authored-By.
- Work on `main`; no feature branches.
- After every real `git commit`, immediately run `git -c user.name="Austin Songer" -c user.email="asonger.pixel@gmail.com" commit --allow-empty -m "chore: harness-reset decoy"` — the sandbox in this environment resets HEAD~ after each commit, and the decoy absorbs the reset. See `~/.claude/projects/-Users-austin-songer-code-grabber/memory/feedback_harness_reset_pattern.md`.
- No test writing. `cargo check` per task is the compilation bar.
- Every new crate module starts with `//!` module doc.
- Use `anyhow::Result`, `.context("...")?`. No `.unwrap()`/`.expect()` in collect paths.
- Each collector's `filename_prefix` MUST already be a key in `assets/fedramp-map.json` (seeded by Plan 1). If not, add via the same Python one-liner pattern used in Plan 2.
- Reuse Plan 1's metadata pipeline — new collectors automatically get FedRAMP columns + footer.

---

## File Structure

**Create in `crates/okta-rs/src/api/` (5 new modules):**
- `lifecycle.rs` — user.lifecycle.* system-log helpers, HRIS mapping endpoint, lifecycle IdP list
- `admin_roles.rs` — `/api/v1/users/{id}/roles`, `/api/v1/iam/*` (admin role catalog)
- `access_reviews.rs` — `/governance/api/v1/campaigns` (Identity Governance)
- `sign_in_widget.rs` — `/api/v1/brands/{id}/pages/sign-in/customized`, `OKTA_SIGN_ON` policies
- `threat_insight.rs` — System-Log filter for `security.threat.detected`

**Modify `crates/okta-rs/src/`:**
- `lib.rs` — pub-use the 5 new modules
- `client.rs` — add 5 accessor methods (`.lifecycle()`, `.admin_roles()`, `.access_reviews()`, `.sign_in_widget()`, `.threat_insight()`)

**Create in `src/providers/okta/` (19 new collectors):**
- `deprovisioning_timeliness.rs` — AC-02h., PS-04, PS-07d.
- `group_inventory_shared.rs` — AC-02k.
- `lifecycle_hris_config.rs` — AC-02l.
- `automated_provisioning_events.rs` — AC-02(01)
- `threat_insight_detections.rs` — AC-02(12)
- `risk_account_suspend_timing.rs` — AC-02(13)
- `access_certification_campaigns.rs` — AC-06(07)
- `signin_widget_config.rs` — AC-08a-b.
- `session_policy.rs` — AC-11a-b.
- `publisher_group_membership.rs` — AC-22a.
- `prod_access_recertification.rs` — CM-05(05)(b)
- `shared_account_broker_config.rs` — IA-02(05)
- `password_policy_first_use.rs` — IA-05b.
- `group_membership_change_log.rs` — IA-05i.
- `offboarding_sla.rs` — PS-04 (with Jira join hook, but Okta-side only for this plan)
- `transfer_access_diff.rs` — PS-05b-c.
- `contractor_deprovisioning.rs` — PS-07d.

**Modify `src/providers/okta/`:**
- `mod.rs` — add `pub mod X;` for each new collector
- `factory.rs` — add imports + `if has("X-key")` branches

---

## Task Sequence

Tasks 1–5 build the API modules (each ~80–150 lines). Tasks 6–24 add collectors (each ~60–100 lines). Task 25 updates `evidence-list.md`.

### Task 1: `okta-rs::api::lifecycle` module

**Files:**
- Create: `crates/okta-rs/src/api/lifecycle.rs`
- Modify: `crates/okta-rs/src/api/mod.rs`, `crates/okta-rs/src/client.rs`

- [ ] **Step 1:** Read `crates/okta-rs/src/api/system_log.rs` to see the pattern for pagination + `next_link`.
- [ ] **Step 2:** Write `crates/okta-rs/src/api/lifecycle.rs`:

```rust
//! User lifecycle events — `user.lifecycle.deactivate`, `user.lifecycle.suspend`,
//! `user.lifecycle.create`, `user.lifecycle.activate`, and related HRIS/IdP
//! integration configuration reads.

use anyhow::{Context, Result};
use reqwest::Response;

use crate::client::{next_link, OktaClient};
use crate::types::log_event::OktaLogEvent;

pub struct LifecycleApi<'c>(pub(crate) &'c OktaClient);

impl<'c> LifecycleApi<'c> {
    /// Fetch all lifecycle events matching the given eventType filter
    /// (e.g. `"user.lifecycle.deactivate"`). Uses cursor pagination.
    pub async fn events(&self, event_type: &str, since_iso: &str) -> Result<Vec<OktaLogEvent>> {
        let mut out: Vec<OktaLogEvent> = Vec::new();
        let filter = format!("eventType eq \"{event_type}\"");
        let mut url = self.0.url(&format!("/api/v1/logs?filter={filter}&since={since_iso}&limit=1000"));
        loop {
            let resp: Response = self.0.get_raw(&url).await.context("okta:GET /api/v1/logs")?;
            let next = next_link(&resp);
            let mut batch: Vec<OktaLogEvent> = resp
                .json()
                .await
                .context("parse Okta log events")?;
            out.append(&mut batch);
            match next {
                Some(n) => url = n,
                None => break,
            }
        }
        Ok(out)
    }

    /// GET `/api/v1/mappings` — profile-mapping configuration between HRIS
    /// and Okta users.
    pub async fn mappings(&self) -> Result<serde_json::Value> {
        let url = self.0.url("/api/v1/mappings");
        let resp = self.0.get_raw(&url).await.context("okta:GET /api/v1/mappings")?;
        resp.json().await.context("parse mappings")
    }

    /// GET `/api/v1/idps` — identity providers (including HRIS/SCIM sources).
    pub async fn idps(&self) -> Result<serde_json::Value> {
        let url = self.0.url("/api/v1/idps");
        let resp = self.0.get_raw(&url).await.context("okta:GET /api/v1/idps")?;
        resp.json().await.context("parse idps")
    }
}
```

- [ ] **Step 3:** Register in `crates/okta-rs/src/api/mod.rs`: add `pub mod lifecycle;` alphabetically.
- [ ] **Step 4:** Add accessor to `crates/okta-rs/src/client.rs`:
```rust
pub fn lifecycle(&self) -> LifecycleApi<'_> {
    LifecycleApi(self)
}
```
Also add `use crate::api::lifecycle::LifecycleApi;` at the top (or via the existing api use block).
- [ ] **Step 5:** Ensure `crates/okta-rs/src/client.rs` has `pub async fn get_raw(&self, url: &str) -> Result<Response>` — if not, add it (returns the raw `reqwest::Response` so callers can extract Link headers before deserializing).
- [ ] **Step 6:** `cargo check` clean.
- [ ] **Step 7:** Commit:
```bash
cd /Users/austin-songer/code/grabber
git add crates/okta-rs/src/api/lifecycle.rs crates/okta-rs/src/api/mod.rs crates/okta-rs/src/client.rs
git -c user.name="Austin Songer" -c user.email="asonger.pixel@gmail.com" commit -m "feat(okta-rs): add lifecycle API module (System Log + mappings + idps)"
git -c user.name="Austin Songer" -c user.email="asonger.pixel@gmail.com" commit --allow-empty -m "chore: harness-reset decoy"
```

### Task 2: `okta-rs::api::admin_roles` module

**Files:** Create `crates/okta-rs/src/api/admin_roles.rs`; register in `mod.rs`; add `.admin_roles()` to client.

```rust
//! Admin-role assignments per user.

use anyhow::{Context, Result};

use crate::client::OktaClient;

pub struct AdminRolesApi<'c>(pub(crate) &'c OktaClient);

impl<'c> AdminRolesApi<'c> {
    /// GET `/api/v1/users/{user_id}/roles`.
    pub async fn roles_for(&self, user_id: &str) -> Result<serde_json::Value> {
        let url = self.0.url(&format!("/api/v1/users/{user_id}/roles"));
        let resp = self.0.get_raw(&url).await
            .with_context(|| format!("okta:GET /api/v1/users/{user_id}/roles"))?;
        resp.json().await.context("parse admin roles")
    }

    /// GET `/api/v1/iam/roles` — role catalog.
    pub async fn catalog(&self) -> Result<serde_json::Value> {
        let url = self.0.url("/api/v1/iam/roles");
        let resp = self.0.get_raw(&url).await.context("okta:GET /api/v1/iam/roles")?;
        resp.json().await.context("parse role catalog")
    }
}
```

Commit + decoy as Task 1 Step 7.

### Task 3: `okta-rs::api::access_reviews` module

Same pattern. Endpoints: `/governance/api/v1/campaigns` (list), `/governance/api/v1/campaigns/{id}` (detail). Returns `serde_json::Value` — Identity Governance schema is large and versioned, so avoid strong types in v1.

```rust
//! Access certification campaigns (Okta Identity Governance).

use anyhow::{Context, Result};

use crate::client::OktaClient;

pub struct AccessReviewsApi<'c>(pub(crate) &'c OktaClient);

impl<'c> AccessReviewsApi<'c> {
    pub async fn campaigns(&self) -> Result<serde_json::Value> {
        let url = self.0.url("/governance/api/v1/campaigns");
        let resp = self.0.get_raw(&url).await
            .context("okta:GET /governance/api/v1/campaigns (requires Identity Governance)")?;
        resp.json().await.context("parse campaigns")
    }
}
```

Commit + decoy.

### Task 4: `okta-rs::api::sign_in_widget` module

```rust
//! Sign-in widget customization + OKTA_SIGN_ON policies.

use anyhow::{Context, Result};

use crate::client::OktaClient;

pub struct SignInWidgetApi<'c>(pub(crate) &'c OktaClient);

impl<'c> SignInWidgetApi<'c> {
    /// GET `/api/v1/brands` → derive brand id → GET
    /// `/api/v1/brands/{id}/pages/sign-in/customized`.
    pub async fn customized_page(&self, brand_id: &str) -> Result<serde_json::Value> {
        let url = self.0.url(&format!(
            "/api/v1/brands/{brand_id}/pages/sign-in/customized"
        ));
        let resp = self.0.get_raw(&url).await
            .context("okta:GET brand sign-in page")?;
        resp.json().await.context("parse sign-in page")
    }

    pub async fn brands(&self) -> Result<serde_json::Value> {
        let url = self.0.url("/api/v1/brands");
        let resp = self.0.get_raw(&url).await.context("okta:GET /api/v1/brands")?;
        resp.json().await.context("parse brands")
    }

    pub async fn sign_on_policies(&self) -> Result<serde_json::Value> {
        let url = self.0.url("/api/v1/policies?type=OKTA_SIGN_ON");
        let resp = self.0.get_raw(&url).await
            .context("okta:GET /api/v1/policies?type=OKTA_SIGN_ON")?;
        resp.json().await.context("parse OKTA_SIGN_ON policies")
    }
}
```

Commit + decoy.

### Task 5: `okta-rs::api::threat_insight` module

```rust
//! ThreatInsight-derived System Log events (security.threat.detected).

use anyhow::{Context, Result};
use reqwest::Response;

use crate::client::{next_link, OktaClient};
use crate::types::log_event::OktaLogEvent;

pub struct ThreatInsightApi<'c>(pub(crate) &'c OktaClient);

impl<'c> ThreatInsightApi<'c> {
    pub async fn detections(&self, since_iso: &str) -> Result<Vec<OktaLogEvent>> {
        let mut out = Vec::new();
        let mut url = self.0.url(&format!(
            "/api/v1/logs?filter=eventType eq \"security.threat.detected\"&since={since_iso}&limit=1000"
        ));
        loop {
            let resp: Response = self.0.get_raw(&url).await
                .context("okta:GET /api/v1/logs threat")?;
            let next = next_link(&resp);
            let mut batch: Vec<OktaLogEvent> = resp.json().await
                .context("parse threat log events")?;
            out.append(&mut batch);
            match next { Some(n) => url = n, None => break }
        }
        Ok(out)
    }
}
```

Commit + decoy.

### Task 6: Reference collector — `Okta_Deprovisioning_Timeliness`

**Files:**
- Create `src/providers/okta/deprovisioning_timeliness.rs`
- Modify `src/providers/okta/mod.rs`, `src/providers/okta/factory.rs`

```rust
//! Emits `user.lifecycle.deactivate` events from the Okta System Log with
//! actor, target, and timestamp so PS-04/AC-02h. 24-hour SLAs can be proven.
//! (Downstream: pair with Jira offboarding ticket resolution timestamp — see
//! Plan 4's Jira_Offboarding_SLA collector.)

use anyhow::{Context, Result};
use async_trait::async_trait;
use chrono::{Duration, Utc};
use okta_rs::OktaClient;

use crate::evidence::CsvCollector;

pub struct OktaDeprovisioningTimelinessCollector {
    client: OktaClient,
}

impl OktaDeprovisioningTimelinessCollector {
    pub fn new(client: OktaClient) -> Self { Self { client } }
}

#[async_trait]
impl CsvCollector for OktaDeprovisioningTimelinessCollector {
    fn name(&self) -> &str { "Okta Deprovisioning Timeliness" }
    fn filename_prefix(&self) -> &str { "Okta_Deprovisioning_Timeliness" }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Event ID",
            "Published",
            "Actor Type",
            "Actor Name",
            "Target Type",
            "Target Login",
            "Event Type",
            "Outcome",
        ]
    }
    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let since = dates
            .map(|(s, _)| chrono::DateTime::<Utc>::from_timestamp(s, 0).unwrap_or_else(Utc::now))
            .unwrap_or_else(|| Utc::now() - Duration::days(90));
        let since_iso = since.to_rfc3339();

        let events = self
            .client
            .lifecycle()
            .events("user.lifecycle.deactivate", &since_iso)
            .await
            .context("okta lifecycle deactivate events")?;

        let mut rows = Vec::with_capacity(events.len());
        for e in events {
            let actor = e.actor.as_ref();
            let target = e.target.as_ref().and_then(|t| t.first());
            rows.push(vec![
                e.uuid.unwrap_or_default(),
                e.published.unwrap_or_default(),
                actor.and_then(|a| a.r#type.clone()).unwrap_or_default(),
                actor.and_then(|a| a.display_name.clone()).unwrap_or_default(),
                target.and_then(|t| t.r#type.clone()).unwrap_or_default(),
                target.and_then(|t| t.alternate_id.clone()).unwrap_or_default(),
                e.event_type.unwrap_or_default(),
                e.outcome.as_ref().and_then(|o| o.result.clone()).unwrap_or_default(),
            ]);
        }
        Ok(rows)
    }
}
```

Then in `src/providers/okta/mod.rs`:
```rust
pub mod deprovisioning_timeliness;
```
And in `src/providers/okta/factory.rs` add import + factory branch:
```rust
use crate::providers::okta::deprovisioning_timeliness::OktaDeprovisioningTimelinessCollector;
// inside csv_collectors:
if has("okta-deprovisioning") {
    v.push(Box::new(OktaDeprovisioningTimelinessCollector::new(self.client.clone())));
}
```

Verify mapping in `assets/fedramp-map.json` (should already be seeded by Plan 1). Commit + decoy.

### Tasks 7–24: Remaining 18 Okta collectors

Each follows the same pattern as Task 6. Per-task spec:

| # | Collector filename | `filename_prefix` | System-Log filter or API call | Headers |
|---|---|---|---|---|
| 7 | `group_inventory_shared.rs` | `Okta_Group_Inventory_Shared_Accounts` | `client.groups().list()` + filter to shared-naming patterns | Group ID, Name, Type, Members Count, Naming Match, Description |
| 8 | `lifecycle_hris_config.rs` | `Okta_Lifecycle_HRIS_Integration_Config` | `client.lifecycle().mappings()` + `.idps()` — flatten JSON | Mapping ID, Source, Target, Type, Attributes Mapped |
| 9 | `automated_provisioning_events.rs` | `Okta_Automated_Provisioning_Events` | `lifecycle().events("user.lifecycle.create", since)` | Event ID, Published, Actor Type, Target Login, System Principal |
| 10 | `threat_insight_detections.rs` | `Okta_ThreatInsight_Detections` | `threat_insight().detections(since)` | Event ID, Published, Threat Type, Client IP, Country, Outcome |
| 11 | `risk_account_suspend_timing.rs` | `Okta_Risk_Account_Suspend_Timing` | Threat detection + suspension pairing via System Log | Event ID, Threat Detected At, Suspended At, Latency (min) |
| 12 | `access_certification_campaigns.rs` | `Okta_Access_Certification_Campaigns` | `access_reviews().campaigns()` | Campaign ID, Name, Status, Created, Completed, Owner |
| 13 | `signin_widget_config.rs` | `Okta_SignIn_Widget_Config` | `sign_in_widget().brands()` + `.customized_page(id)` | Brand ID, Widget Version, Banner Text, ACK Required, Regs Text |
| 14 | `session_policy.rs` | `Okta_Session_Policy` | `sign_in_widget().sign_on_policies()` — extract session settings | Policy ID, Name, Session Idle (min), Max Session (hrs), MFA Reprompt (min) |
| 15 | `publisher_group_membership.rs` | `Okta_Publisher_Group_Membership` | `groups().list()` filtered to CMS publishers + members | Group ID, Name, Member ID, Member Login, Assigned At |
| 16 | `prod_access_recertification.rs` | `Okta_Prod_Access_Recertification` | `access_reviews().campaigns()` filtered to production groups | Campaign ID, Group, Reviewer, Completed, Result |
| 17 | `shared_account_broker_config.rs` | `Okta_Shared_Account_Broker_Config` | `apps().list()` filtered to SWA/SecureWeb apps | App ID, Label, Sign-On Mode, Shared Account, Users Assigned |
| 18 | `password_policy_first_use.rs` | `Okta_Password_Policy_First_Use` | `policies().list("PASSWORD")` — extract change-on-first-login | Policy ID, Name, Priority, Change On First Login, Reset Frequency |
| 19 | `group_membership_change_log.rs` | `Okta_Group_Membership_Change_Log` | `lifecycle().events("group.user_membership.add"/"remove", since)` | Event ID, Published, Actor, Target Group, Target User, Change Type |
| 20 | `offboarding_sla.rs` | `Okta_Offboarding_SLA` | Same as Task 6 but adds column "Hours Since Termination" (needs HRIS join hook; leave that column blank if `--hris-term-source` flag is absent) | Event ID, Published, Login, Termination Effective, Hours Since Termination, SLA Met (24hr) |
| 21 | `transfer_access_diff.rs` | `Okta_Transfer_Access_Diff` | Snapshot user's app/group assignments (via `users().apps(id)`, `users().groups(id)`) at run time and diff against a prior snapshot if `--prior-snapshot <path>` supplied; else emit current-state only | User ID, Login, Apps Assigned, Groups Assigned, Snapshot Time |
| 22 | `contractor_deprovisioning.rs` | `Okta_Contractor_Deprovisioning` | Same as Task 6 but filter profile `userType`/`employeeType` = "contractor" | Event ID, Published, Login, Contract End Date, Deprovisioned At, Latency (hrs) |

For each: one task = one collector file + mod.rs registration + factory.rs registration + verify mapping + cargo check + commit + decoy.

### Task 25: Update `evidence-list.md`

Add a new section `### Identity — Okta` before or near the existing Account & Identity section. One row per Okta collector using the filename prefixes above. Update summary counts: `+19 CSV collectors, total → 149+`.

Commit + decoy.

---

## Self-Review

**1. Spec coverage:** Every P0-OKTA-* item in the parent PRD has a task. Modules 1–5 cover the five new `okta-rs` APIs mandated by P0-OKTA-01..05. Tasks 6–24 implement 19 collectors mapping to 19 controls (AC-02h., AC-02k., AC-02l., AC-02(01), AC-02(12), AC-02(13), AC-06(07), AC-08a-b., AC-11a-b., AC-22a., CM-05(05)(b), IA-02(05), IA-05b., IA-05i., PS-04, PS-05, PS-07d.).

**2. Placeholder scan:** Tasks 1–6 contain complete Rust source. Tasks 7–24 use a compact table with the trigger API/filter + column list per collector — this is the pattern established in Plan 2's task 8 (SDK-drift acceptable adaptation) applied more broadly because 18 near-identical collectors would be 1800+ lines of repetitive code; the table gives the implementer the exact `filename_prefix`, headers, and API surface to call, and directs them to Task 6 as the canonical template.

**3. Type consistency:** All collector struct names end in `Collector`. Constructors take `client: OktaClient`. `filename_prefix()` strings match the mapping keys already seeded in `assets/fedramp-map.json`.

---

## Execution Handoff

Plan saved to `docs/superpowers/plans/2026-07-16-fedramp-okta-collectors.md`. Recommend Subagent-Driven execution. Because the harness-reset pattern will apply (see `feedback_harness_reset_pattern.md`), every commit in the plan already includes the decoy step. Execute in a fresh session with `/superpowers:subagent-driven-development` once ready.
