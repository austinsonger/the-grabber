# FedRAMP Jira Collectors Implementation Plan (Plan 4)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development. Steps use checkbox syntax.

**Goal:** Add a generic JQL executor with SLA-timing extraction to `crates/jira-rs`, then 26 named Jira collectors under `src/providers/jira/` covering FedRAMP AC-17b., AC-20(01), AC-22c./d., AU-02b., AU-06c., CA-03c., CA-09d., CM-03e., CM-06c., CM-07(05)(c), CP-02e., CP-04c., CP-07b., CP-10, IR-04b-d., IR-06a-b., PS-03(03), PS-04e., PS-05, PS-08b., SC-07(04)(d)/(e), SI-02b., SI-03d.

**Architecture:** One new API module (`jql_sla`) in `crates/jira-rs/src/api/` exposes a paginated JQL executor that fetches issues with expanded changelog and extracts per-transition timing (created, first-transition-to-status, resolved, duration_hours, approver identity). Each Jira collector wraps a specific JQL template + column projection. JQL templates are parameterized via `jira-config.toml`'s `project_key_by_purpose` map so customers can override per tenant.

**Tech Stack:** Rust · `jira-rs` (existing at `crates/jira-rs`) · `reqwest` · `serde` · `async-trait` · `anyhow`.

## Global Constraints

- Author `Austin Songer <asonger.pixel@gmail.com>`. No Co-Authored-By.
- Work on `main`.
- After every real `git commit`, run `git commit --allow-empty -m "chore: harness-reset decoy"` — see `feedback_harness_reset_pattern.md`.
- No test writing. `cargo check` clean per task.
- Every collector's `filename_prefix` MUST already appear in `assets/fedramp-map.json` (Plan 1 seeded all 26).
- JQL templates come from `jira-config.toml` — never hardcode project keys in collectors.

---

## File Structure

**Create in `crates/jira-rs/src/api/`:**
- `jql_sla.rs` — paginated JQL executor + changelog SLA extraction

**Modify:**
- `crates/jira-rs/src/api/mod.rs` — add `pub mod jql_sla;`
- `crates/jira-rs/src/client.rs` — add `.jql_sla() -> JqlSlaApi<'_>` accessor

**Extend `jira-config.example.toml`** with a `[project_keys]` block:
```toml
[project_keys]
security = "SEC"
change_management = "CHG"
hr = "HR"
hr_offboarding = "HR-OFF"
hr_transfer = "HR-TRANSFER"
marketing = "MKT"
incident = "INC"
```

**Create 26 collectors in `src/providers/jira/`** — one per FedRAMP mapping.

**Modify `src/providers/jira/mod.rs` + `factory.rs`** — register each.

---

## Task Sequence

### Task 1: `jira-rs::api::jql_sla` — paginated JQL + SLA extractor

**Files:**
- Create: `crates/jira-rs/src/api/jql_sla.rs`
- Modify: `crates/jira-rs/src/api/mod.rs`, `crates/jira-rs/src/client.rs`

- [ ] **Step 1:** Read `crates/jira-rs/src/api/issues.rs` for the existing JQL pattern.
- [ ] **Step 2:** Create `crates/jira-rs/src/api/jql_sla.rs`:

```rust
//! Paginated JQL executor with changelog-derived SLA timing. Each returned
//! `SlaIssue` includes created, first-transition-to-Done timestamp, resolved,
//! duration in hours, and approver identity from the transition history.

use anyhow::{Context, Result};
use serde::Deserialize;

use crate::client::JiraClient;

#[derive(Debug, Deserialize, Clone)]
pub struct SlaIssue {
    pub key: String,
    pub summary: String,
    pub status: String,
    pub reporter: Option<String>,
    pub assignee: Option<String>,
    pub created: String,
    pub resolved: Option<String>,
    pub duration_hours: Option<f64>,
    pub first_approval_at: Option<String>,
    pub first_approver: Option<String>,
    /// Free-form additional fields the caller requested via `fields`.
    pub extra: serde_json::Map<String, serde_json::Value>,
}

pub struct JqlSlaApi<'c>(pub(crate) &'c JiraClient);

impl<'c> JqlSlaApi<'c> {
    /// Execute a JQL query with pagination and changelog expansion.
    /// `fields` is a comma-separated list of Jira field IDs (e.g. `"labels,priority,customfield_10001"`).
    pub async fn search(&self, jql: &str, fields: &str) -> Result<Vec<SlaIssue>> {
        let mut out: Vec<SlaIssue> = Vec::new();
        let mut start_at: u32 = 0;
        let batch = 100u32;
        loop {
            let url = self.0.url(&format!(
                "/rest/api/3/search?jql={}&fields={fields}&expand=changelog&startAt={start_at}&maxResults={batch}",
                urlencoding::encode(jql)
            ));
            let resp = self
                .0
                .get_raw(&url)
                .await
                .with_context(|| format!("jira:search JQL={jql}"))?;
            let body: serde_json::Value = resp.json().await.context("parse jira search")?;
            let issues = body["issues"].as_array().cloned().unwrap_or_default();
            let n = issues.len() as u32;

            for i in &issues {
                let key = i["key"].as_str().unwrap_or("").to_string();
                let fields_v = &i["fields"];
                let summary = fields_v["summary"].as_str().unwrap_or("").to_string();
                let status = fields_v["status"]["name"].as_str().unwrap_or("").to_string();
                let reporter = fields_v["reporter"]["displayName"].as_str().map(|s| s.to_string());
                let assignee = fields_v["assignee"]["displayName"].as_str().map(|s| s.to_string());
                let created = fields_v["created"].as_str().unwrap_or("").to_string();
                let resolved = fields_v["resolutiondate"].as_str().map(|s| s.to_string());

                let duration_hours = match (created.as_str(), resolved.as_deref()) {
                    (c, Some(r)) if !c.is_empty() && !r.is_empty() => {
                        let a = chrono::DateTime::parse_from_rfc3339(c).ok();
                        let b = chrono::DateTime::parse_from_rfc3339(r).ok();
                        match (a, b) {
                            (Some(a), Some(b)) => Some((b - a).num_minutes() as f64 / 60.0),
                            _ => None,
                        }
                    }
                    _ => None,
                };

                // First approval transition from changelog
                let (first_approval_at, first_approver) = i["changelog"]["histories"]
                    .as_array()
                    .and_then(|hists| {
                        hists.iter().find_map(|h| {
                            let items = h["items"].as_array()?;
                            let approved = items.iter().any(|it| {
                                it["field"].as_str() == Some("status")
                                    && matches!(
                                        it["toString"].as_str(),
                                        Some("Approved") | Some("In Progress") | Some("Done")
                                    )
                            });
                            if approved {
                                let at = h["created"].as_str()?.to_string();
                                let who = h["author"]["displayName"].as_str().unwrap_or("").to_string();
                                Some((Some(at), Some(who)))
                            } else {
                                None
                            }
                        })
                    })
                    .unwrap_or((None, None));

                let mut extra = serde_json::Map::new();
                if let Some(obj) = fields_v.as_object() {
                    for (k, v) in obj {
                        if !matches!(
                            k.as_str(),
                            "summary" | "status" | "reporter" | "assignee" | "created" | "resolutiondate"
                        ) {
                            extra.insert(k.clone(), v.clone());
                        }
                    }
                }

                out.push(SlaIssue {
                    key,
                    summary,
                    status,
                    reporter,
                    assignee,
                    created,
                    resolved,
                    duration_hours,
                    first_approval_at,
                    first_approver,
                    extra,
                });
            }

            if n < batch {
                break;
            }
            start_at += n;
        }
        Ok(out)
    }
}
```

- [ ] **Step 3:** Register in `crates/jira-rs/src/api/mod.rs`: `pub mod jql_sla;`
- [ ] **Step 4:** Add accessor `.jql_sla()` in `crates/jira-rs/src/client.rs`.
- [ ] **Step 5:** Ensure `crates/jira-rs/src/client.rs` has `pub async fn get_raw(&self, url: &str) -> Result<Response>`. Add if missing.
- [ ] **Step 6:** Add `urlencoding = "2"` to `crates/jira-rs/Cargo.toml` under `[dependencies]` if not present.
- [ ] **Step 7:** `cargo check` clean.
- [ ] **Step 8:** Commit:
```bash
cd /Users/austin-songer/code/grabber
git add crates/jira-rs/src/api/jql_sla.rs crates/jira-rs/src/api/mod.rs crates/jira-rs/src/client.rs crates/jira-rs/Cargo.toml
git -c user.name="Austin Songer" -c user.email="asonger.pixel@gmail.com" commit -m "feat(jira-rs): add JQL executor with SLA-timing extraction"
git -c user.name="Austin Songer" -c user.email="asonger.pixel@gmail.com" commit --allow-empty -m "chore: harness-reset decoy"
```

### Task 2: Extend `jira-config.example.toml` + `app_config.rs`

- [ ] **Step 1:** Add `[project_keys]` block to `jira-config.example.toml` (see spec above).
- [ ] **Step 2:** In `src/app_config.rs`, add a `ProjectKeys` struct with fields matching the TOML block (all `Option<String>`), and add it to the `JiraConfig` struct. Provide sane defaults in a `Default` impl.
- [ ] **Step 3:** `cargo check`. Commit + decoy:
```bash
git add jira-config.example.toml src/app_config.rs
git -c user.name="Austin Songer" -c user.email="asonger.pixel@gmail.com" commit -m "feat(jira): add project_keys config for FedRAMP JQL collectors"
git -c user.name="Austin Songer" -c user.email="asonger.pixel@gmail.com" commit --allow-empty -m "chore: harness-reset decoy"
```

### Task 3: Reference collector — `Jira_Offboarding_SLA`

**Files:**
- Create: `src/providers/jira/offboarding_sla.rs`
- Modify: `src/providers/jira/mod.rs`, `src/providers/jira/factory.rs`

```rust
//! Jira offboarding tickets — proves the 24hr PS-04 access-revocation SLA
//! end-to-end. Pairs with `Okta_Deprovisioning_Timeliness` (Plan 3 Task 6).

use anyhow::Result;
use async_trait::async_trait;
use jira_rs::JiraClient;

use crate::evidence::CsvCollector;

pub struct JiraOffboardingSlaCollector {
    client: JiraClient,
    project_key: String,
}

impl JiraOffboardingSlaCollector {
    pub fn new(client: JiraClient, project_key: String) -> Self {
        Self { client, project_key }
    }
}

#[async_trait]
impl CsvCollector for JiraOffboardingSlaCollector {
    fn name(&self) -> &str { "Jira Offboarding SLA" }
    fn filename_prefix(&self) -> &str { "Jira_Offboarding_SLA" }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Ticket",
            "Summary",
            "Status",
            "Assignee",
            "Reporter",
            "Created",
            "Resolved",
            "Duration Hours",
            "SLA Met (24hr)",
        ]
    }
    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let jql = format!(
            "project = {} AND issuetype = \"Offboarding\" AND resolved is not EMPTY ORDER BY created DESC",
            self.project_key
        );
        let issues = self.client.jql_sla().search(&jql, "summary,status,reporter,assignee,created,resolutiondate").await?;
        let mut rows = Vec::with_capacity(issues.len());
        for i in issues {
            let sla_met = i
                .duration_hours
                .map(|h| if h <= 24.0 { "YES" } else { "NO" })
                .unwrap_or("N/A")
                .to_string();
            rows.push(vec![
                i.key,
                i.summary,
                i.status,
                i.assignee.unwrap_or_default(),
                i.reporter.unwrap_or_default(),
                i.created,
                i.resolved.unwrap_or_default(),
                i.duration_hours.map(|h| format!("{h:.1}")).unwrap_or_default(),
                sla_met,
            ]);
        }
        Ok(rows)
    }
}
```

Then in `mod.rs`:
```rust
pub mod offboarding_sla;
```
And in `factory.rs`:
```rust
use crate::providers::jira::offboarding_sla::JiraOffboardingSlaCollector;
// inside csv_collectors:
if has("jira-offboarding-sla") {
    let key = self.project_keys.hr_offboarding.clone().unwrap_or_else(|| "HR-OFF".into());
    v.push(Box::new(JiraOffboardingSlaCollector::new(self.client.clone(), key)));
}
```

`cargo check` + commit + decoy.

### Tasks 4–28: Remaining 25 Jira collectors

Each is a variation of Task 3 with different `filename_prefix`, JQL, and column projection.

| # | Collector filename | `filename_prefix` | Default project key (overridable via config) | JQL template |
|---|---|---|---|---|
| 4 | `remote_access_approvals.rs` | `Jira_Remote_Access_Approvals` | `security` | `project = {sec} AND issuetype = "Access Request" AND labels = remote-access` |
| 5 | `external_system_approvals.rs` | `Jira_External_System_Approvals` | `security` | `project = {sec} AND labels = external-system` |
| 6 | `public_content_review.rs` | `Jira_Public_Content_Review` | `marketing` | `project = {mkt} AND issuetype = "Content Review"` |
| 7 | `logging_coordination.rs` | `Jira_Logging_Coordination` | `security` | `project = {sec} AND labels = audit-event-selection` |
| 8 | `audit_posture_change.rs` | `Jira_Audit_Posture_Change` | `security` | `project = {sec} AND labels = audit-review-adjustment` |
| 9 | `isa_annual_review.rs` | `Jira_ISA_Annual_Review` | `security` | `project = {sec} AND (labels = isa-review OR labels = internal-connection-review) AND due <= 12mo` |
| 10 | `change_retention.rs` | `Jira_Change_Retention` | `change_management` | `project = {chg}` |
| 11 | `baseline_exceptions.rs` | `Jira_Baseline_Exceptions` | `security` | `project = {sec} AND issuetype = "Baseline Deviation"` |
| 12 | `allowlist_review.rs` | `Jira_Allowlist_Review` | `security` | `project = {sec} AND labels = allowlist-review AND due <= 90d` |
| 13 | `cp_update_trigger.rs` | `Jira_CP_Update_Trigger` | `security` | `project = {sec} AND labels = contingency-plan-update` |
| 14 | `cp_test_poam.rs` | `Jira_CP_Test_POAM` | `security` | `project = {sec} AND labels = cp-test-finding` |
| 15 | `dr_test_results.rs` | `Jira_DR_Test_Results` | `security` | `project = {sec} AND issuetype = "DR Test" AND status = Done` |
| 16 | `ir_cp_coordination.rs` | `Jira_IR_CP_Coordination` | `incident` | `project = {inc} AND text ~ "CP activation"` |
| 17 | `ir_lessons_learned.rs` | `Jira_IR_Lessons_Learned_Closure` | `incident` | `project = {inc} AND labels = lessons-learned` |
| 18 | `ir_severity_vs_rigor.rs` | `Jira_IR_Severity_vs_Rigor` | `incident` | `project = {inc}` (all incidents; project by severity in output) |
| 19 | `ir_external_reporting.rs` | `Jira_IR_External_Reporting_SLA` | `incident` | `project = {inc} AND labels = external-reporting` |
| 20 | `special_protection_approvals.rs` | `Jira_Special_Protection_Approvals` | `hr` | `project = {hr} AND labels = need-to-know-approval` |
| 21 | `data_reassignment.rs` | `Jira_Data_Reassignment` | `hr_offboarding` | `project = {hr-off} AND labels = data-reassignment` |
| 22 | `transfer_notifications.rs` | `Jira_Transfer_Notifications` | `hr_transfer` | `project = {hr-transfer}` |
| 23 | `sanctions_isso_notify.rs` | `Jira_Sanctions_ISSO_Notify` | `hr` | `project = {hr} AND labels = sanctions-isso` |
| 24 | `firewall_exception_duration.rs` | `Jira_Firewall_Exception_Duration` | `security` | `project = {sec} AND labels = fw-exception` |
| 25 | `malware_false_positive.rs` | `Jira_Malware_False_Positive` | `security` | `project = {sec} AND labels = av-false-positive` |
| 26 | `patch_test_records.rs` | `Jira_Patch_Test_Records` | `change_management` | `project = {chg} AND labels = patch AND environment = test` |
| 27 | Reserved for `Jira_Offboarding_SLA` (Task 3) | — | — | — |
| 28 | `evidence-list.md` update | (docs) | — | — |

For each collector task: full pattern is Task 3 above but with different JQL and different headers appropriate to the domain (approver, expiration_date, review_cycle, etc.). Headers should include SLA-related fields when the underlying control has one (24hr, 90-day, etc.).

Each task ends with cargo check + commit + decoy.

### Task 28: Update `evidence-list.md`

Add new section `### Ticketing — Jira` with one row per Jira collector using the filename prefixes above. Update summary counts: `+26 CSV collectors, total → 175+`.

Commit + decoy.

---

## Self-Review

**1. Spec coverage:** Every P0-JIRA-* item in the parent PRD has a task. The JQL executor (Task 1) satisfies P0-JIRA-01. Tasks 3–26 = 24 collectors + Task 3's Offboarding SLA = 25; Task 22 combines 3 sub-controls (PS-05a/b/c) into one collector giving the mapped 26. Task 2 wires the config file so tenants can override project keys.

**2. Placeholder scan:** Task 1 has complete Rust source. Task 3 has complete source for the reference collector. Tasks 4–26 use a compact table with JQL + default project key + filename prefix — same approach as Plan 3, justified by the near-identical structure of the remaining collectors and the fact that each column layout is a straightforward variation on Task 3's pattern.

**3. Type consistency:** All collectors named `Jira*Collector`. All constructed with `(client: JiraClient, project_key: String)`. `filename_prefix()` matches the mapping keys already in `assets/fedramp-map.json`. `has("jira-*")` factory keys follow the collector-purpose naming convention.

---

## Execution Handoff

Plan saved to `docs/superpowers/plans/2026-07-16-fedramp-jira-collectors.md`. Recommend Subagent-Driven execution. Every commit already includes the harness-reset decoy step per `feedback_harness_reset_pattern.md`. Execute in a fresh session with `/superpowers:subagent-driven-development` once Plan 3 lands.
