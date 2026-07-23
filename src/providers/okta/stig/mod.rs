//! Okta DISA STIG (Okta_IDaaS_STIG v1r1) check evaluators.
//!
//! Each submodule owns exactly one shared API fetch and returns a result for
//! every V-ID it's responsible for — see `evaluate_all`. Evaluator functions
//! are infallible (`Vec<StigCheckResult>`, never `Result`): a fetch failure
//! degrades the affected checks to `NotApplicable`/`NotReviewed` rather than
//! failing the whole collector, so a compliance report never silently drops
//! rows.
//!
//! Threshold direction convention used throughout: for "at least N" controls
//! (password length/complexity counts, history, minimum age) a *stricter*
//! configured value than required still passes; for "at most N" controls
//! (maximum age, lockout attempts, session idle/lifetime) a *stricter*
//! (smaller, but nonzero) configured value than required still passes. This
//! matches how STIG assessors generally read "must enforce at least/at
//! most" language — tightening beyond the floor/ceiling is never a finding.

pub mod access_policy;
pub mod authenticators;
pub mod automations;
pub mod log_streams;
pub mod manual_review;
pub mod password_policy;
pub mod sign_on_session;

use okta_rs::OktaClient;
use serde_json::Value;

use crate::stig_status::StigCheckResult;

/// Classifies an `OktaError` as "feature/endpoint unavailable on this
/// tenant" (→ downgrade affected checks to `NotApplicable`) vs. an
/// unexpected failure (→ `NotReviewed`, since we genuinely don't know the
/// answer and it would be wrong to imply the control doesn't apply).
pub(crate) fn is_feature_unavailable(e: &okta_rs::OktaError) -> bool {
    matches!(e, okta_rs::OktaError::Api { status, .. } if [400, 401, 403, 404].contains(status))
}

/// Emit the same degraded result for every V-ID in `v_ids`, used when a
/// shared fetch for a whole evaluator group fails outright.
pub(crate) fn degrade_all(
    v_ids: &[&str],
    e: &okta_rs::OktaError,
    endpoint: &str,
) -> Vec<StigCheckResult> {
    if is_feature_unavailable(e) {
        v_ids
            .iter()
            .map(|v| {
                StigCheckResult::not_applicable(
                    *v,
                    format!("{endpoint} unavailable on this tenant: {e}"),
                )
            })
            .collect()
    } else {
        v_ids
            .iter()
            .map(|v| StigCheckResult::not_reviewed(*v, format!("Error calling {endpoint}: {e}")))
            .collect()
    }
}

pub(crate) fn json_i64(v: &Value, pointer: &str) -> Option<i64> {
    v.pointer(pointer).and_then(|x| x.as_i64())
}

pub(crate) fn json_bool(v: &Value, pointer: &str) -> Option<bool> {
    v.pointer(pointer).and_then(|x| x.as_bool())
}

pub(crate) fn json_str<'a>(v: &'a Value, pointer: &str) -> Option<&'a str> {
    v.pointer(pointer).and_then(|x| x.as_str())
}

pub async fn evaluate_all(client: &OktaClient) -> Vec<StigCheckResult> {
    let mut out = Vec::new();
    out.extend(password_policy::evaluate(client).await);
    out.extend(sign_on_session::evaluate(client).await);
    out.extend(access_policy::evaluate(client).await);
    out.extend(log_streams::evaluate(client).await);
    out.extend(authenticators::evaluate(client).await);
    out.extend(automations::evaluate(client).await);
    out.extend(manual_review::evaluate(client).await);
    out
}
