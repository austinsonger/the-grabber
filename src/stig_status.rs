//! Generic DISA STIG checklist status vocabulary and per-check result type.
//!
//! Not Okta-specific — any provider that gains STIG-style pass/fail
//! evaluation can reuse these types.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StigStatus {
    Open,
    NotAFinding,
    NotApplicable,
    NotReviewed,
}

impl StigStatus {
    /// Exact strings used by the DISA STIG Viewer / CKL checklist vocabulary.
    pub fn as_stig_str(&self) -> &'static str {
        match self {
            StigStatus::Open => "Open",
            StigStatus::NotAFinding => "NotAFinding",
            StigStatus::NotApplicable => "Not_Applicable",
            StigStatus::NotReviewed => "Not_Reviewed",
        }
    }
}

/// The outcome of evaluating a single STIG check (identified by V-ID)
/// against a live tenant.
#[derive(Debug, Clone)]
pub struct StigCheckResult {
    pub v_id: String,
    pub status: StigStatus,
    pub expected_value: String,
    pub actual_value: String,
    pub details: String,
}

impl StigCheckResult {
    pub fn new(
        v_id: impl Into<String>,
        status: StigStatus,
        expected_value: impl Into<String>,
        actual_value: impl Into<String>,
        details: impl Into<String>,
    ) -> Self {
        Self {
            v_id: v_id.into(),
            status,
            expected_value: expected_value.into(),
            actual_value: actual_value.into(),
            details: details.into(),
        }
    }

    pub fn not_applicable(v_id: impl Into<String>, details: impl Into<String>) -> Self {
        Self::new(v_id, StigStatus::NotApplicable, "", "", details)
    }

    pub fn not_reviewed(v_id: impl Into<String>, details: impl Into<String>) -> Self {
        Self::new(v_id, StigStatus::NotReviewed, "", "", details)
    }
}
