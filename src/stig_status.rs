//! Generic DISA STIG checklist status vocabulary, per-check result type,
//! and the remediation data model layered on top of it.
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

    /// Whether a remediation wizard should offer this check for action.
    /// `NotAFinding` (already passing) and `NotApplicable` (confirmed out
    /// of scope) are excluded; `Open` and `NotReviewed` are not.
    pub fn is_actionable(&self) -> bool {
        !matches!(self, StigStatus::NotAFinding | StigStatus::NotApplicable)
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
    /// What a remediation wizard could do about this result. Empty when
    /// the check is passing/not-applicable, or when nothing was computed
    /// for it. One entry per affected resource (e.g. three PASSWORD
    /// policies all failing the same field yields three targets).
    pub remediation: Vec<RemediationTarget>,
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
            remediation: Vec::new(),
        }
    }

    pub fn not_applicable(v_id: impl Into<String>, details: impl Into<String>) -> Self {
        Self::new(v_id, StigStatus::NotApplicable, "", "", details)
    }

    pub fn not_reviewed(v_id: impl Into<String>, details: impl Into<String>) -> Self {
        Self::new(v_id, StigStatus::NotReviewed, "", "", details)
    }

    /// Attach one remediation target. Chainable at the evaluator call site:
    /// `StigCheckResult::new(...).with_remediation(RemediationTarget::...)`.
    pub fn with_remediation(mut self, target: RemediationTarget) -> Self {
        self.remediation.push(target);
        self
    }
}

// ---------------------------------------------------------------------------
// Remediation
// ---------------------------------------------------------------------------

/// A structured description of one API-actionable (or explicitly
/// not-actionable) fix for a single STIG finding, attached to a
/// `StigCheckResult` by the evaluator that produced it.
#[derive(Debug, Clone)]
pub enum RemediationTarget {
    /// Overwrite one or more JSON-pointer fields on an existing policy or
    /// policy rule. `rule_id: None` means the fields are relative to the
    /// policy's `settings` object (e.g. a PASSWORD policy); `rule_id:
    /// Some(_)` means the fields are relative to the rule object's root
    /// (e.g. a Global Session Policy rule's `actions.signon.session.*`).
    PolicyField {
        policy_id: String,
        /// Policy type string as passed to `PoliciesApi::list_by_type`
        /// (e.g. "PASSWORD", "OKTA_SIGN_ON") — used to re-fetch the policy
        /// fresh immediately before writing.
        policy_type: &'static str,
        rule_id: Option<String>,
        fields: Vec<(String, serde_json::Value)>,
        /// Human label for what's being changed (policy/rule name).
        resource_label: String,
    },
    /// Ensure the top rule of an Identity Engine Authentication (Access)
    /// Policy requires a phishing-resistant possession factor. Kept
    /// separate from `PolicyField` because the underlying JSON is an array
    /// of constraint objects that must be merged, not a scalar field set.
    AccessPolicyPhishingResistant {
        policy_id: String,
        rule_id: String,
        resource_label: String,
    },
    /// Overwrite one or more JSON-pointer fields (relative to the
    /// authenticator object's root) on an existing authenticator.
    AuthenticatorField {
        authenticator_id: String,
        fields: Vec<(String, serde_json::Value)>,
        resource_label: String,
    },
    /// Activate an existing-but-inactive authenticator.
    ActivateAuthenticator {
        authenticator_id: String,
        resource_label: String,
    },
    /// Set the org's custom sign-in page content (e.g. a DOD warning
    /// banner). Needs text supplied interactively — see
    /// `RemediationTarget::needs_text_input`.
    SetSignInBanner { brand_id: String },
    /// No API path exists for this control, or grabber isn't confident
    /// enough in the write schema to attempt one (see the "Global
    /// Constraints" scope note in the plan this type shipped with). The
    /// wizard still shows the check's Fix Text and can record a manual
    /// acknowledgement, but never calls a write API.
    ManualOnly,
}

impl RemediationTarget {
    /// Human-readable one-line description of what applying this target
    /// would do, shown in the remediation wizard before confirmation.
    pub fn describe(&self) -> String {
        match self {
            RemediationTarget::PolicyField {
                resource_label,
                fields,
                ..
            } => {
                let changes: Vec<String> =
                    fields.iter().map(|(p, v)| format!("{p} → {v}")).collect();
                format!("On \"{resource_label}\": set {}", changes.join(", "))
            }
            RemediationTarget::AccessPolicyPhishingResistant { resource_label, .. } => {
                format!("On \"{resource_label}\": require a phishing-resistant possession factor")
            }
            RemediationTarget::AuthenticatorField {
                resource_label,
                fields,
                ..
            } => {
                let changes: Vec<String> =
                    fields.iter().map(|(p, v)| format!("{p} → {v}")).collect();
                format!(
                    "On authenticator \"{resource_label}\": set {}",
                    changes.join(", ")
                )
            }
            RemediationTarget::ActivateAuthenticator { resource_label, .. } => {
                format!("Activate authenticator \"{resource_label}\"")
            }
            RemediationTarget::SetSignInBanner { .. } => {
                "Set the sign-in page's custom content to the text you provide below".to_string()
            }
            RemediationTarget::ManualOnly => {
                "No API path exists for this control — perform the Fix Text steps yourself, \
                 then confirm to record that it was done manually"
                    .to_string()
            }
        }
    }

    /// Whether the wizard must collect free text from the user before this
    /// target can be applied.
    pub fn needs_text_input(&self) -> bool {
        matches!(self, RemediationTarget::SetSignInBanner { .. })
    }
}

/// User-supplied input the wizard collects for targets where
/// `needs_text_input()` is true.
#[derive(Debug, Clone, Default)]
pub struct RemediationInputs {
    pub text: Option<String>,
}

/// What happened when a `RemediationTarget` was applied (or acknowledged).
#[derive(Debug, Clone)]
pub enum RemediationOutcome {
    Applied { summary: String },
    ManuallyAcknowledged,
    Failed { error: String },
}

impl RemediationOutcome {
    pub fn label(&self) -> &'static str {
        match self {
            RemediationOutcome::Applied { .. } => "applied",
            RemediationOutcome::ManuallyAcknowledged => "manually_acknowledged",
            RemediationOutcome::Failed { .. } => "failed",
        }
    }

    pub fn detail(&self) -> String {
        match self {
            RemediationOutcome::Applied { summary } => summary.clone(),
            RemediationOutcome::ManuallyAcknowledged => String::new(),
            RemediationOutcome::Failed { error } => error.clone(),
        }
    }
}
