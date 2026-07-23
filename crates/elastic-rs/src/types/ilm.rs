use serde::Deserialize;

/// One Index Lifecycle Management policy, flattened for CSV output. `name`
/// comes from the `_ilm/policy` response's map key, not the JSON body. The
/// `delete` phase's `min_age` is Elasticsearch's native expression of data
/// retention duration (e.g. "90d") — the direct evidence for AU-11-style
/// audit-record-retention requirements.
#[derive(Debug, Clone)]
pub struct IlmPolicy {
    pub name: String,
    pub modified_date: Option<String>,
    pub has_hot_phase: bool,
    pub has_warm_phase: bool,
    pub has_cold_phase: bool,
    pub has_frozen_phase: bool,
    pub has_delete_phase: bool,
    pub delete_min_age: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct IlmPolicyRaw {
    #[serde(default)]
    pub modified_date: Option<String>,
    #[serde(default)]
    pub policy: IlmPolicyBodyRaw,
}

/// The phase set varies per policy (not every policy has every phase), so
/// `phases` is kept as raw JSON and read defensively rather than through a
/// fixed per-phase struct — the same defensive-read rationale as `FimEvent`.
#[derive(Debug, Default, Deserialize)]
pub(crate) struct IlmPolicyBodyRaw {
    #[serde(default)]
    pub phases: serde_json::Value,
}
