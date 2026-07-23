//! Loader for the bundled Okta DISA STIG (Okta_IDaaS_STIG v1r1) metadata.
//!
//! Compiled into the binary via `include_str!`, same pattern as
//! `fedramp_map.rs`. This table is purely descriptive (V-ID, rule ID,
//! severity, title, check/fix text, CCI references, and the per-check
//! NIST 800-53 control IDs the STIG maps to) — no evaluation logic lives
//! here; that lives in `providers::okta::stig`.

use std::collections::BTreeMap;

use anyhow::{Context, Result};
use once_cell::sync::Lazy;
use serde::Deserialize;

const BUNDLED_JSON: &str = include_str!("../assets/okta-stig-map.json");

#[derive(Debug, Clone, Deserialize)]
pub struct StigCheckMeta {
    pub sv_rule_id: String,
    pub stig_id_version: String,
    pub severity: String,
    pub title: String,
    #[serde(default)]
    pub check_text: String,
    #[serde(default)]
    pub fix_text: String,
    #[serde(default)]
    pub cci: Vec<String>,
    /// NIST 800-53 control IDs this check maps to (e.g. `["AC-11", "SC-10"]`).
    /// Written verbatim to the "FedRAMP Req IDs" column. Unlike most
    /// collectors, a STIG checklist has one row per control, so this varies
    /// per V-ID rather than applying uniformly to the whole file.
    #[serde(default)]
    pub fedramp_req_ids: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct RawMap {
    #[serde(default)]
    schema: u32,
    #[serde(default)]
    checks: BTreeMap<String, StigCheckMeta>,
}

#[derive(Debug)]
pub struct OktaStigMap {
    checks: BTreeMap<String, StigCheckMeta>,
}

impl OktaStigMap {
    pub fn from_json(s: &str) -> Result<Self> {
        let raw: RawMap = serde_json::from_str(s).context("parse okta-stig-map.json")?;
        anyhow::ensure!(
            raw.schema == 1,
            "unsupported okta-stig-map schema {} (expected 1)",
            raw.schema
        );
        Ok(Self { checks: raw.checks })
    }

    pub fn get(&self, v_id: &str) -> Option<&StigCheckMeta> {
        self.checks.get(v_id)
    }
}

static BUNDLED: Lazy<OktaStigMap> = Lazy::new(|| {
    OktaStigMap::from_json(BUNDLED_JSON).expect("bundled okta-stig-map.json must parse")
});

pub fn bundled() -> &'static OktaStigMap {
    &BUNDLED
}
