//! Loader for the FedRAMP requirement/collector mapping table.
//!
//! The mapping is compiled into the binary via `include_str!` so grabber has
//! no runtime file dependency. All CSV and JSON evidence emission consults
//! this table to attach `FedRAMP Req IDs`, `FedRAMP Control IDs`, and
//! `Source Evidence File` metadata to every record.

use std::collections::BTreeMap;

use anyhow::{Context, Result};
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};

const BUNDLED_JSON: &str = include_str!("../assets/fedramp-map.json");

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FedRampMapping {
    #[serde(default)]
    pub req_ids: Vec<String>,
    #[serde(default)]
    pub control_ids: Vec<String>,
}

impl FedRampMapping {
    pub fn is_empty(&self) -> bool {
        self.req_ids.is_empty() && self.control_ids.is_empty()
    }

    /// Pipe-separated, sorted, deduped.
    pub fn req_ids_joined(&self) -> String {
        let mut v = self.req_ids.clone();
        v.sort();
        v.dedup();
        v.join("|")
    }

    pub fn control_ids_joined(&self) -> String {
        let mut v = self.control_ids.clone();
        v.sort();
        v.dedup();
        v.join("|")
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequirementInfo {
    pub control_id: String,
    pub family: String,
    #[serde(default)]
    pub description: String,
}

#[derive(Debug, Deserialize)]
struct RawMap {
    #[serde(default)]
    schema: u32,
    #[serde(default)]
    collectors: BTreeMap<String, FedRampMapping>,
    #[serde(default)]
    requirements: BTreeMap<String, RequirementInfo>,
}

#[derive(Debug)]
pub struct FedRampMap {
    collectors: BTreeMap<String, FedRampMapping>,
    requirements: BTreeMap<String, RequirementInfo>,
}

impl FedRampMap {
    pub fn from_json(s: &str) -> Result<Self> {
        let raw: RawMap = serde_json::from_str(s).context("parse fedramp-map.json")?;
        anyhow::ensure!(
            raw.schema == 1,
            "unsupported fedramp-map schema {} (expected 1)",
            raw.schema
        );
        Ok(Self {
            collectors: raw.collectors,
            requirements: raw.requirements,
        })
    }

    pub fn get(&self, filename_prefix: &str) -> FedRampMapping {
        self.collectors
            .get(filename_prefix)
            .cloned()
            .unwrap_or_default()
    }

    pub fn all_requirements(&self) -> &BTreeMap<String, RequirementInfo> {
        &self.requirements
    }

    /// All filename prefixes that carry at least one requirement mapping.
    pub fn mapped_prefixes(&self) -> impl Iterator<Item = &str> {
        self.collectors
            .iter()
            .filter(|(_, m)| !m.is_empty())
            .map(|(k, _)| k.as_str())
    }
}

static BUNDLED: Lazy<FedRampMap> = Lazy::new(|| {
    FedRampMap::from_json(BUNDLED_JSON).expect("bundled fedramp-map.json must parse")
});

pub fn bundled() -> &'static FedRampMap {
    &BUNDLED
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FedRampManifest {
    pub req_ids: Vec<String>,
    pub control_ids: Vec<String>,
    pub source_evidence_file: String,
}

impl FedRampManifest {
    pub fn new(mapping: &FedRampMapping, source_evidence_file: impl Into<String>) -> Self {
        let mut req_ids = mapping.req_ids.clone();
        req_ids.sort();
        req_ids.dedup();
        let mut control_ids = mapping.control_ids.clone();
        control_ids.sort();
        control_ids.dedup();
        Self {
            req_ids,
            control_ids,
            source_evidence_file: source_evidence_file.into(),
        }
    }
}
