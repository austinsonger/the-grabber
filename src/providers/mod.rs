pub mod aws;

#[cfg(feature = "azure")]
pub mod azure;

#[cfg(feature = "gcp")]
pub mod gcp;

#[cfg(feature = "tenable")]
pub mod tenable;

#[cfg(feature = "okta")]
pub mod okta;

#[cfg(feature = "jira")]
pub mod jira;

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::evidence::{CsvCollector, EvidenceCollector, JsonCollector};

// ---------------------------------------------------------------------------
// CloudProvider — identifies which system a collector belongs to
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[derive(Default)]
pub enum CloudProvider {
    #[default]
    Aws,
    Azure,
    Gcp,
    Tenable,
    Okta,
    Jira,
}

impl fmt::Display for CloudProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CloudProvider::Aws => write!(f, "AWS"),
            CloudProvider::Azure => write!(f, "Azure"),
            CloudProvider::Gcp => write!(f, "GCP"),
            CloudProvider::Tenable => write!(f, "Tenable"),
            CloudProvider::Okta => write!(f, "Okta"),
            CloudProvider::Jira => write!(f, "Jira"),
        }
    }
}

// ---------------------------------------------------------------------------
// ProviderFactory — the single contract every provider must implement
// ---------------------------------------------------------------------------

/// Implement this trait once per provider. The application layer calls these
/// methods to obtain collectors; it never imports provider-specific SDKs.
pub trait ProviderFactory: Send + Sync {
    /// The provider variant this factory represents.
    fn provider(&self) -> CloudProvider;

    /// Account/project/site identifier used to prefix output filenames.
    /// AWS: account ID  Azure: subscription ID  GCP: project ID  Tenable: site name
    fn account_id(&self) -> &str;

    /// Region, location, or scope label used in report metadata and output paths.
    /// Providers without a region concept (Tenable) return an empty string.
    fn region(&self) -> &str;

    /// Point-in-time CSV snapshot collectors (current resource state).
    fn csv_collectors(&self) -> Vec<Box<dyn CsvCollector>>;

    /// Structured JSON snapshot collectors (policy documents, configs).
    fn json_collectors(&self) -> Vec<Box<dyn JsonCollector>>;

    /// Time-windowed evidence collectors (event logs, findings).
    fn evidence_collectors(&self) -> Vec<Box<dyn EvidenceCollector>>;
}
