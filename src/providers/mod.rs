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

#[cfg(feature = "elastic")]
pub mod elastic;

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
    Elastic,
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
            CloudProvider::Elastic => write!(f, "Elastic"),
        }
    }
}

impl CloudProvider {
    /// Every provider compiled into this build, in canonical UI order.
    /// Single source of truth for the Provider Selection screen — both
    /// the renderer and the key handler call this instead of maintaining
    /// their own copies.
    #[allow(dead_code)]
    pub fn available() -> Vec<CloudProvider> {
        let mut v = vec![CloudProvider::Aws];
        #[cfg(feature = "azure")]
        v.push(CloudProvider::Azure);
        #[cfg(feature = "gcp")]
        v.push(CloudProvider::Gcp);
        #[cfg(feature = "tenable")]
        v.push(CloudProvider::Tenable);
        #[cfg(feature = "okta")]
        v.push(CloudProvider::Okta);
        #[cfg(feature = "jira")]
        v.push(CloudProvider::Jira);
        #[cfg(feature = "elastic")]
        v.push(CloudProvider::Elastic);
        v
    }

    /// Long-form display name for the Provider Selection UI, e.g.
    /// "Amazon Web Services (AWS)". Distinct from `Display`, which yields
    /// the short form ("AWS") used in filenames/report metadata.
    #[allow(dead_code)]
    pub fn display_name(&self) -> &'static str {
        match self {
            CloudProvider::Aws => "Amazon Web Services (AWS)",
            CloudProvider::Azure => "Microsoft Azure",
            CloudProvider::Gcp => "Google Cloud Platform (GCP)",
            CloudProvider::Tenable => "Tenable",
            CloudProvider::Okta => "Okta",
            CloudProvider::Jira => "Jira",
            CloudProvider::Elastic => "Elastic Security",
        }
    }

    /// One-line description shown in the Provider Selection detail panel.
    #[allow(dead_code)]
    pub fn description(&self) -> &'static str {
        match self {
            CloudProvider::Aws => {
                "Run 100+ compliance evidence collectors (CloudTrail, S3, IAM, RDS, …)"
            }
            CloudProvider::Azure => "Collect compliance evidence from Azure resources",
            CloudProvider::Gcp => "Collect compliance evidence from GCP resources",
            CloudProvider::Tenable => "Export vulnerability findings from Tenable.io or Tenable.sc",
            CloudProvider::Okta => {
                "Collect users, groups, apps, policies, MFA factors, and system log events"
            }
            CloudProvider::Jira => "Collect projects and issues from Jira Cloud or Jira Server",
            CloudProvider::Elastic => {
                "Collect detection rules, exception items, alerts, and cases from Elastic SIEM"
            }
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
