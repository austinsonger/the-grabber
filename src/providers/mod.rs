//! Cloud provider abstractions.
//!
//! This module defines the `CloudProvider` enum and re-exports the concrete
//! provider sub-modules that are enabled via feature flags.

use serde::{Deserialize, Serialize};

/// Identifies the target cloud platform for a configuration account.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CloudProvider {
    Aws,
    #[cfg(feature = "azure")]
    Azure,
    #[cfg(feature = "gcp")]
    Gcp,
}

impl Default for CloudProvider {
    fn default() -> Self {
        CloudProvider::Aws
    }
}

#[cfg(feature = "azure")]
pub mod azure;

#[cfg(feature = "gcp")]
pub mod gcp;
