//! Per-provider TUI collector menu data. Each provider owns its own
//! category structure, keeping AWS-shaped categories from bleeding into
//! Okta/Jira/Tenable flows.

pub mod aws;
pub mod crowdstrike;
pub mod elastic;
pub mod github;
pub mod jamf;
pub mod jira;
pub mod okta;
pub mod tenable;

use crate::providers::CloudProvider;

pub struct ProviderCategory {
    pub name: &'static str,
    /// `(selector, display)` tuples. Selectors are the same strings the
    /// provider's factory.rs recognises in `has(...)` gates.
    pub items: &'static [(&'static str, &'static str)],
}

pub struct ProviderMenu {
    pub provider: CloudProvider,
    pub categories: &'static [ProviderCategory],
}

pub const PROVIDER_MENUS: &[ProviderMenu] = &[
    ProviderMenu {
        provider: CloudProvider::Aws,
        categories: aws::AWS_CATEGORIES,
    },
    ProviderMenu {
        provider: CloudProvider::Okta,
        categories: okta::OKTA_CATEGORIES,
    },
    ProviderMenu {
        provider: CloudProvider::Jira,
        categories: jira::JIRA_CATEGORIES,
    },
    ProviderMenu {
        provider: CloudProvider::Tenable,
        categories: tenable::TENABLE_CATEGORIES,
    },
    ProviderMenu {
        provider: CloudProvider::CrowdStrike,
        categories: crowdstrike::CROWDSTRIKE_CATEGORIES,
    },
    ProviderMenu {
        provider: CloudProvider::Elastic,
        categories: elastic::ELASTIC_CATEGORIES,
    },
    ProviderMenu {
        provider: CloudProvider::Jamf,
        categories: jamf::JAMF_CATEGORIES,
    },
    ProviderMenu {
        provider: CloudProvider::Github,
        categories: github::GITHUB_CATEGORIES,
    },
];

/// Return the menu for a provider. Panics with a clear message if the
/// provider has no menu registered — this is a build-time programming error.
pub fn menu_for(provider: CloudProvider) -> &'static ProviderMenu {
    PROVIDER_MENUS
        .iter()
        .find(|m| m.provider == provider)
        .unwrap_or_else(|| panic!("no TUI menu registered for provider {provider:?}"))
}
