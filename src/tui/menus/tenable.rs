//! Tenable collector menu. 5 collectors, one category.
//! Selectors verified against src/providers/tenable/factory.rs (the plan's
//! draft used tenable-scans/tenable-audit-log, which do not exist).

use super::ProviderCategory;

pub const TENABLE_CATEGORIES: &[ProviderCategory] = &[ProviderCategory {
    name: "Vulnerability Scanning",
    items: &[
        ("tenable-vulns", "Vulnerability Findings   "),
        ("tenable-was", "Web App Scanning         "),
        ("tenable-pci-asv", "PCI ASV Compliance       "),
        ("tenable-assets", "Asset Inventory          "),
        ("tenable-compliance", "Compliance Findings      "),
    ],
}];
