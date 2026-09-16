//! CrowdStrike collector menu. 5 collectors across 2 categories.

use super::ProviderCategory;

pub const CROWDSTRIKE_CATEGORIES: &[ProviderCategory] = &[
    ProviderCategory {
        name: "Detection & Response",
        items: &[
            ("crowdstrike-hosts", "Host Inventory           "),
            ("crowdstrike-alerts", "Alerts (Detections/Incidents)"),
        ],
    },
    ProviderCategory {
        name: "Vulnerability & Policy Management",
        items: &[
            ("crowdstrike-vulnerabilities", "Vulnerability Findings   "),
            (
                "crowdstrike-prevention-policies",
                "Prevention Policies      ",
            ),
            (
                "crowdstrike-sensor-update-policies",
                "Sensor Update Policies   ",
            ),
        ],
    },
];
