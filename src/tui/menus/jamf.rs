//! Jamf collector menu. 9 collectors across 3 categories.

use super::ProviderCategory;

pub const JAMF_CATEGORIES: &[ProviderCategory] = &[
    ProviderCategory {
        name: "Device Inventory",
        items: &[
            ("jamf-computers", "Computers                "),
            ("jamf-mobile-devices", "Mobile Devices           "),
            ("jamf-computer-groups", "Computer Groups          "),
            ("jamf-mobile-device-groups", "Mobile Device Groups     "),
        ],
    },
    ProviderCategory {
        name: "Configuration & Policy",
        items: &[
            ("jamf-computer-config-profiles", "Computer Config Profiles "),
            ("jamf-mobile-config-profiles", "Mobile Config Profiles   "),
            ("jamf-policies", "Policies                 "),
        ],
    },
    ProviderCategory {
        name: "Patch Management",
        items: &[
            ("jamf-patch-titles", "Patch Titles             "),
            ("jamf-patch-compliance", "Patch Compliance         "),
        ],
    },
];
