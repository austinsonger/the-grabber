//! Elastic Security collector menu. 4 collectors across 2 categories.

use super::ProviderCategory;

pub const ELASTIC_CATEGORIES: &[ProviderCategory] = &[
    ProviderCategory {
        name: "Detection Engine",
        items: &[
            ("elastic-rules", "Detection Rules Inventory"),
            ("elastic-exceptions", "Exception List Items     "),
        ],
    },
    ProviderCategory {
        name: "Alerts & Case Management",
        items: &[
            ("elastic-alerts", "Security Alerts          "),
            ("elastic-cases", "Cases                    "),
        ],
    },
];
