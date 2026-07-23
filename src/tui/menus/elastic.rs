//! Elastic Security collector menu. 10 collectors across 5 categories.

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
            ("elastic-connectors", "Alerting Connectors      "),
        ],
    },
    ProviderCategory {
        name: "Identity & Access",
        items: &[
            ("elastic-users", "Security Users           "),
            ("elastic-roles", "Security Roles           "),
        ],
    },
    ProviderCategory {
        name: "Endpoint Management",
        items: &[
            ("elastic-agents", "Fleet Agents Inventory   "),
            ("elastic-fim", "File Integrity Monitoring"),
        ],
    },
    ProviderCategory {
        name: "Data Retention",
        items: &[("elastic-ilm", "ILM Retention Policies")],
    },
];
