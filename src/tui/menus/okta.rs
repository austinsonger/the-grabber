//! Okta collector menu. 24 collectors across 5 categories.

use super::ProviderCategory;

pub const OKTA_CATEGORIES: &[ProviderCategory] = &[
    ProviderCategory {
        name: "Directory & Membership",
        items: &[
            ("okta-users", "Users                    "),
            ("okta-groups", "Groups                   "),
            ("okta-group-members", "Group Members            "),
            ("okta-apps", "Applications             "),
            ("okta-shared-groups", "Shared Group Inventory  "),
            ("okta-publisher-groups", "Publisher Groups        "),
        ],
    },
    ProviderCategory {
        name: "Authentication & Sessions",
        items: &[
            ("okta-policies", "Policies                 "),
            ("okta-signin-widget", "Sign-In Widget Config   "),
            ("okta-session-policy", "Session Policy          "),
            ("okta-password-policy", "Password Policy         "),
            ("okta-factors", "MFA Factors              "),
            ("okta-shared-account-broker", "Shared-Account Broker   "),
        ],
    },
    ProviderCategory {
        name: "Lifecycle & Provisioning",
        items: &[
            ("okta-deprovisioning", "Deprovisioning Timeliness"),
            ("okta-auto-provisioning", "Automated Provisioning  "),
            ("okta-hris-config", "HRIS Integration Config "),
            ("okta-offboarding-sla", "Offboarding SLA         "),
            ("okta-contractor-deprov", "Contractor Deprovisioning"),
            ("okta-transfer-diff", "Transfer Access Diff    "),
        ],
    },
    ProviderCategory {
        name: "Access Governance",
        items: &[
            ("okta-access-reviews", "Access Certification    "),
            ("okta-prod-recert", "Prod Access Recert      "),
            ("okta-group-changes", "Group Membership Changes"),
            ("okta-risk-suspend", "Risk-Account Suspend    "),
        ],
    },
    ProviderCategory {
        name: "Threat Detection & Logs",
        items: &[
            ("okta-threat-insight", "ThreatInsight Detections"),
            ("okta-system-log", "System Log Events        "),
        ],
    },
];
