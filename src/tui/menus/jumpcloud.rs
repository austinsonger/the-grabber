//! JumpCloud collector menu. 16 collectors across 5 categories.

use super::ProviderCategory;

pub const JUMPCLOUD_CATEGORIES: &[ProviderCategory] = &[
    ProviderCategory {
        name: "Identity",
        items: &[
            ("jumpcloud-users", "Users                    "),
            ("jumpcloud-user-groups", "User Groups              "),
            ("jumpcloud-user-group-members", "User Group Members       "),
            ("jumpcloud-mfa-factors", "MFA Factors              "),
            ("jumpcloud-admin-roles", "Admin Roles              "),
            ("jumpcloud-disabled-users", "Disabled Users           "),
        ],
    },
    ProviderCategory {
        name: "Applications",
        items: &[("jumpcloud-applications", "Applications")],
    },
    ProviderCategory {
        name: "Policy",
        items: &[
            ("jumpcloud-policies", "Policies       "),
            ("jumpcloud-password-policy", "Password Policy"),
            ("jumpcloud-session-policy", "Session Policy "),
        ],
    },
    ProviderCategory {
        name: "Audit & Security",
        items: &[
            ("jumpcloud-directory-insights", "Directory Insights"),
            ("jumpcloud-directory-alerts", "Directory Alerts  "),
        ],
    },
    ProviderCategory {
        name: "Devices",
        items: &[
            ("jumpcloud-systems", "Systems                       "),
            ("jumpcloud-system-groups", "System Groups                 "),
            (
                "jumpcloud-system-group-members",
                "System Group Members          ",
            ),
            (
                "jumpcloud-system-user-associations",
                "System-User Associations      ",
            ),
        ],
    },
];
