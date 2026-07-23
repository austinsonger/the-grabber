//! GitHub collector menu. 10 collectors across 3 categories.

use super::ProviderCategory;

pub const GITHUB_CATEGORIES: &[ProviderCategory] = &[
    ProviderCategory {
        name: "Access Control",
        items: &[
            ("github-members", "Org Members            "),
            ("github-teams", "Org Teams              "),
            ("github-team-members", "Team Membership        "),
            ("github-security-settings", "Org Security Settings  "),
        ],
    },
    ProviderCategory {
        name: "Repositories & Change Control",
        items: &[
            ("github-repos", "Repositories           "),
            ("github-branch-protection", "Branch Protection      "),
        ],
    },
    ProviderCategory {
        name: "Audit & Security Alerts",
        items: &[
            ("github-audit-log", "Org Audit Log          "),
            ("github-dependabot-alerts", "Dependabot Alerts      "),
            ("github-secret-scanning-alerts", "Secret Scanning Alerts "),
            ("github-code-scanning-alerts", "Code Scanning Alerts   "),
        ],
    },
];
