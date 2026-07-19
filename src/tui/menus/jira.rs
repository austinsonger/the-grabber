//! Jira collector menu. 28 collectors across 6 categories.

use super::ProviderCategory;

pub const JIRA_CATEGORIES: &[ProviderCategory] = &[
    ProviderCategory {
        name: "Core",
        items: &[
            ("jira-projects", "Projects                 "),
            ("jira-issues", "Issues                   "),
        ],
    },
    ProviderCategory {
        name: "SLA Tracking",
        items: &[
            ("jira-offboarding-sla", "Offboarding SLA         "),
            ("jira-ir-external", "IR: External Reporting SLA"),
            ("jira-sanctions-isso", "Sanctions ISSO Notify   "),
            ("jira-transfer-notify", "Transfer Notifications  "),
        ],
    },
    ProviderCategory {
        name: "Access & Approvals",
        items: &[
            ("jira-remote-access-approvals", "Remote Access Approvals "),
            (
                "jira-external-system-approvals",
                "External System Approvals",
            ),
            ("jira-remote-maint", "Remote Maintenance      "),
            ("jira-special-protection", "Special Protection      "),
        ],
    },
    ProviderCategory {
        name: "Change Management",
        items: &[
            ("jira-change-retention", "Change Retention        "),
            ("jira-cp-update", "CP Update Trigger       "),
            ("jira-cp-test-poam", "CP Test POAM            "),
            ("jira-baseline-exceptions", "Baseline Exceptions     "),
            ("jira-allowlist-review", "Allowlist Review        "),
            ("jira-patch-test", "Patch Test Records      "),
            ("jira-sw-license", "SW License Review       "),
        ],
    },
    ProviderCategory {
        name: "Incident Response",
        items: &[
            ("jira-ir-cp", "IR: CP Coordination     "),
            ("jira-ir-lessons", "IR: Lessons Learned     "),
            ("jira-ir-severity", "IR: Severity vs Rigor   "),
            ("jira-dr-test", "DR Test Results         "),
            ("jira-malware-fp", "Malware False Positive  "),
        ],
    },
    ProviderCategory {
        name: "Compliance & Review",
        items: &[
            ("jira-public-content", "Public Content Review   "),
            ("jira-logging-coordination", "Logging Coordination    "),
            ("jira-audit-posture", "Audit Posture Change    "),
            ("jira-isa-annual", "ISA Annual Review       "),
            ("jira-fw-exception", "Firewall Exception      "),
            ("jira-data-reassignment", "Data Reassignment       "),
        ],
    },
];
