//! Classifies collector failures into expected (Skipped) vs unexpected (Error).
//!
//! Some AWS API errors are expected operating conditions (service not enabled,
//! member account without org perms, etc.) — we don't want them noisily shown
//! in the red Errors panel.

/// If the (collector, error message) pair matches a known-benign failure mode,
/// returns `Some(reason_label)`. Caller should send `Progress::Skipped` with
/// that label instead of `Progress::Error`.
pub fn classify_failure(collector: &str, message: &str) -> Option<&'static str> {
    let lower = message.to_lowercase();

    // Permission denials — expected when running against member accounts
    // or accounts without the relevant IAM grant.
    if lower.contains("accessdenied")
        || lower.contains("access denied")
        || lower.contains("unauthorizedoperation")
        || lower.contains("not authorized to perform")
        || lower.contains("user is not authorized")
    {
        return Some("Access denied — permission not granted");
    }

    // GuardDuty: BadRequestException means no detector / service not enabled here.
    if collector.to_lowercase().contains("guardduty")
        && (lower.contains("badrequestexception")
            || lower.contains("no detector")
            || lower.contains("not enabled"))
    {
        return Some("GuardDuty not enabled in this region");
    }

    // Macie: enable-check errors.
    if collector.to_lowercase().contains("macie")
        && (lower.contains("not subscribed") || lower.contains("not enabled"))
    {
        return Some("Macie not enabled in this region");
    }

    // Inspector2 ECR timeouts — expected for large registries; do not error out.
    if collector.to_lowercase().contains("inspector2 ecr") && lower.contains("timed out") {
        return Some("Inspector2 ECR scan exceeded timeout (expected for large registries)");
    }

    None
}

/// Convenience: same logic, but only for the timeout path (collector message
/// is the synthesized `"timed out after N minutes"` from the runner).
pub fn classify_timeout(collector: &str) -> Option<&'static str> {
    let lc = collector.to_lowercase();
    if lc.contains("inspector2 ecr") {
        Some("Inspector2 ECR scan exceeded timeout (expected for large registries)")
    } else {
        None
    }
}
