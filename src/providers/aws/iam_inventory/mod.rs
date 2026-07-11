mod access_keys;
mod policy;
mod role;
mod user;

pub use access_keys::IamAccessKeyCollector;
pub use policy::IamPolicyCollector;
pub use role::IamRoleCollector;
pub use user::IamUserCollector;

// ---------------------------------------------------------------------------
// Shared helpers (pub(super) so submodules can reach them via super::)
// ---------------------------------------------------------------------------

pub(super) fn fmt_iam_dt(dt: &aws_sdk_iam::primitives::DateTime) -> String {
    chrono::DateTime::<chrono::Utc>::from_timestamp(dt.secs(), dt.subsec_nanos())
        .map(|c| c.to_rfc3339())
        .unwrap_or_default()
}

/// Minimal URL-decode for IAM policy documents (handles the characters AWS encodes).
pub(super) fn url_decode(s: &str) -> String {
    s.replace("%22", "\"")
        .replace("%7B", "{")
        .replace("%7D", "}")
        .replace("%5B", "[")
        .replace("%5D", "]")
        .replace("%3A", ":")
        .replace("%2F", "/")
        .replace("%2C", ",")
        .replace("%20", " ")
        .replace("%0A", " ")
        .replace("+", " ")
}

/// Summarize principals from a URL-encoded trust policy JSON.
pub(super) fn trust_policy_principals(encoded: &str) -> String {
    let decoded = url_decode(encoded);
    // Quick extraction: find "Principal" and grab the next 300 chars.
    if let Some(idx) = decoded.find("\"Principal\"") {
        let snippet = &decoded[idx..];
        let end = snippet.len().min(300);
        snippet[..end].replace('\n', " ").replace("  ", " ")
    } else {
        decoded.chars().take(200).collect()
    }
}

pub(super) fn summarize_policy_actions(doc: &str) -> String {
    // Rough extraction of "Action" values from the JSON policy document.
    let mut actions = Vec::new();
    let mut rest = doc;
    while let Some(idx) = rest.find("\"Action\"") {
        rest = &rest[idx + 8..];
        // Skip to first quote or bracket after the colon
        if let Some(start) = rest.find('"') {
            let snippet = &rest[start + 1..];
            if let Some(end) = snippet.find('"') {
                actions.push(snippet[..end].to_string());
            }
        }
        if actions.len() >= 5 {
            break;
        }
    }
    if actions.is_empty() {
        doc.chars().take(150).collect()
    } else {
        let mut result = actions.join(", ");
        if doc.matches("\"Action\"").count() > 5 {
            result.push_str(", ...");
        }
        result
    }
}
