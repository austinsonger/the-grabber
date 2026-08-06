//! Parsing for the S3 object keys Inspector writes during an SBOM export.
//!
//! Inspector lays an export out as:
//!
//! ```text
//! <key_prefix>/<FORMAT>_outputs_<report_id>/account=<account_id>/
//!   resource=AWS_ECR_CONTAINER_IMAGE/
//!   arn:aws:ecr:<region>:<account_id>:repository_<repo>_<digest>_<FORMAT>.json
//! ```
//!
//! The repository name and image digest are recovered from the key, not the
//! JSON body — the body does not carry the repository name in a stable place.

use aws_sdk_inspector2::types::SbomReportFormat;

/// One exported SBOM object, identified by the repository and image digest
/// encoded in its S3 key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportedSbom {
    pub key: String,
    pub repository: String,
    /// Full digest, including the `sha256:` prefix.
    pub digest: String,
}

/// True when `key` belongs to the export identified by `report_id`.
pub fn belongs_to_report(key: &str, report_id: &str) -> bool {
    key.contains(&format!("_outputs_{report_id}/"))
}

/// Recover the repository name and image digest from an exported object key.
/// Returns `None` for keys that are not ECR container-image SBOMs.
pub fn parse_export_key(key: &str) -> Option<ExportedSbom> {
    // Search the whole key rather than only its last path segment: ECR
    // repository names may contain `/` (e.g. `team/service`), which would
    // otherwise be mistaken for a key separator.
    // Anchor on the ARN's `:repository_` segment, not a bare `repository_`:
    // the key begins with a user-supplied prefix that could contain the latter.
    let after_marker = key.split_once(":repository_")?.1;

    // `:` is not legal in an ECR repository name, so the first `_sha256:`
    // is always the repository/digest boundary even when the repository name
    // itself contains underscores.
    let (repository, tail) = after_marker.split_once("_sha256:")?;
    let hex = tail.split_once('_')?.0;

    if repository.is_empty() || hex.is_empty() || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }

    Some(ExportedSbom {
        key: key.to_string(),
        repository: repository.to_string(),
        digest: format!("sha256:{hex}"),
    })
}

/// Filesystem-safe leaf name for a repository — ECR allows `/` in names.
pub fn sanitize_repo_name(repository: &str) -> String {
    repository.replace('/', "_")
}

/// Filename stem for a report format, used in the local output filenames.
pub fn format_stem(format: &SbomReportFormat) -> &'static str {
    match format {
        SbomReportFormat::Spdx23 => "spdx",
        _ => "cyclonedx",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const REAL_KEY: &str = "CYCLONEDX_1_4_outputs_75fe89e2-aad1-4a7e-8240-44d70e687eeb/\
account=187940674018/resource=AWS_ECR_CONTAINER_IMAGE/\
arn:aws:ecr:us-east-1:187940674018:repository_webapp-legacyassets_\
sha256:1ffd88db3d0754bceaa663a63a789c6b57bce154af36c8a2f7210bfaed943660_CYCLONEDX_1_4.json";

    #[test]
    fn parses_a_real_export_key() {
        let parsed = parse_export_key(REAL_KEY).expect("real key should parse");
        assert_eq!(parsed.repository, "webapp-legacyassets");
        assert_eq!(
            parsed.digest,
            "sha256:1ffd88db3d0754bceaa663a63a789c6b57bce154af36c8a2f7210bfaed943660"
        );
        assert_eq!(parsed.key, REAL_KEY);
    }

    #[test]
    fn parses_repository_names_containing_underscores() {
        let key = "p/CYCLONEDX_1_4_outputs_r/arn:aws:ecr:us-east-1:1:repository_my_app_name_\
sha256:abc123_CYCLONEDX_1_4.json";
        let parsed = parse_export_key(key).expect("underscored repo should parse");
        assert_eq!(parsed.repository, "my_app_name");
        assert_eq!(parsed.digest, "sha256:abc123");
    }

    #[test]
    fn parses_namespaced_repository_names() {
        // ECR allows `/` in repository names; the parser must not treat it as
        // a key separator.
        let key = "CYCLONEDX_1_4_outputs_r/arn:aws:ecr:us-east-1:1:repository_team/service_\
sha256:def456_CYCLONEDX_1_4.json";
        let parsed = parse_export_key(key).expect("namespaced repo should parse");
        assert_eq!(parsed.repository, "team/service");
        assert_eq!(parsed.digest, "sha256:def456");
    }

    #[test]
    fn parses_spdx_keys() {
        let key = "arn:aws:ecr:us-east-1:1:repository_app_sha256:aa11_SPDX_2_3.json";
        let parsed = parse_export_key(key).expect("spdx key should parse");
        assert_eq!(parsed.repository, "app");
        assert_eq!(parsed.digest, "sha256:aa11");
    }

    #[test]
    fn rejects_non_ecr_and_malformed_keys() {
        // Lambda resources carry no `repository_` marker.
        assert!(parse_export_key(
            "CYCLONEDX_1_4_outputs_r/resource=AWS_LAMBDA_FUNCTION/arn:aws:lambda:x:1:function_f.json"
        )
        .is_none());
        // No digest segment.
        assert!(
            parse_export_key("arn:aws:ecr:us-east-1:1:repository_app_CYCLONEDX_1_4.json").is_none()
        );
        // Empty repository name.
        assert!(parse_export_key(
            "arn:aws:ecr:us-east-1:1:repository__sha256:aa11_CYCLONEDX_1_4.json"
        )
        .is_none());
        // Non-hex digest.
        assert!(parse_export_key(
            "arn:aws:ecr:us-east-1:1:repository_app_sha256:zzzz_CYCLONEDX_1_4.json"
        )
        .is_none());
        // Digest not terminated by `_`.
        assert!(parse_export_key("arn:aws:ecr:us-east-1:1:repository_app_sha256:aa11").is_none());
    }

    #[test]
    fn belongs_to_report_matches_only_its_own_report() {
        assert!(belongs_to_report(
            REAL_KEY,
            "75fe89e2-aad1-4a7e-8240-44d70e687eeb"
        ));
        assert!(!belongs_to_report(
            REAL_KEY,
            "00000000-0000-0000-0000-000000000000"
        ));
        // A report id appearing outside the `_outputs_<id>/` segment must not match.
        assert!(!belongs_to_report("prefix-abc/arn:...json", "abc"));
    }

    #[test]
    fn a_key_prefix_containing_repository_does_not_confuse_the_anchor() {
        let key = "repository_backups/CYCLONEDX_1_4_outputs_r/\
arn:aws:ecr:us-east-1:1:repository_real-app_sha256:aa11_CYCLONEDX_1_4.json";
        let parsed = parse_export_key(key).expect("should anchor on the ARN segment");
        assert_eq!(parsed.repository, "real-app");
        assert_eq!(parsed.digest, "sha256:aa11");
    }

    #[test]
    fn sanitizes_namespaced_repository_names() {
        assert_eq!(sanitize_repo_name("team/service"), "team_service");
        assert_eq!(sanitize_repo_name("plain"), "plain");
    }

    #[test]
    fn format_stem_maps_both_formats() {
        assert_eq!(format_stem(&SbomReportFormat::Cyclonedx14), "cyclonedx");
        assert_eq!(format_stem(&SbomReportFormat::Spdx23), "spdx");
    }
}
