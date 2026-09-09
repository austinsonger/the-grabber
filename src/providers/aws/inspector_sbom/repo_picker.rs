//! Choosing which exported image SBOM represents a repository.
//!
//! Inspector only exports SBOMs for images it has actually scanned, so the
//! newest image in ECR is frequently absent from an export. A repository's
//! representative SBOM is therefore the newest image that is *both* still
//! present in ECR and present in the export.

use std::collections::HashSet;

/// A live ECR image, reduced to the fields the picker needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EcrImage {
    /// Full digest, including the `sha256:` prefix.
    pub digest: String,
    /// `imagePushedAt` as epoch seconds. Images with no timestamp sort oldest.
    pub pushed_at_secs: i64,
    pub tags: Vec<String>,
}

/// The newest image (by `pushed_at_secs`) whose digest appears in `exported`.
pub fn newest_exported<'a>(
    images: &'a [EcrImage],
    exported: &HashSet<String>,
) -> Option<&'a EcrImage> {
    images
        .iter()
        .filter(|i| exported.contains(&i.digest))
        .max_by_key(|i| i.pushed_at_secs)
}

/// Every exported digest, newest ECR image first. Digests that are no longer
/// present in ECR sort last, in lexicographic order for run-to-run stability.
pub fn exported_newest_first(images: &[EcrImage], exported: &HashSet<String>) -> Vec<String> {
    let mut live: Vec<&EcrImage> = images
        .iter()
        .filter(|i| exported.contains(&i.digest))
        .collect();
    live.sort_by(|a, b| b.pushed_at_secs.cmp(&a.pushed_at_secs));

    let live_digests: HashSet<&str> = live.iter().map(|i| i.digest.as_str()).collect();
    let mut orphans: Vec<String> = exported
        .iter()
        .filter(|d| !live_digests.contains(d.as_str()))
        .cloned()
        .collect();
    orphans.sort();

    let mut out: Vec<String> = live.into_iter().map(|i| i.digest.clone()).collect();
    out.extend(orphans);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn img(digest: &str, pushed: i64) -> EcrImage {
        EcrImage {
            digest: digest.to_string(),
            pushed_at_secs: pushed,
            tags: vec![],
        }
    }

    fn set(digests: &[&str]) -> HashSet<String> {
        digests.iter().map(|d| d.to_string()).collect()
    }

    #[test]
    fn picks_the_newest_image_that_was_actually_exported() {
        // The regression this whole feature exists for: the newest image in
        // ECR (`newest`) was never scanned, so it is absent from the export.
        let images = vec![img("newest", 300), img("middle", 200), img("oldest", 100)];
        let exported = set(&["middle", "oldest"]);

        let chosen = newest_exported(&images, &exported).expect("middle should be chosen");
        assert_eq!(chosen.digest, "middle");
    }

    #[test]
    fn returns_none_when_no_exported_digest_is_still_in_ecr() {
        let images = vec![img("a", 100)];
        assert!(newest_exported(&images, &set(&["gone"])).is_none());
    }

    #[test]
    fn returns_none_for_an_empty_export() {
        let images = vec![img("a", 100)];
        assert!(newest_exported(&images, &HashSet::new()).is_none());
    }

    #[test]
    fn images_without_a_push_timestamp_lose_to_timestamped_ones() {
        let images = vec![img("undated", 0), img("dated", 50)];
        let chosen = newest_exported(&images, &set(&["undated", "dated"])).expect("a pick");
        assert_eq!(chosen.digest, "dated");
    }

    #[test]
    fn orders_exported_digests_newest_first() {
        let images = vec![img("a", 100), img("b", 300), img("c", 200)];
        let ordered = exported_newest_first(&images, &set(&["a", "b", "c"]));
        assert_eq!(ordered, vec!["b", "c", "a"]);
    }

    #[test]
    fn orphaned_digests_sort_last_and_deterministically() {
        // `zz` and `yy` were exported but are no longer in ECR. They must come
        // after every live image, in a stable order across runs.
        let images = vec![img("live-old", 100), img("live-new", 200)];
        let ordered = exported_newest_first(&images, &set(&["live-old", "live-new", "zz", "yy"]));
        assert_eq!(ordered, vec!["live-new", "live-old", "yy", "zz"]);
    }

    #[test]
    fn ignores_live_images_that_were_not_exported() {
        let images = vec![img("exported", 100), img("not-exported", 200)];
        let ordered = exported_newest_first(&images, &set(&["exported"]));
        assert_eq!(ordered, vec!["exported"]);
    }
}
