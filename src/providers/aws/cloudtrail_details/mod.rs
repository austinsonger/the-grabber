mod trail_collectors;
mod event_collectors;

pub use trail_collectors::{
    CloudTrailEventSelectorsCollector,
    CloudTrailLogValidationCollector,
    CloudTrailS3PolicyCollector,
};
pub use event_collectors::{CloudTrailChangeEventsCollector, S3DataEventsCollector};

// ─── helpers ──────────────────────────────────────────────────────────────────

pub(super) fn fmt_dt(dt: &aws_sdk_cloudtrail::primitives::DateTime) -> String {
    chrono::DateTime::<chrono::Utc>::from_timestamp(dt.secs(), 0)
        .map(|c| c.to_rfc3339())
        .unwrap_or_default()
}
