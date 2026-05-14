mod event_collectors;
mod trail_collectors;

pub use event_collectors::{CloudTrailChangeEventsCollector, S3DataEventsCollector};
pub use trail_collectors::{
    CloudTrailEventSelectorsCollector, CloudTrailLogValidationCollector,
    CloudTrailS3PolicyCollector,
};

// ─── helpers ──────────────────────────────────────────────────────────────────

pub(super) fn fmt_dt(dt: &aws_sdk_cloudtrail::primitives::DateTime) -> String {
    chrono::DateTime::<chrono::Utc>::from_timestamp(dt.secs(), 0)
        .map(|c| c.to_rfc3339())
        .unwrap_or_default()
}
