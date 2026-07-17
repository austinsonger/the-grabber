use anyhow::Result;
use aws_sdk_cloudtrail::Client as CloudTrailClient;
use aws_sdk_config::Client as ConfigClient;
use aws_sdk_guardduty::Client as GuardDutyClient;
use aws_sdk_securityhub::Client as SecurityHubClient;
use aws_sdk_wafv2::Client as Wafv2Client;

pub(super) async fn collect_cloudtrail_trails(_c: &CloudTrailClient, _region: &str) -> Result<Vec<Vec<String>>> {
    Ok(Vec::new())
}
pub(super) async fn collect_config_recorders(_c: &ConfigClient, _account_id: &str, _region: &str) -> Result<Vec<Vec<String>>> {
    Ok(Vec::new())
}
pub(super) async fn collect_guardduty_detectors(_c: &GuardDutyClient, _account_id: &str, _region: &str) -> Result<Vec<Vec<String>>> {
    Ok(Vec::new())
}
pub(super) async fn collect_securityhub_hubs(_c: &SecurityHubClient, _region: &str) -> Result<Vec<Vec<String>>> {
    Ok(Vec::new())
}
pub(super) async fn collect_waf_webacls(_c: &Wafv2Client, _region: &str) -> Result<Vec<Vec<String>>> {
    Ok(Vec::new())
}
