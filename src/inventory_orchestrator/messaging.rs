use anyhow::Result;
use aws_sdk_eventbridge::Client as EventBridgeClient;
use aws_sdk_firehose::Client as FirehoseClient;
use aws_sdk_kinesis::Client as KinesisClient;
use aws_sdk_sns::Client as SnsClient;
use aws_sdk_sqs::Client as SqsClient;

pub(super) async fn collect_sns_topics(_c: &SnsClient, _region: &str) -> Result<Vec<Vec<String>>> {
    Ok(Vec::new())
}
pub(super) async fn collect_sqs_queues(_c: &SqsClient, _region: &str) -> Result<Vec<Vec<String>>> {
    Ok(Vec::new())
}
pub(super) async fn collect_kinesis_streams(_c: &KinesisClient, _region: &str) -> Result<Vec<Vec<String>>> {
    Ok(Vec::new())
}
pub(super) async fn collect_firehose_streams(_c: &FirehoseClient, _region: &str) -> Result<Vec<Vec<String>>> {
    Ok(Vec::new())
}
pub(super) async fn collect_eventbridge(_c: &EventBridgeClient, _region: &str) -> Result<Vec<Vec<String>>> {
    Ok(Vec::new())
}
