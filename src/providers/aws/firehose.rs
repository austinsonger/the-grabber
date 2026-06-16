use anyhow::Result;
use async_trait::async_trait;
use aws_sdk_firehose::Client as FhClient;

use crate::evidence::CsvCollector;

// ══════════════════════════════════════════════════════════════════════════════
// Firehose Delivery Streams
// ══════════════════════════════════════════════════════════════════════════════

pub struct FirehoseDeliveryStreamsCollector {
    client: FhClient,
}

impl FirehoseDeliveryStreamsCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self {
            client: FhClient::new(config),
        }
    }
}

fn fmt_dt(dt: &aws_sdk_firehose::primitives::DateTime) -> String {
    chrono::DateTime::<chrono::Utc>::from_timestamp(dt.secs(), dt.subsec_nanos())
        .map(|c| c.to_rfc3339())
        .unwrap_or_default()
}

#[async_trait]
impl CsvCollector for FirehoseDeliveryStreamsCollector {
    fn name(&self) -> &str {
        "Firehose Delivery Streams"
    }
    fn filename_prefix(&self) -> &str {
        "Firehose_DeliveryStreams"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Stream Name",
            "Stream ARN",
            "Stream Status",
            "Source Type",
            "Destination Type",
            "Destination Bucket/Endpoint",
            "Encryption (KMS Key)",
            "Created Time",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let mut rows = Vec::new();

        // Manual pagination via exclusive_start_delivery_stream_name.
        let mut start: Option<String> = None;
        loop {
            let mut req = self.client.list_delivery_streams();
            if let Some(ref s) = start {
                req = req.exclusive_start_delivery_stream_name(s);
            }
            let resp = match req.send().await {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("  WARN: Firehose list_delivery_streams: {e:#}");
                    break;
                }
            };

            let names: Vec<String> = resp.delivery_stream_names().to_vec();
            if names.is_empty() {
                break;
            }

            for name in &names {
                let desc_resp = match self
                    .client
                    .describe_delivery_stream()
                    .delivery_stream_name(name)
                    .send()
                    .await
                {
                    Ok(r) => r,
                    Err(e) => {
                        eprintln!("  WARN: Firehose describe_delivery_stream {name}: {e:#}");
                        continue;
                    }
                };

                let Some(desc) = desc_resp.delivery_stream_description() else {
                    continue;
                };

                let stream_arn = desc.delivery_stream_arn().to_string();
                let status = desc.delivery_stream_status().as_str().to_string();

                // Source type: from delivery_stream_type, refined by source description.
                let source_type = if let Some(src) = desc.source() {
                    if src.direct_put_source_description().is_some() {
                        "DirectPut".to_string()
                    } else if src.kinesis_stream_source_description().is_some() {
                        "KinesisStreamAsSource".to_string()
                    } else if src.msk_source_description().is_some() {
                        "MSKAsSource".to_string()
                    } else if src.database_source_description().is_some() {
                        "DatabaseAsSource".to_string()
                    } else {
                        desc.delivery_stream_type().as_str().to_string()
                    }
                } else {
                    desc.delivery_stream_type().as_str().to_string()
                };

                // First destination: pick variant + endpoint identifier.
                let (dest_type, dest_endpoint) = if let Some(d) = desc.destinations().first() {
                    if let Some(s) = d.extended_s3_destination_description() {
                        ("ExtendedS3".to_string(), s.bucket_arn().to_string())
                    } else if let Some(s) = d.s3_destination_description() {
                        ("S3".to_string(), s.bucket_arn().to_string())
                    } else if let Some(_s) = d.redshift_destination_description() {
                        ("Redshift".to_string(), String::new())
                    } else if let Some(s) = d.elasticsearch_destination_description() {
                        (
                            "Elasticsearch".to_string(),
                            s.domain_arn().unwrap_or("").to_string(),
                        )
                    } else if let Some(s) = d.amazonopensearchservice_destination_description() {
                        (
                            "OpenSearch".to_string(),
                            s.domain_arn().unwrap_or("").to_string(),
                        )
                    } else if let Some(_s) = d.splunk_destination_description() {
                        ("Splunk".to_string(), String::new())
                    } else if let Some(s) = d.http_endpoint_destination_description() {
                        let url = s
                            .endpoint_configuration()
                            .and_then(|e| e.url())
                            .unwrap_or("")
                            .to_string();
                        ("HttpEndpoint".to_string(), url)
                    } else if let Some(_s) = d.snowflake_destination_description() {
                        ("Snowflake".to_string(), String::new())
                    } else if let Some(_s) =
                        d.amazon_open_search_serverless_destination_description()
                    {
                        ("OpenSearchServerless".to_string(), String::new())
                    } else if let Some(_s) = d.iceberg_destination_description() {
                        ("Iceberg".to_string(), String::new())
                    } else {
                        ("Unknown".to_string(), String::new())
                    }
                } else {
                    (String::new(), String::new())
                };

                let kms_key = desc
                    .delivery_stream_encryption_configuration()
                    .and_then(|c| c.key_arn())
                    .unwrap_or("")
                    .to_string();

                let created_time = desc.create_timestamp().map(fmt_dt).unwrap_or_default();

                rows.push(vec![
                    name.clone(),
                    stream_arn,
                    status,
                    source_type,
                    dest_type,
                    dest_endpoint,
                    kms_key,
                    created_time,
                ]);
            }

            if !resp.has_more_delivery_streams() {
                break;
            }
            start = names.last().cloned();
            if start.is_none() {
                break;
            }
        }

        Ok(rows)
    }
}
