use anyhow::Result;
use async_trait::async_trait;
use aws_sdk_kinesis::Client as KinesisClient;

use crate::evidence::CsvCollector;

// ---------------------------------------------------------------------------
// Kinesis Data Streams — encryption, retention, stream mode
// ---------------------------------------------------------------------------

pub struct KinesisStreamsCollector {
    client: KinesisClient,
}

impl KinesisStreamsCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self {
            client: KinesisClient::new(config),
        }
    }
}

#[async_trait]
impl CsvCollector for KinesisStreamsCollector {
    fn name(&self) -> &str {
        "Kinesis Data Streams"
    }
    fn filename_prefix(&self) -> &str {
        "Kinesis_DataStreams"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Stream Name",
            "Stream ARN",
            "Mode",
            "Retention (hours)",
            "Encryption Type",
            "KMS Key",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let mut rows = Vec::new();
        let mut next_token: Option<String> = None;

        loop {
            let mut req = self.client.list_streams();
            if let Some(ref t) = next_token {
                req = req.next_token(t);
            }
            let resp = match req.send().await {
                Ok(r) => r,
                Err(e) => {
                    let msg = format!("{e:#}");
                    if msg.contains("not supported")
                        || msg.contains("not available")
                        || msg.contains("UnsupportedOperation")
                    {
                        return Ok(rows);
                    }
                    eprintln!("  WARN: Kinesis list_streams: {e:#}");
                    return Ok(rows);
                }
            };

            for name in resp.stream_names() {
                let summary = match self
                    .client
                    .describe_stream_summary()
                    .stream_name(name)
                    .send()
                    .await
                {
                    Ok(r) => r.stream_description_summary().cloned(),
                    Err(e) => {
                        eprintln!("  WARN: Kinesis describe_stream_summary {name}: {e:#}");
                        None
                    }
                };

                let (arn, mode, retention, enc, key) = match summary {
                    Some(s) => {
                        let arn = s.stream_arn().to_string();
                        let mode = s
                            .stream_mode_details()
                            .map(|m| m.stream_mode().as_str().to_string())
                            .unwrap_or_default();
                        let retention = s.retention_period_hours().to_string();
                        let enc = s
                            .encryption_type()
                            .map(|e| e.as_str().to_string())
                            .unwrap_or_default();
                        let key = s.key_id().unwrap_or("").to_string();
                        (arn, mode, retention, enc, key)
                    }
                    None => (
                        String::new(),
                        String::new(),
                        String::new(),
                        String::new(),
                        String::new(),
                    ),
                };

                rows.push(vec![name.to_string(), arn, mode, retention, enc, key]);
            }

            next_token = resp.next_token().map(|s| s.to_string());
            if next_token.is_none() {
                break;
            }
        }

        Ok(rows)
    }
}
