use anyhow::Result;
use async_trait::async_trait;
use aws_sdk_kafka::types::ClusterType;
use aws_sdk_kafka::Client as KafkaClient;

use crate::evidence::CsvCollector;

// ---------------------------------------------------------------------------
// MSK (Kafka) Clusters — encryption, client auth, broker logging
// ---------------------------------------------------------------------------

pub struct MskClustersCollector {
    client: KafkaClient,
}

impl MskClustersCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self {
            client: KafkaClient::new(config),
        }
    }
}

#[async_trait]
impl CsvCollector for MskClustersCollector {
    fn name(&self) -> &str {
        "MSK Clusters"
    }
    fn filename_prefix(&self) -> &str {
        "MSK_Clusters"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Cluster ARN",
            "Name",
            "State",
            "Type",
            "At-Rest KMS",
            "In-Transit Client-Broker",
            "SASL/SCRAM",
            "IAM Auth",
            "Broker Logs CW",
            "Broker Logs S3",
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
            let mut req = self.client.list_clusters_v2();
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
                    eprintln!("  WARN: MSK list_clusters_v2: {e:#}");
                    return Ok(rows);
                }
            };

            for cluster in resp.cluster_info_list() {
                let arn = cluster.cluster_arn().unwrap_or("").to_string();
                let name = cluster.cluster_name().unwrap_or("").to_string();
                let state = cluster
                    .state()
                    .map(|s| s.as_str().to_string())
                    .unwrap_or_default();
                let ctype = cluster
                    .cluster_type()
                    .map(|t| t.as_str().to_string())
                    .unwrap_or_default();

                let is_provisioned =
                    matches!(cluster.cluster_type(), Some(ClusterType::Provisioned));

                let (at_rest_kms, ib_client_broker, sasl_scram, iam_auth, cw_logs, s3_logs) =
                    if is_provisioned {
                        if let Some(p) = cluster.provisioned() {
                            let (at_rest, in_transit) = match p.encryption_info() {
                                Some(ei) => (
                                    ei.encryption_at_rest()
                                        .and_then(|e| e.data_volume_kms_key_id())
                                        .unwrap_or("")
                                        .to_string(),
                                    ei.encryption_in_transit()
                                        .and_then(|t| t.client_broker())
                                        .map(|cb| cb.as_str().to_string())
                                        .unwrap_or_default(),
                                ),
                                None => (String::new(), String::new()),
                            };
                            let (scram, iam) = match p.client_authentication() {
                                Some(ca) => match ca.sasl() {
                                    Some(sasl) => (
                                        sasl.scram()
                                            .and_then(|s| s.enabled())
                                            .map(yn)
                                            .unwrap_or_default(),
                                        sasl.iam()
                                            .and_then(|i| i.enabled())
                                            .map(yn)
                                            .unwrap_or_default(),
                                    ),
                                    None => (String::new(), String::new()),
                                },
                                None => (String::new(), String::new()),
                            };
                            let (cw, s3) = match p.logging_info() {
                                Some(li) => match li.broker_logs() {
                                    Some(bl) => (
                                        bl.cloud_watch_logs()
                                            .and_then(|c| c.enabled())
                                            .map(yn)
                                            .unwrap_or_default(),
                                        bl.s3()
                                            .and_then(|s| s.enabled())
                                            .map(yn)
                                            .unwrap_or_default(),
                                    ),
                                    None => (String::new(), String::new()),
                                },
                                None => (String::new(), String::new()),
                            };
                            (at_rest, in_transit, scram, iam, cw, s3)
                        } else {
                            (
                                String::new(),
                                String::new(),
                                String::new(),
                                String::new(),
                                String::new(),
                                String::new(),
                            )
                        }
                    } else {
                        (
                            String::new(),
                            String::new(),
                            String::new(),
                            String::new(),
                            String::new(),
                            String::new(),
                        )
                    };

                rows.push(vec![
                    arn,
                    name,
                    state,
                    ctype,
                    at_rest_kms,
                    ib_client_broker,
                    sasl_scram,
                    iam_auth,
                    cw_logs,
                    s3_logs,
                ]);
            }

            next_token = resp.next_token().map(|s| s.to_string());
            if next_token.is_none() {
                break;
            }
        }

        Ok(rows)
    }
}

fn yn(v: bool) -> String {
    if v {
        "Yes".to_string()
    } else {
        "No".to_string()
    }
}
