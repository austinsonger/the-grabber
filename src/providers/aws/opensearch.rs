use anyhow::Result;
use async_trait::async_trait;
use aws_sdk_opensearch::types::LogType;
use aws_sdk_opensearch::Client as OpenSearchClient;

use crate::evidence::CsvCollector;

// ---------------------------------------------------------------------------
// OpenSearch Domains — encryption, HTTPS/TLS, VPC, audit logging
// ---------------------------------------------------------------------------

pub struct OpenSearchDomainsCollector {
    client: OpenSearchClient,
}

impl OpenSearchDomainsCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self {
            client: OpenSearchClient::new(config),
        }
    }
}

#[async_trait]
impl CsvCollector for OpenSearchDomainsCollector {
    fn name(&self) -> &str {
        "OpenSearch Domains"
    }
    fn filename_prefix(&self) -> &str {
        "OpenSearch_Domains"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Domain Name",
            "Engine",
            "At-Rest Encryption",
            "KMS Key",
            "Node-to-Node",
            "Enforce HTTPS",
            "TLS Policy",
            "VPC ID",
            "Audit Logs Enabled",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let mut rows = Vec::new();

        let list_resp = match self.client.list_domain_names().send().await {
            Ok(r) => r,
            Err(e) => {
                let msg = format!("{e:#}");
                if msg.contains("not supported")
                    || msg.contains("not available")
                    || msg.contains("UnsupportedOperation")
                {
                    return Ok(rows);
                }
                eprintln!("  WARN: OpenSearch list_domain_names: {e:#}");
                return Ok(rows);
            }
        };

        for di in list_resp.domain_names() {
            let name = match di.domain_name() {
                Some(n) => n.to_string(),
                None => continue,
            };

            let desc_resp = match self
                .client
                .describe_domain()
                .domain_name(&name)
                .send()
                .await
            {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("  WARN: OpenSearch describe_domain {name}: {e:#}");
                    continue;
                }
            };

            let status = match desc_resp.domain_status() {
                Some(s) => s,
                None => continue,
            };

            let engine = status.engine_version().unwrap_or("").to_string();
            let (at_rest, kms) = match status.encryption_at_rest_options() {
                Some(e) => (
                    bool_yn(e.enabled()),
                    e.kms_key_id().unwrap_or("").to_string(),
                ),
                None => (String::new(), String::new()),
            };
            let n2n = status
                .node_to_node_encryption_options()
                .and_then(|o| o.enabled())
                .map(yn)
                .unwrap_or_default();
            let (enforce_https, tls_policy) = match status.domain_endpoint_options() {
                Some(o) => (
                    bool_yn(o.enforce_https()),
                    o.tls_security_policy()
                        .map(|p| p.as_str().to_string())
                        .unwrap_or_default(),
                ),
                None => (String::new(), String::new()),
            };
            let vpc_id = status
                .vpc_options()
                .and_then(|v| v.vpc_id())
                .unwrap_or("")
                .to_string();
            let audit_enabled = status
                .log_publishing_options()
                .and_then(|m| m.get(&LogType::AuditLogs))
                .and_then(|opt| opt.enabled())
                .map(yn)
                .unwrap_or_default();

            rows.push(vec![
                name,
                engine,
                at_rest,
                kms,
                n2n,
                enforce_https,
                tls_policy,
                vpc_id,
                audit_enabled,
            ]);
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

fn bool_yn(val: Option<bool>) -> String {
    match val {
        Some(true) => "Yes".to_string(),
        Some(false) => "No".to_string(),
        None => String::new(),
    }
}
