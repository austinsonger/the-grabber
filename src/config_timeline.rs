use anyhow::Result;
use async_trait::async_trait;
use aws_sdk_config::Client as ConfigClient;
use aws_sdk_config::types::ResourceType;

use crate::evidence::CsvCollector;

fn epoch_to_rfc3339(secs: i64) -> String {
    chrono::DateTime::<chrono::Utc>::from_timestamp(secs, 0)
        .map(|c| c.to_rfc3339())
        .unwrap_or_default()
}

// ══════════════════════════════════════════════════════════════════════════════
// 1. Config Resource Timeline
// ══════════════════════════════════════════════════════════════════════════════

pub struct ConfigResourceTimelineCollector {
    client: ConfigClient,
}

impl ConfigResourceTimelineCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self { client: ConfigClient::new(config) }
    }
}

#[async_trait]
impl CsvCollector for ConfigResourceTimelineCollector {
    fn name(&self) -> &str { "AWS Config Resource Timeline" }
    fn filename_prefix(&self) -> &str { "Config_Resource_Timeline" }
    fn headers(&self) -> &'static [&'static str] {
        &["Resource ID", "Resource Type", "Capture Time", "Config State ID",
          "Configuration (excerpt)", "Change Type"]
    }

    async fn collect_rows(&self, _account_id: &str, _region: &str, _dates: Option<(i64, i64)>) -> Result<Vec<Vec<String>>> {
        let mut rows = Vec::new();

        let key_types: &[&str] = &[
            "AWS::EC2::Instance",
            "AWS::EC2::SecurityGroup",
            "AWS::S3::Bucket",
            "AWS::IAM::Role",
            "AWS::RDS::DBInstance",
            "AWS::KMS::Key",
            "AWS::Lambda::Function",
            "AWS::CloudTrail::Trail",
            "AWS::EC2::VPC",
        ];

        for type_str in key_types {
            let resource_type = ResourceType::from(*type_str);
            let mut next_token: Option<String> = None;
            let mut resource_count = 0;

            'outer: loop {
                let mut req = self.client
                    .list_discovered_resources()
                    .resource_type(resource_type.clone());
                if let Some(ref t) = next_token {
                    req = req.next_token(t);
                }
                let resp = match req.send().await {
                    Ok(r) => r,
                    Err(e) => {
                        eprintln!("  WARN: Config list_discovered_resources {type_str}: {e:#}");
                        break;
                    }
                };

                for resource in resp.resource_identifiers() {
                    if resource_count >= 50 { break 'outer; }
                    resource_count += 1;

                    let resource_id = resource.resource_id().unwrap_or("").to_string();
                    let rtype = resource.resource_type()
                        .map(|t| t.as_str().to_string())
                        .unwrap_or_else(|| type_str.to_string());

                    let history = match self.client
                        .get_resource_config_history()
                        .resource_type(resource_type.clone())
                        .resource_id(&resource_id)
                        .limit(5)
                        .send()
                        .await
                    {
                        Ok(r) => r,
                        Err(e) => {
                            eprintln!("  WARN: Config get_resource_config_history {resource_id}: {e:#}");
                            continue;
                        }
                    };

                    for item in history.configuration_items() {
                        let capture_time = item.configuration_item_capture_time()
                            .map(|d| epoch_to_rfc3339(d.secs()))
                            .unwrap_or_default();
                        let state_id = item.configuration_state_id().unwrap_or("").to_string();
                        let change_type = item.configuration_item_status()
                            .map(|s| s.as_str().to_string())
                            .unwrap_or_default();
                        let config = item.configuration().unwrap_or("");
                        let config_trunc = if config.len() > 400 {
                            format!("{}...", &config[..400])
                        } else {
                            config.to_string()
                        };

                        rows.push(vec![
                            resource_id.clone(), rtype.clone(),
                            capture_time, state_id, config_trunc, change_type,
                        ]);
                    }
                }

                next_token = resp.next_token().map(|s| s.to_string());
                if next_token.is_none() { break; }
            }
        }

        Ok(rows)
    }
}

// ══════════════════════════════════════════════════════════════════════════════
// 2. Config Compliance History
// ══════════════════════════════════════════════════════════════════════════════

pub struct ConfigComplianceHistoryCollector {
    client: ConfigClient,
}

impl ConfigComplianceHistoryCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self { client: ConfigClient::new(config) }
    }
}

#[async_trait]
impl CsvCollector for ConfigComplianceHistoryCollector {
    fn name(&self) -> &str { "AWS Config Compliance History" }
    fn filename_prefix(&self) -> &str { "Config_Compliance_History" }
    fn headers(&self) -> &'static [&'static str] {
        &["Config Rule Name", "Resource ID", "Resource Type", "Compliance Type", "Ordering Timestamp"]
    }

    async fn collect_rows(&self, _account_id: &str, _region: &str, _dates: Option<(i64, i64)>) -> Result<Vec<Vec<String>>> {
        let mut rows = Vec::new();

        // Collect all rule names first
        let mut rule_names: Vec<String> = Vec::new();
        let mut next_token: Option<String> = None;
        loop {
            let mut req = self.client.describe_config_rules();
            if let Some(ref t) = next_token {
                req = req.next_token(t);
            }
            let resp = match req.send().await {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("  WARN: Config describe_config_rules: {e:#}");
                    break;
                }
            };
            for rule in resp.config_rules() {
                if let Some(name) = rule.config_rule_name() {
                    rule_names.push(name.to_string());
                }
            }
            next_token = resp.next_token().map(|s| s.to_string());
            if next_token.is_none() { break; }
        }

        // Get compliance details per rule
        for rule_name in &rule_names {
            let mut nt: Option<String> = None;
            loop {
                let mut req = self.client
                    .get_compliance_details_by_config_rule()
                    .config_rule_name(rule_name)
                    .limit(100);
                if let Some(ref t) = nt {
                    req = req.next_token(t);
                }
                let resp = match req.send().await {
                    Ok(r) => r,
                    Err(e) => {
                        eprintln!("  WARN: Config get_compliance_details {rule_name}: {e:#}");
                        break;
                    }
                };

                for result in resp.evaluation_results() {
                    let compliance_type = result.compliance_type()
                        .map(|c| c.as_str().to_string())
                        .unwrap_or_default();

                    let (resource_id, resource_type) = result
                        .evaluation_result_identifier()
                        .and_then(|id| id.evaluation_result_qualifier())
                        .map(|q| (
                            q.resource_id().unwrap_or("").to_string(),
                            q.resource_type().unwrap_or("").to_string(),
                        ))
                        .unwrap_or_default();

                    let ordering_ts = result.result_recorded_time()
                        .map(|d| epoch_to_rfc3339(d.secs()))
                        .unwrap_or_default();

                    rows.push(vec![
                        rule_name.clone(), resource_id, resource_type,
                        compliance_type, ordering_ts,
                    ]);
                }

                nt = resp.next_token().map(|s| s.to_string());
                if nt.is_none() { break; }
            }
        }

        Ok(rows)
    }
}

// ══════════════════════════════════════════════════════════════════════════════
// 3. Config Snapshot (point-in-time baseline)
// ══════════════════════════════════════════════════════════════════════════════

pub struct ConfigSnapshotCollector {
    client: ConfigClient,
}

impl ConfigSnapshotCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self { client: ConfigClient::new(config) }
    }
}

#[async_trait]
impl CsvCollector for ConfigSnapshotCollector {
    fn name(&self) -> &str { "AWS Config Snapshot (Point-in-Time)" }
    fn filename_prefix(&self) -> &str { "Config_Snapshot" }
    fn headers(&self) -> &'static [&'static str] {
        &["Resource ID", "Resource Type", "Resource Name", "Account ID",
          "Configuration (excerpt)", "Relationships"]
    }

    async fn collect_rows(&self, account_id: &str, _region: &str, _dates: Option<(i64, i64)>) -> Result<Vec<Vec<String>>> {
        let mut rows = Vec::new();
        let expression =
            "SELECT resourceId, resourceType, resourceName, accountId, configuration, relationships \
             WHERE resourceType <> ''";
        let mut next_token: Option<String> = None;

        loop {
            let mut req = self.client
                .select_resource_config()
                .expression(expression)
                .limit(100);
            if let Some(ref t) = next_token {
                req = req.next_token(t);
            }
            let resp = match req.send().await {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("  WARN: Config select_resource_config: {e:#}");
                    break;
                }
            };

            for result_json in resp.results() {
                let v: serde_json::Value = match serde_json::from_str(result_json) {
                    Ok(v) => v,
                    Err(_) => continue,
                };

                let get_str = |key: &str| {
                    v.get(key).and_then(|x| x.as_str()).unwrap_or("").to_string()
                };
                let resource_id   = get_str("resourceId");
                let resource_type = get_str("resourceType");
                let resource_name = get_str("resourceName");
                let acct_id = v.get("accountId").and_then(|x| x.as_str())
                    .unwrap_or(account_id).to_string();

                let config = v.get("configuration").map(|c| {
                    let s = c.to_string();
                    if s.len() > 400 { format!("{}...", &s[..400]) } else { s }
                }).unwrap_or_default();

                let relationships = v.get("relationships").map(|r| {
                    let s = r.to_string();
                    if s.len() > 200 { format!("{}...", &s[..200]) } else { s }
                }).unwrap_or_default();

                rows.push(vec![resource_id, resource_type, resource_name,
                               acct_id, config, relationships]);
            }

            next_token = resp.next_token().map(|s| s.to_string());
            if next_token.is_none() { break; }
        }

        Ok(rows)
    }
}
