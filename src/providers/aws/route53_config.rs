use anyhow::{Context, Result};
use async_trait::async_trait;
use aws_sdk_route53::Client as R53Client;
use aws_sdk_route53resolver::Client as ResolverClient;

use crate::evidence::CsvCollector;

// ══════════════════════════════════════════════════════════════════════════════
// 1. Route53 Hosted Zones
// ══════════════════════════════════════════════════════════════════════════════

pub struct Route53ZonesCollector {
    client: R53Client,
}

impl Route53ZonesCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self {
            client: R53Client::new(config),
        }
    }
}

#[async_trait]
impl CsvCollector for Route53ZonesCollector {
    fn name(&self) -> &str {
        "Route53 Hosted Zones"
    }
    fn filename_prefix(&self) -> &str {
        "Route53_Config"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Zone ID",
            "Name",
            "Private Zone",
            "Record Count",
            "Comment",
            "Sample Records",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let mut rows = Vec::new();
        let mut marker: Option<String> = None;

        loop {
            let mut req = self.client.list_hosted_zones();
            if let Some(ref m) = marker {
                req = req.marker(m);
            }
            let resp = req.send().await.context("Route53 list_hosted_zones")?;

            for zone in resp.hosted_zones() {
                let zone_id = zone.id().trim_start_matches("/hostedzone/").to_string();
                let name = zone.name().to_string();
                let private = zone
                    .config()
                    .map(|c| c.private_zone().to_string())
                    .unwrap_or_else(|| "false".to_string());
                let rec_count = zone
                    .resource_record_set_count()
                    .map(|n| n.to_string())
                    .unwrap_or_default();
                let comment = zone
                    .config()
                    .and_then(|c| c.comment())
                    .unwrap_or("")
                    .to_string();

                // Get first few record sets as sample
                let sample_records = match self
                    .client
                    .list_resource_record_sets()
                    .hosted_zone_id(&zone_id)
                    .max_items(5)
                    .send()
                    .await
                {
                    Ok(r) => r
                        .resource_record_sets()
                        .iter()
                        .map(|rs| {
                            let rec_name = rs.name();
                            let rec_type = rs.r#type().as_str();
                            format!("{rec_name}({rec_type})")
                        })
                        .collect::<Vec<_>>()
                        .join(", "),
                    Err(_) => String::new(),
                };

                rows.push(vec![
                    zone_id,
                    name,
                    private,
                    rec_count,
                    comment,
                    sample_records,
                ]);
            }

            marker = if resp.is_truncated() {
                resp.next_marker().map(|s| s.to_string())
            } else {
                None
            };
            if marker.is_none() {
                break;
            }
        }

        Ok(rows)
    }
}

// ══════════════════════════════════════════════════════════════════════════════
// 2. Route53 Resolver Rules
// ══════════════════════════════════════════════════════════════════════════════

pub struct Route53ResolverRulesCollector {
    client: ResolverClient,
}

impl Route53ResolverRulesCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self {
            client: ResolverClient::new(config),
        }
    }
}

#[async_trait]
impl CsvCollector for Route53ResolverRulesCollector {
    fn name(&self) -> &str {
        "Route53 Resolver Rules"
    }
    fn filename_prefix(&self) -> &str {
        "Route53_Resolver_Config"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Rule ID",
            "Name",
            "Domain Name",
            "Rule Type",
            "Status",
            "Target IPs",
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
            let mut req = self.client.list_resolver_rules();
            if let Some(ref t) = next_token {
                req = req.next_token(t);
            }
            let resp = match req.send().await {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("  WARN: Route53Resolver list_resolver_rules: {e:#}");
                    break;
                }
            };

            for rule in resp.resolver_rules() {
                let rule_id = rule.id().unwrap_or("").to_string();
                let name = rule.name().unwrap_or("").to_string();
                let domain = rule.domain_name().unwrap_or("").to_string();
                let rule_type = rule
                    .rule_type()
                    .map(|t| t.as_str().to_string())
                    .unwrap_or_default();
                let status = rule
                    .status()
                    .map(|s| s.as_str().to_string())
                    .unwrap_or_default();
                let targets: Vec<String> = rule
                    .target_ips()
                    .iter()
                    .map(|t| {
                        let ip = t.ip().unwrap_or("");
                        let port = t
                            .port()
                            .map(|p| p.to_string())
                            .unwrap_or_else(|| "53".to_string());
                        format!("{ip}:{port}")
                    })
                    .collect();

                rows.push(vec![
                    rule_id,
                    name,
                    domain,
                    rule_type,
                    status,
                    targets.join(", "),
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

// ══════════════════════════════════════════════════════════════════════════════
// 3. Route53 DNSSEC
// ══════════════════════════════════════════════════════════════════════════════

pub struct Route53DnssecCollector {
    client: R53Client,
}

impl Route53DnssecCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self {
            client: R53Client::new(config),
        }
    }
}

#[async_trait]
impl CsvCollector for Route53DnssecCollector {
    fn name(&self) -> &str {
        "Route53 DNSSEC"
    }
    fn filename_prefix(&self) -> &str {
        "Route53_DNSSEC"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Zone ID",
            "Zone Name",
            "Private Zone",
            "Signing Status",
            "Status Message",
            "KSK Count",
            "KSK Names",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let mut rows = Vec::new();
        let mut marker: Option<String> = None;

        loop {
            let mut req = self.client.list_hosted_zones();
            if let Some(ref m) = marker {
                req = req.marker(m);
            }
            let resp = req
                .send()
                .await
                .context("Route53 list_hosted_zones (dnssec)")?;

            for zone in resp.hosted_zones() {
                let zone_id = zone.id().trim_start_matches("/hostedzone/").to_string();
                let name = zone.name().to_string();
                let private = zone
                    .config()
                    .map(|c| c.private_zone().to_string())
                    .unwrap_or_else(|| "false".to_string());

                if private == "true" {
                    rows.push(vec![
                        zone_id,
                        name,
                        private,
                        "NOT_APPLICABLE".into(),
                        "Private zone".into(),
                        "0".into(),
                        String::new(),
                    ]);
                    continue;
                }

                match self
                    .client
                    .get_dnssec()
                    .hosted_zone_id(&zone_id)
                    .send()
                    .await
                {
                    Ok(d) => {
                        let (status, msg) = match d.status() {
                            Some(s) => (
                                s.serve_signature().unwrap_or("").to_string(),
                                s.status_message().unwrap_or("").to_string(),
                            ),
                            None => (String::new(), String::new()),
                        };
                        let ksks = d.key_signing_keys();
                        let ksk_count = ksks.len().to_string();
                        let ksk_names = ksks
                            .iter()
                            .map(|k| k.name().unwrap_or("").to_string())
                            .collect::<Vec<_>>()
                            .join(", ");
                        rows.push(vec![
                            zone_id, name, private, status, msg, ksk_count, ksk_names,
                        ]);
                    }
                    Err(e) => {
                        eprintln!("  WARN: Route53 get_dnssec({zone_id}): {e:#}");
                        rows.push(vec![
                            zone_id,
                            name,
                            private,
                            "ERROR".into(),
                            format!("{e}"),
                            String::new(),
                            String::new(),
                        ]);
                    }
                }
            }

            marker = if resp.is_truncated() {
                resp.next_marker().map(|s| s.to_string())
            } else {
                None
            };
            if marker.is_none() {
                break;
            }
        }

        Ok(rows)
    }
}
