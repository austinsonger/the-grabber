use anyhow::Result;
use async_trait::async_trait;
use std::collections::HashMap;

use aws_sdk_cloudfront::Client as CfClient;

use crate::evidence::CsvCollector;

pub struct CloudFrontOacCollector {
    client: CfClient,
}

impl CloudFrontOacCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self {
            client: CfClient::new(config),
        }
    }
}

#[async_trait]
impl CsvCollector for CloudFrontOacCollector {
    fn name(&self) -> &str {
        "CloudFront Origin Access Controls"
    }
    fn filename_prefix(&self) -> &str {
        "CloudFront_OAC"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "OAC ID",
            "Name",
            "Signing Protocol",
            "Signing Behavior",
            "Origin Type",
            "Used By Distribution IDs",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        // Build map OAC id → distribution IDs that reference it.
        let mut oac_to_dists: HashMap<String, Vec<String>> = HashMap::new();
        let mut dist_marker: Option<String> = None;
        loop {
            let mut req = self.client.list_distributions();
            if let Some(m) = dist_marker.as_ref() {
                req = req.marker(m);
            }
            let resp = match req.send().await {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("  WARN: cloudfront list_distributions: {e:#}");
                    break;
                }
            };
            let dl = match resp.distribution_list() {
                Some(dl) => dl,
                None => break,
            };
            for dist in dl.items() {
                let dist_id = dist.id().to_string();
                if let Some(origins) = dist.origins() {
                    for origin in origins.items() {
                        if let Some(oac_id) = origin.origin_access_control_id() {
                            if !oac_id.is_empty() {
                                oac_to_dists
                                    .entry(oac_id.to_string())
                                    .or_default()
                                    .push(dist_id.clone());
                            }
                        }
                    }
                }
            }
            if dl.is_truncated() {
                dist_marker = dl.next_marker().map(|s| s.to_string());
                if dist_marker.is_none() {
                    break;
                }
            } else {
                break;
            }
        }

        // List OACs and emit one row each.
        let mut rows: Vec<Vec<String>> = Vec::new();
        let mut marker: Option<String> = None;
        loop {
            let mut req = self.client.list_origin_access_controls();
            if let Some(m) = marker.as_ref() {
                req = req.marker(m);
            }
            let resp = match req.send().await {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("  WARN: cloudfront list_origin_access_controls: {e:#}");
                    break;
                }
            };
            let oac_list = match resp.origin_access_control_list() {
                Some(l) => l,
                None => break,
            };
            for oac in oac_list.items() {
                let id = oac.id().to_string();
                let name = oac.name().to_string();
                let proto = oac.signing_protocol().as_str().to_string();
                let behavior = oac.signing_behavior().as_str().to_string();
                let origin_type = oac.origin_access_control_origin_type().as_str().to_string();
                let used_by = oac_to_dists
                    .get(&id)
                    .map(|v| v.join(", "))
                    .unwrap_or_default();

                rows.push(vec![id, name, proto, behavior, origin_type, used_by]);
            }
            if oac_list.is_truncated() {
                marker = oac_list.next_marker().map(|s| s.to_string());
                if marker.is_none() {
                    break;
                }
            } else {
                break;
            }
        }

        Ok(rows)
    }
}
