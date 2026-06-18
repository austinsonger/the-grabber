use anyhow::Result;
use async_trait::async_trait;
use aws_sdk_guardduty::types::DetectorFeatureResult;
use aws_sdk_guardduty::Client as GdClient;

use crate::evidence::CsvCollector;

pub struct GdProtectionPlansCollector {
    client: GdClient,
}

impl GdProtectionPlansCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self {
            client: GdClient::new(config),
        }
    }
}

fn is_benign(err: &str) -> bool {
    err.contains("AccessDenied")
        || err.contains("AccessDeniedException")
        || err.contains("UnauthorizedOperation")
        || err.contains("not available")
        || err.contains("UnknownEndpoint")
        || err.contains("dispatch failure")
        || err.contains("ResourceNotFoundException")
        || err.contains("BadRequestException")
}

#[async_trait]
impl CsvCollector for GdProtectionPlansCollector {
    fn name(&self) -> &str {
        "GuardDuty Protection Plans"
    }
    fn filename_prefix(&self) -> &str {
        "GuardDuty_ProtectionPlans"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Type",
            "ID",
            "Role / Resource",
            "Status / Feature State",
            "Detail",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let mut rows: Vec<Vec<String>> = Vec::new();

        // Malware Protection Plans (manually paginated).
        let mut next_token: Option<String> = None;
        loop {
            let mut req = self.client.list_malware_protection_plans();
            if let Some(ref t) = next_token {
                req = req.next_token(t);
            }
            let resp = match req.send().await {
                Ok(r) => r,
                Err(e) => {
                    let msg = format!("{e:#}");
                    if is_benign(&msg) {
                        break;
                    }
                    eprintln!("  WARN: GuardDuty list_malware_protection_plans: {msg}");
                    break;
                }
            };
            for plan in resp.malware_protection_plans() {
                let plan_id = match plan.malware_protection_plan_id() {
                    Some(id) => id.to_string(),
                    None => continue,
                };
                let detail = match self
                    .client
                    .get_malware_protection_plan()
                    .malware_protection_plan_id(&plan_id)
                    .send()
                    .await
                {
                    Ok(d) => d,
                    Err(e) => {
                        let msg = format!("{e:#}");
                        if !is_benign(&msg) {
                            eprintln!(
                                "  WARN: GuardDuty get_malware_protection_plan {plan_id}: {msg}"
                            );
                        }
                        continue;
                    }
                };
                let role = detail.role().unwrap_or("").to_string();
                let bucket = detail
                    .protected_resource()
                    .and_then(|p| p.s3_bucket())
                    .and_then(|s| s.bucket_name())
                    .unwrap_or("")
                    .to_string();
                let status = detail
                    .status()
                    .map(|s| s.as_str().to_string())
                    .unwrap_or_default();
                let role_resource = if bucket.is_empty() {
                    role.clone()
                } else {
                    format!("role={role} bucket={bucket}")
                };
                rows.push(vec![
                    "Plan".to_string(),
                    plan_id,
                    role_resource,
                    status,
                    String::new(),
                ]);
            }
            match resp.next_token() {
                Some(t) if !t.is_empty() => next_token = Some(t.to_string()),
                _ => break,
            }
        }

        // Detector features — RUNTIME_MONITORING (paginated).
        let mut det_paginator = self.client.list_detectors().into_paginator().send();
        while let Some(page) = det_paginator.next().await {
            let resp = match page {
                Ok(r) => r,
                Err(e) => {
                    let msg = format!("{e:#}");
                    if is_benign(&msg) {
                        break;
                    }
                    eprintln!("  WARN: GuardDuty list_detectors: {msg}");
                    break;
                }
            };
            for detector_id in resp.detector_ids() {
                let detail = match self
                    .client
                    .get_detector()
                    .detector_id(detector_id)
                    .send()
                    .await
                {
                    Ok(d) => d,
                    Err(e) => {
                        let msg = format!("{e:#}");
                        if !is_benign(&msg) {
                            eprintln!("  WARN: GuardDuty get_detector {detector_id}: {msg}");
                        }
                        continue;
                    }
                };
                for feat in detail.features() {
                    let is_runtime =
                        matches!(feat.name(), Some(DetectorFeatureResult::RuntimeMonitoring));
                    if !is_runtime {
                        continue;
                    }
                    let name = feat
                        .name()
                        .map(|n| n.as_str().to_string())
                        .unwrap_or_default();
                    let state = feat
                        .status()
                        .map(|s| s.as_str().to_string())
                        .unwrap_or_default();
                    rows.push(vec![
                        "Feature".to_string(),
                        detector_id.to_string(),
                        name,
                        state,
                        String::new(),
                    ]);
                }
            }
        }

        Ok(rows)
    }
}
