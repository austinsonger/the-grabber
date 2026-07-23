use anyhow::Result;
use async_trait::async_trait;
use okta_rs::OktaClient;

use crate::evidence::CsvCollector;
use crate::okta_stig_map;

pub struct OktaStigComplianceCollector {
    client: OktaClient,
}

impl OktaStigComplianceCollector {
    pub fn new(client: OktaClient) -> Self {
        Self { client }
    }
}

#[async_trait]
impl CsvCollector for OktaStigComplianceCollector {
    fn name(&self) -> &str {
        "Okta STIG Compliance"
    }
    fn filename_prefix(&self) -> &str {
        "Okta_STIG_Compliance"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "V-ID",
            "Rule ID",
            "STIG ID",
            "CCI",
            "Severity",
            "Title",
            "Status",
            "Expected Value",
            "Actual Value",
            "Details/Evidence",
            "Check Text",
            "Fix Text",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let results = super::stig::evaluate_all(&self.client).await;
        let meta = okta_stig_map::bundled();

        let mut rows: Vec<Vec<String>> = results
            .into_iter()
            .map(|r| {
                let m = meta.get(&r.v_id);
                vec![
                    r.v_id.clone(),
                    m.map(|m| m.sv_rule_id.clone()).unwrap_or_default(),
                    m.map(|m| m.stig_id_version.clone()).unwrap_or_default(),
                    m.map(|m| m.cci.join("; ")).unwrap_or_default(),
                    m.map(|m| m.severity.clone()).unwrap_or_default(),
                    m.map(|m| m.title.clone()).unwrap_or_default(),
                    r.status.as_stig_str().to_string(),
                    r.expected_value,
                    r.actual_value,
                    r.details,
                    m.map(|m| m.check_text.replace(['\n', '\r'], " "))
                        .unwrap_or_default(),
                    m.map(|m| m.fix_text.replace(['\n', '\r'], " "))
                        .unwrap_or_default(),
                ]
            })
            .collect();

        rows.sort_by(|a, b| a[0].cmp(&b[0]));
        Ok(rows)
    }
}
