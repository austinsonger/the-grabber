//! Microsoft Defender for Cloud collector.
//!
//! Maps to AWS SecurityHub + GuardDuty.  Uses `azure_mgmt_security` to list
//! all security assessments (findings) across the subscription scope.

use std::sync::Arc;

use anyhow::{Context, Result};
use async_trait::async_trait;
use azure_mgmt_security::Client as SecurityClient;
use futures::StreamExt;

use crate::evidence::CsvCollector;

pub struct DefenderCollector {
    client:          SecurityClient,
    subscription_id: String,
}

impl DefenderCollector {
    pub fn new(
        credential: Arc<dyn azure_core::auth::TokenCredential>,
        subscription_id: String,
    ) -> Self {
        Self {
            client: SecurityClient::builder(credential).build(),
            subscription_id,
        }
    }
}

#[async_trait]
impl CsvCollector for DefenderCollector {
    fn name(&self) -> &str { "Microsoft Defender for Cloud" }
    fn filename_prefix(&self) -> &str { "Azure_Defender_Assessments" }

    fn headers(&self) -> &'static [&'static str] {
        &[
            "Assessment Name",
            "Resource ID",
            "Resource Type",
            "Status",
            "Severity",
            "Category",
            "Description",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let mut rows = Vec::new();
        let scope = format!("/subscriptions/{}", self.subscription_id);

        let mut stream = self.client
            .assessments_client()
            .list(&scope)
            .into_stream();

        while let Some(page) = stream.next().await {
            let page = page.context("Defender: assessments list page failed")?;
            for assessment in page.value {
                let props = assessment.properties.as_ref();
                let base = props.map(|p| &p.security_assessment_properties_base);
                let status_code = props
                    .map(|p| format!("{:?}", p.status.assessment_status.code))
                    .unwrap_or_default();
                let metadata = base.and_then(|b| b.metadata.as_ref());

                rows.push(vec![
                    assessment.resource.name.clone().unwrap_or_default(),
                    assessment.resource.id.clone().unwrap_or_default(),
                    assessment.resource.type_.clone().unwrap_or_default(),
                    status_code,
                    metadata.and_then(|m| m.severity.as_ref())
                        .map(|s| format!("{:?}", s))
                        .unwrap_or_default(),
                    metadata.and_then(|m| m.categories.as_ref())
                        .map(|c| {
                            c.iter()
                                .map(|x| format!("{:?}", x))
                                .collect::<Vec<_>>()
                                .join(", ")
                        })
                        .unwrap_or_default(),
                    metadata.and_then(|m| m.description.clone()).unwrap_or_default(),
                ]);
            }
        }

        Ok(rows)
    }
}
