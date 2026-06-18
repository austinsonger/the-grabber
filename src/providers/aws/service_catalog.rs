use anyhow::Result;
use async_trait::async_trait;
use aws_sdk_servicecatalog::Client as ScClient;

use crate::evidence::CsvCollector;

pub struct ServiceCatalogCollector {
    client: ScClient,
}

impl ServiceCatalogCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self {
            client: ScClient::new(config),
        }
    }
}

fn is_benign(err: &str) -> bool {
    err.contains("AccessDenied")
        || err.contains("ResourceNotFoundException")
        || err.contains("ValidationException")
        || err.contains("not enabled")
        || err.contains("not subscribed")
        || err.contains("UnknownService")
        || err.contains("dispatch failure")
        || err.contains("could not be found")
        || err.contains("OptInRequired")
}

#[async_trait]
impl CsvCollector for ServiceCatalogCollector {
    fn name(&self) -> &str {
        "Service Catalog Products"
    }
    fn filename_prefix(&self) -> &str {
        "ServiceCatalog_Products"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Type",
            "ID",
            "Name",
            "Owner / Status",
            "Product Type / Artifact",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let mut rows: Vec<Vec<String>> = Vec::new();

        // search_products_as_admin paginated
        let mut page_token: Option<String> = None;
        loop {
            let mut req = self.client.search_products_as_admin();
            if let Some(t) = page_token.as_ref() {
                req = req.page_token(t);
            }
            let resp = match req.send().await {
                Ok(r) => r,
                Err(e) => {
                    let msg = format!("{e:#}");
                    if is_benign(&msg) {
                        return Ok(rows);
                    }
                    eprintln!("  WARN: ServiceCatalog search_products_as_admin: {e:#}");
                    break;
                }
            };

            for pvd in resp.product_view_details() {
                if let Some(s) = pvd.product_view_summary() {
                    let product_id = s.product_id().unwrap_or("").to_string();
                    let name = s.name().unwrap_or("").to_string();
                    let owner = s.owner().unwrap_or("").to_string();
                    let ptype = s
                        .r#type()
                        .map(|t| t.as_str().to_string())
                        .unwrap_or_default();
                    rows.push(vec!["Product".to_string(), product_id, name, owner, ptype]);
                }
            }

            page_token = resp.next_page_token().map(|s| s.to_string());
            if page_token.is_none() {
                break;
            }
        }

        // search_provisioned_products paginated
        let mut page_token: Option<String> = None;
        loop {
            let mut req = self.client.search_provisioned_products();
            if let Some(t) = page_token.as_ref() {
                req = req.page_token(t);
            }
            let resp = match req.send().await {
                Ok(r) => r,
                Err(e) => {
                    let msg = format!("{e:#}");
                    if is_benign(&msg) {
                        break;
                    }
                    eprintln!("  WARN: ServiceCatalog search_provisioned_products: {e:#}");
                    break;
                }
            };

            for pp in resp.provisioned_products() {
                let id = pp.id().unwrap_or("").to_string();
                let name = pp.name().unwrap_or("").to_string();
                let status = pp
                    .status()
                    .map(|s| s.as_str().to_string())
                    .unwrap_or_default();
                let product_id = pp.product_id().unwrap_or("").to_string();
                let artifact_id = pp.provisioning_artifact_id().unwrap_or("").to_string();
                let combo = if artifact_id.is_empty() {
                    product_id
                } else {
                    format!("{product_id}/{artifact_id}")
                };
                rows.push(vec!["Provisioned".to_string(), id, name, status, combo]);
            }

            page_token = resp.next_page_token().map(|s| s.to_string());
            if page_token.is_none() {
                break;
            }
        }

        Ok(rows)
    }
}
