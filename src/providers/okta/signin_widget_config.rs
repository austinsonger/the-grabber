use anyhow::Result;
use async_trait::async_trait;
use okta_rs::OktaClient;
use serde_json::Value;

use crate::evidence::CsvCollector;

pub struct OktaSignInWidgetConfigCollector {
    client: OktaClient,
}

impl OktaSignInWidgetConfigCollector {
    pub fn new(client: OktaClient) -> Self {
        Self { client }
    }
}

fn str_field(v: &Value, key: &str) -> String {
    v.get(key)
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .to_string()
}

#[async_trait]
impl CsvCollector for OktaSignInWidgetConfigCollector {
    fn name(&self) -> &str {
        "Okta Sign-In Widget Config"
    }
    fn filename_prefix(&self) -> &str {
        "Okta_SignIn_Widget_Config"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Brand ID",
            "Brand Name",
            "Widget Version",
            "Has Custom Sign-In",
            "Sign-In URL",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let brands = match self.client.sign_in_widget().brands().await {
            Ok(v) => v,
            Err(okta_rs::OktaError::Api { status, .. }) if [401, 403, 404].contains(&status) => {
                return Ok(vec![])
            }
            Err(e) => return Err(e.into()),
        };

        let arr = match brands.as_array() {
            Some(a) => a,
            None => return Ok(vec![]),
        };

        let mut rows: Vec<Vec<String>> = Vec::new();
        for brand in arr {
            let brand_id = str_field(brand, "id");
            let brand_name = str_field(brand, "name");

            let page = match self
                .client
                .sign_in_widget()
                .customized_page(&brand_id)
                .await
            {
                Ok(v) => v,
                Err(okta_rs::OktaError::Api { status, .. })
                    if [401, 403, 404].contains(&status) =>
                {
                    Value::Null
                }
                Err(e) => return Err(e.into()),
            };

            let widget_version = {
                let direct = page.get("widgetVersion").and_then(|v| v.as_str());
                let nested = page
                    .get("customization")
                    .and_then(|c| c.get("version"))
                    .and_then(|v| v.as_str());
                direct.or(nested).unwrap_or("").to_string()
            };

            let has_custom_sign_in = match page.as_object() {
                Some(obj) => {
                    let sign_in_html = obj
                        .get("signInHtml")
                        .and_then(|v| v.as_str())
                        .map(|s| !s.is_empty())
                        .unwrap_or(false);
                    let content = obj
                        .get("content")
                        .and_then(|v| v.as_str())
                        .map(|s| !s.is_empty())
                        .unwrap_or(false);
                    if sign_in_html || content {
                        "YES"
                    } else {
                        "NO"
                    }
                }
                None => "NO",
            }
            .to_string();

            let sign_in_url = {
                let preview = page.get("preview").and_then(|v| v.as_str());
                let url = page.get("url").and_then(|v| v.as_str());
                preview.or(url).unwrap_or("").to_string()
            };

            rows.push(vec![
                brand_id,
                brand_name,
                widget_version,
                has_custom_sign_in,
                sign_in_url,
            ]);
        }

        Ok(rows)
    }
}
