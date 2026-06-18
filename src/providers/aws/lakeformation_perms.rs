use anyhow::Result;
use async_trait::async_trait;
use aws_sdk_lakeformation::Client as LakeFormationClient;

use crate::evidence::CsvCollector;

pub struct LakeFormationPermsCollector {
    client: LakeFormationClient,
}

impl LakeFormationPermsCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self {
            client: LakeFormationClient::new(config),
        }
    }
}

#[async_trait]
impl CsvCollector for LakeFormationPermsCollector {
    fn name(&self) -> &str {
        "Lake Formation Permissions"
    }
    fn filename_prefix(&self) -> &str {
        "LakeFormation_Permissions"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Principal",
            "Resource Type",
            "Resource Identifier",
            "Permissions",
            "Grantable Permissions",
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
            let mut req = self.client.list_permissions();
            if let Some(ref t) = next_token {
                req = req.next_token(t);
            }
            let resp = match req.send().await {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("  WARN: LakeFormation list_permissions: {e:#}");
                    return Ok(rows);
                }
            };

            for entry in resp.principal_resource_permissions() {
                let principal = entry
                    .principal()
                    .and_then(|p| p.data_lake_principal_identifier())
                    .unwrap_or("")
                    .to_string();

                let (res_type, res_id) = match entry.resource() {
                    Some(r) => {
                        if let Some(db) = r.database() {
                            ("DATABASE".to_string(), db.name().to_string())
                        } else if let Some(tbl) = r.table() {
                            let db_name = tbl.database_name();
                            let tname = tbl.name().unwrap_or("").to_string();
                            ("TABLE".to_string(), format!("{db_name}.{tname}"))
                        } else if let Some(loc) = r.data_location() {
                            ("DATA_LOCATION".to_string(), loc.resource_arn().to_string())
                        } else if r.catalog().is_some() {
                            ("CATALOG".to_string(), String::new())
                        } else {
                            ("OTHER".to_string(), String::new())
                        }
                    }
                    None => (String::new(), String::new()),
                };

                let perms = entry
                    .permissions()
                    .iter()
                    .map(|p| p.as_str().to_string())
                    .collect::<Vec<_>>()
                    .join(",");
                let grantable = entry
                    .permissions_with_grant_option()
                    .iter()
                    .map(|p| p.as_str().to_string())
                    .collect::<Vec<_>>()
                    .join(",");

                rows.push(vec![principal, res_type, res_id, perms, grantable]);
            }

            next_token = resp.next_token().map(|s| s.to_string());
            if next_token.is_none() {
                break;
            }
        }

        Ok(rows)
    }
}
