use anyhow::Result;
use async_trait::async_trait;
use aws_sdk_glue::Client as GlueClient;

use crate::evidence::CsvCollector;

pub struct GlueCatalogCollector {
    client: GlueClient,
}

impl GlueCatalogCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self {
            client: GlueClient::new(config),
        }
    }
}

#[async_trait]
impl CsvCollector for GlueCatalogCollector {
    fn name(&self) -> &str {
        "Glue Catalog"
    }
    fn filename_prefix(&self) -> &str {
        "Glue_Catalog"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Database",
            "Table",
            "Owner",
            "Type",
            "Storage Location",
            "Input Format",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let mut rows = Vec::new();

        // Paginate get_databases.
        let mut databases: Vec<String> = Vec::new();
        let mut next_token: Option<String> = None;
        loop {
            let mut req = self.client.get_databases();
            if let Some(ref t) = next_token {
                req = req.next_token(t);
            }
            let resp = match req.send().await {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("  WARN: Glue get_databases: {e:#}");
                    return Ok(rows);
                }
            };
            for db in resp.database_list() {
                databases.push(db.name().to_string());
            }
            next_token = resp.next_token().map(|s| s.to_string());
            if next_token.is_none() {
                break;
            }
        }

        for db_name in &databases {
            let mut tbl_token: Option<String> = None;
            loop {
                let mut req = self.client.get_tables().database_name(db_name);
                if let Some(ref t) = tbl_token {
                    req = req.next_token(t);
                }
                let resp = match req.send().await {
                    Ok(r) => r,
                    Err(e) => {
                        eprintln!("  WARN: Glue get_tables db={db_name}: {e:#}");
                        break;
                    }
                };
                for tbl in resp.table_list() {
                    let table_name = tbl.name().to_string();
                    let owner = tbl.owner().unwrap_or("").to_string();
                    let table_type = tbl.table_type().unwrap_or("").to_string();
                    let (location, input_format) = match tbl.storage_descriptor() {
                        Some(sd) => (
                            sd.location().unwrap_or("").to_string(),
                            sd.input_format().unwrap_or("").to_string(),
                        ),
                        None => (String::new(), String::new()),
                    };
                    rows.push(vec![
                        db_name.clone(),
                        table_name,
                        owner,
                        table_type,
                        location,
                        input_format,
                    ]);
                }
                tbl_token = resp.next_token().map(|s| s.to_string());
                if tbl_token.is_none() {
                    break;
                }
            }
        }

        Ok(rows)
    }
}
