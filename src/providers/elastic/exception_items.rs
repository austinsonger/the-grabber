use anyhow::Result;
use async_trait::async_trait;

use elastic_rs::ElasticClient;

use crate::evidence::CsvCollector;

pub struct ElasticExceptionItemsCollector {
    client: ElasticClient,
}

impl ElasticExceptionItemsCollector {
    pub fn new(client: ElasticClient) -> Self {
        Self { client }
    }
}

#[async_trait]
impl CsvCollector for ElasticExceptionItemsCollector {
    fn name(&self) -> &str {
        "Elastic Exception List Items"
    }

    fn filename_prefix(&self) -> &str {
        "Elastic_Exception_List_Items"
    }

    fn headers(&self) -> &'static [&'static str] {
        &[
            "List ID",
            "Item ID",
            "Name",
            "Description",
            "Type",
            "Entry Count",
            "Tags",
            "Created At",
            "Created By",
            "Updated At",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let lists = self.client.exceptions().find_all_lists().await?;
        let items = self.client.exceptions().find_all_items(&lists).await?;

        let rows = items
            .into_iter()
            .map(|i| {
                vec![
                    i.list_id,
                    i.item_id,
                    i.name,
                    i.description,
                    i.item_type,
                    i.entries.len().to_string(),
                    i.tags.join("; "),
                    i.created_at,
                    i.created_by,
                    i.updated_at,
                ]
            })
            .collect();

        Ok(rows)
    }
}
