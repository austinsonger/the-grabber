use serde::Deserialize;

use crate::client::JiraClient;
use crate::error::JiraError;
use crate::types::project::JiraProject;

pub struct ProjectsApi<'c>(pub(crate) &'c JiraClient);

#[derive(Deserialize)]
struct ProjectSearchPage {
    #[serde(default)]
    values: Vec<JiraProject>,
    #[serde(rename = "isLast", default)]
    is_last: bool,
    #[serde(rename = "nextPage", default)]
    next_page: Option<String>,
}

impl<'c> ProjectsApi<'c> {
    /// GET /rest/api/3/project/search — paginated list of projects.
    pub async fn list_all(&self) -> Result<Vec<JiraProject>, JiraError> {
        let mut all = Vec::new();
        let mut url = self
            .0
            .url("/rest/api/3/project/search?maxResults=50&expand=lead");
        loop {
            let resp = self.0.get_absolute(&url).await?;
            if !resp.status().is_success() {
                let status = resp.status().as_u16();
                let message = resp.text().await.unwrap_or_default();
                return Err(JiraError::Api { status, message });
            }
            let page: ProjectSearchPage = resp.json().await?;
            all.extend(page.values);
            if page.is_last {
                break;
            }
            match page.next_page {
                Some(next) => url = next,
                None => break,
            }
        }
        Ok(all)
    }
}
