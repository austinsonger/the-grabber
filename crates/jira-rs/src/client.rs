// Populated in Task 3.

use crate::api::{IssuesApi, ProjectsApi};
use crate::error::JiraError;

#[derive(Clone)]
pub struct JiraClient;

impl JiraClient {
    pub fn new(_base_url: &str, _email: &str, _api_token: &str) -> Result<Self, JiraError> {
        Ok(Self)
    }
    pub fn projects(&self) -> ProjectsApi<'_> {
        ProjectsApi(self)
    }
    pub fn issues(&self) -> IssuesApi<'_> {
        IssuesApi(self)
    }
}
