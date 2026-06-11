// Populated in Task 5.

use crate::client::JiraClient;

pub struct ProjectsApi<'c>(pub(crate) &'c JiraClient);
pub struct IssuesApi<'c>(pub(crate) &'c JiraClient);
