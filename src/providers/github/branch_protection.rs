use anyhow::Result;
use async_trait::async_trait;
use github_rs::{GithubClient, GithubError};

use crate::evidence::CsvCollector;

pub struct GithubBranchProtectionCollector {
    pub(crate) client: GithubClient,
}

impl GithubBranchProtectionCollector {
    pub fn new(client: GithubClient) -> Self {
        Self { client }
    }
}

#[async_trait]
impl CsvCollector for GithubBranchProtectionCollector {
    fn name(&self) -> &str {
        "GitHub Branch Protection"
    }
    fn filename_prefix(&self) -> &str {
        "Github_Branch_Protection"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Repository",
            "Branch",
            "Protected",
            "Enforce Admins",
            "Required Approving Review Count",
            "Require Code Owner Reviews",
            "Required Status Checks Strict",
            "Allow Force Pushes",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let repos = self.client.repos().list_all().await?;
        let mut rows = Vec::with_capacity(repos.len());
        for r in repos {
            if r.default_branch.is_empty() {
                continue;
            }
            let protection = match self
                .client
                .repos()
                .get_branch_protection(&r.name, &r.default_branch)
                .await
            {
                Ok(p) => Some(p),
                Err(GithubError::Api { status: 404, .. }) => None,
                Err(e) => return Err(e.into()),
            };

            match protection {
                None => rows.push(vec![
                    r.full_name,
                    r.default_branch,
                    "false".to_string(),
                    "unknown".to_string(),
                    String::new(),
                    "unknown".to_string(),
                    "unknown".to_string(),
                    "unknown".to_string(),
                ]),
                Some(p) => {
                    let reviews = p.required_pull_request_reviews;
                    rows.push(vec![
                        r.full_name,
                        r.default_branch,
                        "true".to_string(),
                        p.enforce_admins
                            .map(|e| e.enabled.to_string())
                            .unwrap_or_else(|| "unknown".to_string()),
                        reviews
                            .as_ref()
                            .and_then(|rv| rv.required_approving_review_count)
                            .map(|n| n.to_string())
                            .unwrap_or_default(),
                        reviews
                            .as_ref()
                            .and_then(|rv| rv.require_code_owner_reviews)
                            .map(|b| b.to_string())
                            .unwrap_or_else(|| "unknown".to_string()),
                        p.required_status_checks
                            .map(|c| c.strict.to_string())
                            .unwrap_or_else(|| "unknown".to_string()),
                        p.allow_force_pushes
                            .map(|f| f.enabled.to_string())
                            .unwrap_or_else(|| "unknown".to_string()),
                    ]);
                }
            }
        }
        Ok(rows)
    }
}
