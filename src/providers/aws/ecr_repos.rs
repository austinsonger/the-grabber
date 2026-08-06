//! Standalone ECR repository discovery.
//!
//! Used by the TUI's SBOM repository picker and by `--sbom-all-repos`. This is
//! deliberately not a collector — nothing is written to disk.

use anyhow::{Context, Result};
use aws_sdk_ecr::Client as EcrClient;

/// One ECR repository, as shown in the SBOM repository picker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EcrRepoSummary {
    pub name: String,
    pub uri: String,
}

/// Every ECR repository in the account/region behind `config`, sorted by name.
pub async fn list_repositories(config: &aws_config::SdkConfig) -> Result<Vec<EcrRepoSummary>> {
    let client = EcrClient::new(config);
    let mut out: Vec<EcrRepoSummary> = Vec::new();
    let mut pages = client
        .describe_repositories()
        .into_paginator()
        .items()
        .send();

    while let Some(repo) = pages.next().await {
        let repo = repo.context("ECR describe_repositories")?;
        let Some(name) = repo.repository_name() else {
            continue;
        };
        out.push(EcrRepoSummary {
            name: name.to_string(),
            uri: repo.repository_uri().unwrap_or_default().to_string(),
        });
    }

    out.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(out)
}
