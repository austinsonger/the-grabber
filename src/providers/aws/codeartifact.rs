use anyhow::Result;
use async_trait::async_trait;
use aws_sdk_codeartifact::Client as CodeArtifactClient;

use crate::evidence::CsvCollector;

pub struct CodeArtifactCollector {
    client: CodeArtifactClient,
}

impl CodeArtifactCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self {
            client: CodeArtifactClient::new(config),
        }
    }
}

#[async_trait]
impl CsvCollector for CodeArtifactCollector {
    fn name(&self) -> &str {
        "CodeArtifact Repositories"
    }
    fn filename_prefix(&self) -> &str {
        "CodeArtifact_Repos_Sources"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Domain",
            "Repository",
            "Description",
            "Upstreams",
            "External Connections",
            "Created Time",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let mut rows = Vec::new();

        // List domains.
        let mut domain_token: Option<String> = None;
        loop {
            let mut req = self.client.list_domains();
            if let Some(t) = domain_token.as_ref() {
                req = req.next_token(t);
            }
            let resp = match req.send().await {
                Ok(r) => r,
                Err(e) => {
                    let msg = format!("{e}");
                    if msg.contains("AccessDenied") || msg.contains("not supported") {
                        return Ok(rows);
                    }
                    eprintln!("  WARN: CodeArtifact list_domains: {e:#}");
                    return Ok(rows);
                }
            };

            for domain in resp.domains() {
                let domain_name = domain.name().unwrap_or("").to_string();
                let domain_owner = domain.owner().unwrap_or("").to_string();
                if domain_name.is_empty() {
                    continue;
                }

                // List repositories in this domain.
                let mut repo_token: Option<String> = None;
                loop {
                    let mut rreq = self
                        .client
                        .list_repositories_in_domain()
                        .domain(&domain_name);
                    if !domain_owner.is_empty() {
                        rreq = rreq.domain_owner(&domain_owner);
                    }
                    if let Some(t) = repo_token.as_ref() {
                        rreq = rreq.next_token(t);
                    }
                    let rresp = match rreq.send().await {
                        Ok(r) => r,
                        Err(e) => {
                            eprintln!(
                                "  WARN: CodeArtifact list_repositories_in_domain({domain_name}): {e:#}"
                            );
                            break;
                        }
                    };
                    for repo_summary in rresp.repositories() {
                        let repo_name = repo_summary.name().unwrap_or("").to_string();
                        if repo_name.is_empty() {
                            continue;
                        }

                        // describe_repository for full details.
                        let mut dreq = self
                            .client
                            .describe_repository()
                            .domain(&domain_name)
                            .repository(&repo_name);
                        if !domain_owner.is_empty() {
                            dreq = dreq.domain_owner(&domain_owner);
                        }
                        let (description, upstreams, external_conns, created) = match dreq
                            .send()
                            .await
                        {
                            Ok(d) => {
                                if let Some(r) = d.repository() {
                                    let desc = r.description().unwrap_or("").to_string();
                                    let ups: Vec<String> = r
                                        .upstreams()
                                        .iter()
                                        .map(|u| u.repository_name().unwrap_or("").to_string())
                                        .collect();
                                    let ext: Vec<String> = r
                                        .external_connections()
                                        .iter()
                                        .map(|ec| {
                                            let name = ec
                                                .external_connection_name()
                                                .unwrap_or("")
                                                .to_string();
                                            let fmt = ec
                                                .package_format()
                                                .map(|f| f.as_str().to_string())
                                                .unwrap_or_default();
                                            if fmt.is_empty() {
                                                name
                                            } else {
                                                format!("{name}({fmt})")
                                            }
                                        })
                                        .collect();
                                    let created = repo_summary
                                        .created_time()
                                        .map(|t| t.to_string())
                                        .unwrap_or_default();
                                    (desc, ups.join(";"), ext.join(";"), created)
                                } else {
                                    (String::new(), String::new(), String::new(), String::new())
                                }
                            }
                            Err(e) => {
                                eprintln!(
                                        "  WARN: CodeArtifact describe_repository({domain_name}/{repo_name}): {e:#}"
                                    );
                                (String::new(), String::new(), String::new(), String::new())
                            }
                        };

                        rows.push(vec![
                            domain_name.clone(),
                            repo_name,
                            description,
                            upstreams,
                            external_conns,
                            created,
                        ]);
                    }
                    repo_token = rresp.next_token().map(|s| s.to_string());
                    if repo_token.is_none() {
                        break;
                    }
                }
            }

            domain_token = resp.next_token().map(|s| s.to_string());
            if domain_token.is_none() {
                break;
            }
        }

        Ok(rows)
    }
}
