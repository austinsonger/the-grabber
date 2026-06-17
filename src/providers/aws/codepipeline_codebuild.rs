use anyhow::Result;
use async_trait::async_trait;
use aws_sdk_codebuild::Client as CodeBuildClient;
use aws_sdk_codepipeline::Client as CodePipelineClient;

use crate::evidence::CsvCollector;

pub struct CodePipelineCodeBuildCollector {
    pipeline: CodePipelineClient,
    build: CodeBuildClient,
}

impl CodePipelineCodeBuildCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self {
            pipeline: CodePipelineClient::new(config),
            build: CodeBuildClient::new(config),
        }
    }
}

#[async_trait]
impl CsvCollector for CodePipelineCodeBuildCollector {
    fn name(&self) -> &str {
        "CodePipeline & CodeBuild Config"
    }
    fn filename_prefix(&self) -> &str {
        "CodePipeline_CodeBuild"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Resource Type",
            "Name",
            "Source Provider",
            "Source Location",
            "Has Manual Approval",
            "Privileged Mode",
            "Logs Destination",
            "Service Role",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let mut rows = Vec::new();

        // ── CodePipeline ──────────────────────────────────────────────────
        let mut pipeline_token: Option<String> = None;
        loop {
            let mut req = self.pipeline.list_pipelines();
            if let Some(t) = pipeline_token.as_ref() {
                req = req.next_token(t);
            }
            let resp = match req.send().await {
                Ok(r) => r,
                Err(e) => {
                    let msg = format!("{e}");
                    if msg.contains("AccessDenied") || msg.contains("not supported") {
                        break;
                    }
                    eprintln!("  WARN: CodePipeline list_pipelines: {e:#}");
                    break;
                }
            };

            for ps in resp.pipelines() {
                let pname = ps.name().unwrap_or("").to_string();
                if pname.is_empty() {
                    continue;
                }

                let get_resp = match self.pipeline.get_pipeline().name(&pname).send().await {
                    Ok(g) => g,
                    Err(e) => {
                        eprintln!("  WARN: CodePipeline get_pipeline({pname}): {e:#}");
                        continue;
                    }
                };

                let mut has_approval = false;
                let mut role_arn = String::new();
                if let Some(decl) = get_resp.pipeline() {
                    role_arn = decl.role_arn().to_string();
                    for stage in decl.stages() {
                        for action in stage.actions() {
                            if let Some(tid) = action.action_type_id() {
                                if tid.category().as_str() == "Approval" {
                                    has_approval = true;
                                }
                            }
                        }
                    }
                }

                rows.push(vec![
                    "Pipeline".to_string(),
                    pname,
                    String::new(),
                    String::new(),
                    if has_approval { "Yes" } else { "No" }.to_string(),
                    String::new(),
                    String::new(),
                    role_arn,
                ]);
            }

            pipeline_token = resp.next_token().map(|s| s.to_string());
            if pipeline_token.is_none() {
                break;
            }
        }

        // ── CodeBuild ────────────────────────────────────────────────────
        let mut project_token: Option<String> = None;
        loop {
            let mut req = self.build.list_projects();
            if let Some(t) = project_token.as_ref() {
                req = req.next_token(t);
            }
            let resp = match req.send().await {
                Ok(r) => r,
                Err(e) => {
                    let msg = format!("{e}");
                    if msg.contains("AccessDenied") || msg.contains("not supported") {
                        break;
                    }
                    eprintln!("  WARN: CodeBuild list_projects: {e:#}");
                    break;
                }
            };

            let names: Vec<String> = resp.projects().iter().map(|s| s.to_string()).collect();
            if !names.is_empty() {
                // batch_get_projects accepts up to 100 names; list_projects returns max 100.
                let batch_resp = match self
                    .build
                    .batch_get_projects()
                    .set_names(Some(names.clone()))
                    .send()
                    .await
                {
                    Ok(b) => b,
                    Err(e) => {
                        eprintln!("  WARN: CodeBuild batch_get_projects: {e:#}");
                        break;
                    }
                };

                for proj in batch_resp.projects() {
                    let pname = proj.name().unwrap_or("").to_string();
                    let (src_type, src_loc) = match proj.source() {
                        Some(s) => (
                            s.r#type().as_str().to_string(),
                            s.location().unwrap_or("").to_string(),
                        ),
                        None => (String::new(), String::new()),
                    };
                    let privileged = proj
                        .environment()
                        .and_then(|e| e.privileged_mode())
                        .map(|b| if b { "Yes" } else { "No" }.to_string())
                        .unwrap_or_default();
                    let logs_dest = match proj.logs_config() {
                        Some(lc) => {
                            let mut parts: Vec<String> = Vec::new();
                            if let Some(cw) = lc.cloud_watch_logs() {
                                parts.push(format!("CloudWatch:{}", cw.status().as_str()));
                            }
                            if let Some(s3) = lc.s3_logs() {
                                parts.push(format!("S3:{}", s3.status().as_str()));
                            }
                            parts.join(";")
                        }
                        None => String::new(),
                    };
                    let role = proj.service_role().unwrap_or("").to_string();

                    rows.push(vec![
                        "Project".to_string(),
                        pname,
                        src_type,
                        src_loc,
                        String::new(),
                        privileged,
                        logs_dest,
                        role,
                    ]);
                }
            }

            project_token = resp.next_token().map(|s| s.to_string());
            if project_token.is_none() {
                break;
            }
        }

        Ok(rows)
    }
}
