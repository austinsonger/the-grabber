use anyhow::Result;
use async_trait::async_trait;
use aws_sdk_appconfig::Client as AppConfigClient;

use crate::evidence::CsvCollector;

fn fmt_appcfg_dt(dt: &aws_sdk_appconfig::primitives::DateTime) -> String {
    chrono::DateTime::<chrono::Utc>::from_timestamp(dt.secs(), 0)
        .map(|c| c.to_rfc3339())
        .unwrap_or_default()
}

pub struct AppConfigDeploymentsCollector {
    client: AppConfigClient,
}

impl AppConfigDeploymentsCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self {
            client: AppConfigClient::new(config),
        }
    }
}

#[async_trait]
impl CsvCollector for AppConfigDeploymentsCollector {
    fn name(&self) -> &str {
        "AppConfig Deployments"
    }
    fn filename_prefix(&self) -> &str {
        "AppConfig_Deployments"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "App Name",
            "Environment",
            "Deployment #",
            "Config Version",
            "State",
            "Started",
            "Completed",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let mut rows = Vec::new();

        // 1. List applications.
        let mut apps: Vec<(String, String)> = Vec::new(); // (id, name)
        let mut next_token: Option<String> = None;
        loop {
            let mut req = self.client.list_applications();
            if let Some(ref t) = next_token {
                req = req.next_token(t);
            }
            let resp = match req.send().await {
                Ok(r) => r,
                Err(e) => {
                    let msg = format!("{e:#}");
                    if msg.contains("AccessDenied") || msg.contains("not supported") {
                        return Ok(rows);
                    }
                    eprintln!("  WARN: AppConfig list_applications: {msg}");
                    return Ok(rows);
                }
            };
            for app in resp.items() {
                let id = app.id().unwrap_or("").to_string();
                let name = app.name().unwrap_or("").to_string();
                if !id.is_empty() {
                    apps.push((id, name));
                }
            }
            next_token = resp.next_token().map(|s| s.to_string());
            if next_token.is_none() {
                break;
            }
        }

        // 2. For each app, list environments.
        for (app_id, app_name) in &apps {
            let mut envs: Vec<(String, String)> = Vec::new();
            let mut e_token: Option<String> = None;
            loop {
                let mut req = self.client.list_environments().application_id(app_id);
                if let Some(ref t) = e_token {
                    req = req.next_token(t);
                }
                let resp = match req.send().await {
                    Ok(r) => r,
                    Err(e) => {
                        eprintln!("  WARN: AppConfig list_environments app={app_id}: {e:#}");
                        break;
                    }
                };
                for env in resp.items() {
                    let id = env.id().unwrap_or("").to_string();
                    let name = env.name().unwrap_or("").to_string();
                    if !id.is_empty() {
                        envs.push((id, name));
                    }
                }
                e_token = resp.next_token().map(|s| s.to_string());
                if e_token.is_none() {
                    break;
                }
            }

            // 3. For each env, list deployments (first 5).
            for (env_id, env_name) in &envs {
                let mut deployments: Vec<Vec<String>> = Vec::new();
                let mut d_token: Option<String> = None;
                'dep: loop {
                    let mut req = self
                        .client
                        .list_deployments()
                        .application_id(app_id)
                        .environment_id(env_id);
                    if let Some(ref t) = d_token {
                        req = req.next_token(t);
                    }
                    let resp = match req.send().await {
                        Ok(r) => r,
                        Err(e) => {
                            eprintln!(
                                "  WARN: AppConfig list_deployments app={app_id} env={env_id}: {e:#}"
                            );
                            break 'dep;
                        }
                    };
                    for dep in resp.items() {
                        let deployment_number = dep.deployment_number().to_string();
                        let cfg_version = dep.configuration_version().unwrap_or("").to_string();
                        let state = dep
                            .state()
                            .map(|s| s.as_str().to_string())
                            .unwrap_or_default();
                        let started = dep.started_at().map(fmt_appcfg_dt).unwrap_or_default();
                        let completed = dep.completed_at().map(fmt_appcfg_dt).unwrap_or_default();
                        deployments.push(vec![
                            app_name.clone(),
                            env_name.clone(),
                            deployment_number,
                            cfg_version,
                            state,
                            started,
                            completed,
                        ]);
                        if deployments.len() >= 5 {
                            break 'dep;
                        }
                    }
                    d_token = resp.next_token().map(|s| s.to_string());
                    if d_token.is_none() {
                        break;
                    }
                }
                rows.extend(deployments);
            }
        }

        Ok(rows)
    }
}
