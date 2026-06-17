use anyhow::Result;
use async_trait::async_trait;
use aws_sdk_iam::Client as IamClient;
use std::time::Duration;

use crate::evidence::CsvCollector;

const ACTIONS: &[&str] = &[
    "iam:CreateUser",
    "iam:DeleteUser",
    "iam:AttachUserPolicy",
    "iam:AttachRolePolicy",
    "iam:PutUserPolicy",
    "iam:PutRolePolicy",
    "kms:Decrypt",
    "kms:ScheduleKeyDeletion",
    "s3:DeleteObject",
    "s3:PutBucketPolicy",
    "ec2:RunInstances",
    "ec2:TerminateInstances",
    "cloudtrail:StopLogging",
    "config:DeleteConfigurationRecorder",
];

const MAX_PRINCIPALS: usize = 200;

pub struct IamSimulatorCollector {
    client: IamClient,
}

impl IamSimulatorCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self {
            client: IamClient::new(config),
        }
    }
}

#[async_trait]
impl CsvCollector for IamSimulatorCollector {
    fn name(&self) -> &str {
        "IAM Policy Simulator"
    }
    fn filename_prefix(&self) -> &str {
        "IAM_Simulator"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Principal ARN",
            "Principal Type",
            "Action",
            "Decision",
            "Matched Statements Count",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let mut rows = Vec::new();
        let mut principals: Vec<(String, String)> = Vec::new(); // (arn, type)

        // Users (paginated).
        let mut user_token: Option<String> = None;
        loop {
            let mut req = self.client.list_users();
            if let Some(t) = user_token.as_ref() {
                req = req.marker(t);
            }
            let resp = match req.send().await {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("  WARN: IAM list_users: {e:#}");
                    break;
                }
            };
            for u in resp.users() {
                principals.push((u.arn().to_string(), "User".to_string()));
                if principals.len() >= MAX_PRINCIPALS {
                    break;
                }
            }
            if principals.len() >= MAX_PRINCIPALS {
                break;
            }
            if resp.is_truncated() {
                user_token = resp.marker().map(|s| s.to_string());
                if user_token.is_none() {
                    break;
                }
            } else {
                break;
            }
        }

        // Roles (paginated). Skip service-linked roles.
        if principals.len() < MAX_PRINCIPALS {
            let mut role_token: Option<String> = None;
            'roles: loop {
                let mut req = self.client.list_roles();
                if let Some(t) = role_token.as_ref() {
                    req = req.marker(t);
                }
                let resp = match req.send().await {
                    Ok(r) => r,
                    Err(e) => {
                        eprintln!("  WARN: IAM list_roles: {e:#}");
                        break;
                    }
                };
                for r in resp.roles() {
                    let arn = r.arn().to_string();
                    if arn.contains(":role/aws-service-role/") {
                        continue;
                    }
                    principals.push((arn, "Role".to_string()));
                    if principals.len() >= MAX_PRINCIPALS {
                        break 'roles;
                    }
                }
                if resp.is_truncated() {
                    role_token = resp.marker().map(|s| s.to_string());
                    if role_token.is_none() {
                        break;
                    }
                } else {
                    break;
                }
            }
        }

        // Simulate each principal against all actions in one batch.
        for (arn, ptype) in &principals {
            let results = self.simulate(arn).await;
            for (action, decision, count) in results {
                rows.push(vec![
                    arn.clone(),
                    ptype.clone(),
                    action,
                    decision,
                    count.to_string(),
                ]);
            }
        }

        Ok(rows)
    }
}

impl IamSimulatorCollector {
    async fn simulate(&self, principal_arn: &str) -> Vec<(String, String, usize)> {
        let mut out: Vec<(String, String, usize)> = Vec::new();
        let mut attempted_retry = false;
        loop {
            let resp = self
                .client
                .simulate_principal_policy()
                .policy_source_arn(principal_arn)
                .set_action_names(Some(ACTIONS.iter().map(|s| s.to_string()).collect()))
                .send()
                .await;
            match resp {
                Ok(r) => {
                    for er in r.evaluation_results() {
                        let action = er.eval_action_name().to_string();
                        let decision = er.eval_decision().as_str().to_string();
                        let count = er.matched_statements().len();
                        out.push((action, decision, count));
                    }
                    return out;
                }
                Err(e) => {
                    let msg = format!("{e:#}");
                    if !attempted_retry
                        && (msg.contains("Throttling") || msg.contains("TooManyRequests"))
                    {
                        attempted_retry = true;
                        tokio::time::sleep(Duration::from_secs(2)).await;
                        continue;
                    }
                    eprintln!("  WARN: IAM simulate_principal_policy [{principal_arn}]: {msg}");
                    return out;
                }
            }
        }
    }
}
