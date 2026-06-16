use anyhow::Result;
use async_trait::async_trait;
use aws_sdk_cognitoidentityprovider::Client as CognitoClient;

use crate::evidence::CsvCollector;

// ══════════════════════════════════════════════════════════════════════════════
// AWS Cognito — User Pool Configuration (MFA, password policy, advanced security)
// ══════════════════════════════════════════════════════════════════════════════

pub struct CognitoUserPoolCollector {
    client: CognitoClient,
}

impl CognitoUserPoolCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self {
            client: CognitoClient::new(config),
        }
    }
}

fn fmt_dt(dt: &aws_sdk_cognitoidentityprovider::primitives::DateTime) -> String {
    chrono::DateTime::<chrono::Utc>::from_timestamp(dt.secs(), dt.subsec_nanos())
        .map(|c| c.to_rfc3339())
        .unwrap_or_default()
}

#[async_trait]
impl CsvCollector for CognitoUserPoolCollector {
    fn name(&self) -> &str {
        "Cognito User Pool Configuration"
    }
    fn filename_prefix(&self) -> &str {
        "Cognito_UserPool_Config"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Pool ID",
            "Pool Name",
            "MFA Configuration",
            "Min Password Length",
            "Require Symbols",
            "Require Numbers",
            "Require Upper",
            "Require Lower",
            "Advanced Security Mode",
            "Account Recovery",
            "Created Date",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let mut rows: Vec<Vec<String>> = Vec::new();

        // 1. List all user pools.
        let mut pool_ids: Vec<String> = Vec::new();
        let mut paginator = self
            .client
            .list_user_pools()
            .max_results(60)
            .into_paginator()
            .send();
        while let Some(page) = paginator.next().await {
            let resp = match page {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("  WARN: Cognito list_user_pools: {e:#}");
                    return Ok(rows);
                }
            };
            for p in resp.user_pools() {
                if let Some(id) = p.id() {
                    pool_ids.push(id.to_string());
                }
            }
        }

        for pool_id in &pool_ids {
            let resp = match self
                .client
                .describe_user_pool()
                .user_pool_id(pool_id)
                .send()
                .await
            {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("  WARN: Cognito describe_user_pool [{pool_id}]: {e:#}");
                    continue;
                }
            };
            let pool = match resp.user_pool() {
                Some(p) => p,
                None => continue,
            };

            let name = pool.name().unwrap_or("").to_string();
            let mfa = pool
                .mfa_configuration()
                .map(|m| m.as_str().to_string())
                .unwrap_or_default();

            let (min_len, req_sym, req_num, req_up, req_low) =
                match pool.policies().and_then(|p| p.password_policy()) {
                    Some(pp) => (
                        pp.minimum_length()
                            .map(|n| n.to_string())
                            .unwrap_or_default(),
                        pp.require_symbols().to_string(),
                        pp.require_numbers().to_string(),
                        pp.require_uppercase().to_string(),
                        pp.require_lowercase().to_string(),
                    ),
                    None => (
                        String::new(),
                        String::new(),
                        String::new(),
                        String::new(),
                        String::new(),
                    ),
                };

            let adv_sec = pool
                .user_pool_add_ons()
                .map(|a| a.advanced_security_mode().as_str().to_string())
                .unwrap_or_default();

            let recovery = pool
                .account_recovery_setting()
                .map(|r| {
                    r.recovery_mechanisms()
                        .iter()
                        .map(|m| m.name().as_str().to_string())
                        .collect::<Vec<_>>()
                        .join(";")
                })
                .unwrap_or_default();

            let created = pool.creation_date().map(fmt_dt).unwrap_or_default();

            rows.push(vec![
                pool_id.clone(),
                name,
                mfa,
                min_len,
                req_sym,
                req_num,
                req_up,
                req_low,
                adv_sec,
                recovery,
                created,
            ]);
        }

        Ok(rows)
    }
}
